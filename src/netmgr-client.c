/* netmgr-client.c — pull DHCP reservations from a local net-mgr daemon.
 *
 * Copyright (c) 2026 the net-mgr authors.  Distributed under the same terms
 * as the rest of dnsmasq (GPL v2 or v3).
 *
 * WHY
 *
 * Reservations live in net-mgr's replicated database. Getting them into
 * dnsmasq has meant generating files and SIGHUPing, which works but has two
 * costs: the file layer has to be kept in step on every gateway, and a
 * directory watched with --dhcp-hostsdir is ADD-ONLY, so a deleted reservation
 * survives until something sends a SIGHUP.
 *
 * This talks to the daemon instead. Every gateway already runs a net-mgr node
 * holding a full replica, so it is a loopback conversation: it does not make
 * nas3 a dependency, and it keeps working while the wider network does not.
 *
 * PULL ON A DOORBELL, NOT PUSH
 *
 * A single SUBSCRIBE in "snapshot+stream" mode does both jobs. The snapshot is
 * the initial state; each streamed ROW afterwards is treated purely as a
 * DOORBELL — "something changed" — and never applied on its own. When one
 * rings we re-subscribe and take a fresh snapshot.
 *
 * That is deliberate. Applying rows incrementally means reconstructing the
 * daemon's state from a message sequence, and any missed, duplicated or
 * out-of-order message leaves dnsmasq quietly disagreeing with the database
 * with nothing to detect it. Re-reading the whole set is idempotent, self-heals
 * after a dropped connection, and costs a few hundred short lines. Pull also
 * recovers by itself: if the daemon restarts, WE reconnect. With push, a lost
 * message leaves us stale until someone notices.
 *
 * FAILURE IS NOT FATAL
 *
 * If the daemon is unreachable we keep whatever the file layer gave us and
 * retry with backoff. A resolver that refuses to serve because a database is
 * down is worse than one serving slightly stale data, and on a gateway it is
 * the difference between "DNS is a bit behind" and "the network is off".
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define NM_BUFSZ      8192      /* line assembly */
#define NM_MAXDATA    (4*1024*1024)   /* refuse an implausible payload */
#define NM_BACKOFF_MIN 2
#define NM_BACKOFF_MAX 120
#define NM_SETTLE      2        /* seconds to coalesce a burst of doorbells */

enum nm_state {
  NM_OFF = 0,      /* --netmgr not given */
  NM_IDLE,         /* connected, snapshot applied, waiting for a doorbell */
  NM_CONNECTING,
  NM_GREETING,     /* HELLO sent */
  NM_LOADING,      /* SUBSCRIBE sent, collecting ROWs until EOS */
  NM_WAIT          /* disconnected, backing off */
};

static struct {
  int fd;
  enum nm_state state;
  struct sockaddr_in addr;
  char line[NM_BUFSZ];
  size_t linelen;
  char *data;              /* accumulated bank lines for this snapshot */
  size_t datalen, datacap;
  time_t retry_at, settle_at;
  int backoff;
  int dirty;               /* doorbell rang while loading/idle */
  unsigned long applied;   /* records applied at last successful load */
  int ever_loaded;
} nm;

/* ---- tiny helpers -------------------------------------------------- */

static void nm_close(int backoff)
{
  if (nm.fd != -1) { close(nm.fd); nm.fd = -1; }
  nm.linelen = 0;
  nm.datalen = 0;
  if (backoff)
    {
      nm.state = NM_WAIT;
      nm.retry_at = dnsmasq_time() + nm.backoff;
      nm.backoff *= 2;
      if (nm.backoff > NM_BACKOFF_MAX) nm.backoff = NM_BACKOFF_MAX;
    }
}

static int nm_send(const char *s)
{
  size_t len = strlen(s);
  while (len)
    {
      ssize_t n = write(nm.fd, s, len);
      if (n <= 0)
	{
	  if (errno == EINTR) continue;
	  return 0;
	}
      s += n; len -= n;
    }
  return 1;
}

/* Append to the snapshot buffer, growing as needed. Returns 0 on refusal. */
static int nm_append(const char *s, size_t len)
{
  if (nm.datalen + len + 1 > NM_MAXDATA) return 0;
  if (nm.datalen + len + 1 > nm.datacap)
    {
      size_t want = (nm.datacap ? nm.datacap * 2 : 8192);
      while (want < nm.datalen + len + 1) want *= 2;
      char *p = whine_malloc(want);
      if (!p) return 0;
      if (nm.data) { memcpy(p, nm.data, nm.datalen); free(nm.data); }
      nm.data = p; nm.datacap = want;
    }
  memcpy(nm.data + nm.datalen, s, len);
  nm.datalen += len;
  nm.data[nm.datalen] = 0;
  return 1;
}

/* Extract key="value" or key=value from a net-mgr protocol line.
 * The wire form quotes any value containing whitespace, '=' or '"', and
 * doubles an embedded quote. Returns 0 if the key is absent. */
static int nm_kv(const char *line, const char *key, char *out, size_t outsz)
{
  size_t klen = strlen(key);
  const char *p = line;

  while ((p = strstr(p, key)))
    {
      /* must be at a word boundary and followed by '=' */
      if ((p != line && p[-1] != ' ') || p[klen] != '=') { p += klen; continue; }
      p += klen + 1;
      size_t n = 0;
      if (*p == '"')
	{
	  p++;
	  while (*p)
	    {
	      if (*p == '"')
		{
		  if (p[1] == '"') { p++; }        /* "" is a literal quote */
		  else break;
		}
	      if (n + 1 < outsz) out[n++] = *p;
	      p++;
	    }
	}
      else
	while (*p && *p != ' ')
	  {
	    if (n + 1 < outsz) out[n++] = *p;
	    p++;
	  }
      out[n] = 0;
      return 1;
    }
  return 0;
}

/* ---- applying a snapshot ------------------------------------------- */

/* Hand the accumulated bank lines to dnsmasq's own config parser and rebuild.
 *
 * reread_dhcp() is the existing clear-and-rebuild used by SIGHUP: it calls
 * clear_dynamic_conf() and then re-reads every file bank. Ours is applied from
 * inside it (see option.c), so one call rebuilds from BOTH the files and
 * net-mgr, in that order. Going through the same path is what makes deletions
 * work - the alternative, adding records without clearing, can never remove
 * one. */
static void nm_apply(void)
{
  nm.ever_loaded = 1;
  reread_dhcp();
  my_syslog(MS_DHCP | LOG_INFO,
	    _("netmgr: applied %lu reservation(s)"), nm.applied);
}

/* The buffer option.c reads back when rebuilding. NULL when we have never
 * completed a load, which is what keeps a dead daemon from wiping the
 * file-derived configuration. */
char *netmgr_bank_data(size_t *len)
{
  if (!nm.ever_loaded || !nm.data || !nm.datalen) return NULL;
  if (len) *len = nm.datalen;
  return nm.data;
}

/* ---- protocol ------------------------------------------------------ */

static void nm_line(char *line)
{
  if (nm.state == NM_GREETING)
    {
      if (strncmp(line, "OK", 2) != 0)
	{
	  my_syslog(MS_DHCP | LOG_WARNING,
		    _("netmgr: HELLO refused: %s"), line);
	  nm_close(1);
	  return;
	}
      /* snapshot+stream: the snapshot is the state, the stream is the bell. */
      if (!nm_send("SUBSCRIBE sub=1 mode=snapshot+stream FROM dhcp_reservations\n"))
	{ nm_close(1); return; }
      nm.state = NM_LOADING;
      nm.applied = 0;
      nm.datalen = 0;
      return;
    }

  if (strncmp(line, "ROW", 3) == 0)
    {
      if (nm.state != NM_LOADING)
	{
	  /* Streamed change = doorbell. Never applied on its own. */
	  if (!nm.dirty)
	    my_syslog(MS_DHCP | LOG_INFO,
		      _("netmgr: change notified, reloading in %ds"), NM_SETTLE);
	  nm.dirty = 1;
	  nm.settle_at = dnsmasq_time() + NM_SETTLE;
	  return;
	}
      char mac[64], ip[64], name[128];
      if (!nm_kv(line, "mac", mac, sizeof(mac))) return;
      if (!nm_kv(line, "ip",  ip,  sizeof(ip)))  return;
      if (!nm_kv(line, "name", name, sizeof(name))) name[0] = 0;

      /* Bare "mac,name,ip,lease" - a --dhcp-hostsdir bank line is a list of
	 option ARGUMENTS, not options, so the dhcp-host= keyword must NOT
	 appear. With it, dnsmasq logs "bad hex constant" per line, which is a
	 SOFT error: it starts happily having dropped every reservation. */
      char buf[320];
      int n = name[0]
	? snprintf(buf, sizeof(buf), "%s,%s,%s,%s\n", mac, name, ip, daemon->netmgr_lease)
	: snprintf(buf, sizeof(buf), "%s,%s,%s\n", mac, ip, daemon->netmgr_lease);
      if (n > 0 && (size_t)n < sizeof(buf) && nm_append(buf, n))
	nm.applied++;
      return;
    }

  if (strncmp(line, "EOS", 3) == 0)
    {
      if (nm.state == NM_LOADING)
	{
	  nm_apply();
	  nm.state = NM_IDLE;
	  nm.backoff = NM_BACKOFF_MIN;   /* a good load resets the backoff */
	}
      return;
    }

  if (strncmp(line, "ERR", 3) == 0)
    {
      my_syslog(MS_DHCP | LOG_WARNING, _("netmgr: %s"), line);
      nm_close(1);
    }
}

static void nm_readable(void)
{
  char buf[NM_BUFSZ];
  ssize_t n = read(nm.fd, buf, sizeof(buf));
  if (n == 0) { nm_close(1); return; }
  if (n < 0)
    {
      if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return;
      nm_close(1);
      return;
    }
  for (ssize_t i = 0; i < n; i++)
    {
      if (buf[i] == '\n')
	{
	  nm.line[nm.linelen] = 0;
	  if (nm.linelen) nm_line(nm.line);
	  nm.linelen = 0;
	}
      else if (nm.linelen + 1 < sizeof(nm.line))
	nm.line[nm.linelen++] = buf[i];
      else
	nm.linelen = 0;          /* overlong line: drop it, stay in sync */
    }
}

static void nm_connect(void)
{
  nm.fd = socket(AF_INET, SOCK_STREAM, 0);
  if (nm.fd == -1) { nm_close(1); return; }
  if (!fix_fd(nm.fd)) { nm_close(1); return; }
  if (connect(nm.fd, (struct sockaddr *)&nm.addr, sizeof(nm.addr)) == -1
      && errno != EINPROGRESS)
    { nm_close(1); return; }
  nm.state = NM_CONNECTING;
}

/* ---- entry points, mirroring event-socket.c ------------------------ */

void netmgr_init(void)
{
  nm.fd = -1;
  nm.backoff = NM_BACKOFF_MIN;
  if (!daemon->netmgr_spec) { nm.state = NM_OFF; return; }

  char host[128]; int port = 7531;
  const char *colon = strrchr(daemon->netmgr_spec, ':');
  size_t hlen = colon ? (size_t)(colon - daemon->netmgr_spec)
                      : strlen(daemon->netmgr_spec);
  if (hlen >= sizeof(host)) hlen = sizeof(host) - 1;
  memcpy(host, daemon->netmgr_spec, hlen);
  host[hlen] = 0;
  if (colon) port = atoi(colon + 1);
  if (!host[0]) strcpy(host, "127.0.0.1");

  memset(&nm.addr, 0, sizeof(nm.addr));
  nm.addr.sin_family = AF_INET;
  nm.addr.sin_port = htons(port);
  if (inet_pton(AF_INET, host, &nm.addr.sin_addr) != 1)
    {
      my_syslog(MS_DHCP | LOG_ERR,
		_("netmgr: bad --netmgr address '%s', disabled"), host);
      nm.state = NM_OFF;
      return;
    }
  if (!daemon->netmgr_lease) daemon->netmgr_lease = "1440";
  nm.state = NM_WAIT;
  nm.retry_at = 0;                 /* connect on the first pass */
  my_syslog(MS_DHCP | LOG_INFO, _("netmgr: will pull reservations from %s:%d"),
	    host, port);
}

void netmgr_set_listeners(void)
{
  if (nm.state == NM_OFF || nm.fd == -1) return;
  /* While connecting, readiness shows as writable. */
  poll_listen(nm.fd, nm.state == NM_CONNECTING ? POLLOUT : POLLIN);
}

void netmgr_check(time_t now)
{
  if (nm.state == NM_OFF) return;

  if (nm.state == NM_WAIT)
    {
      if (now >= nm.retry_at) nm_connect();
      return;
    }

  if (nm.state == NM_CONNECTING && nm.fd != -1 && poll_check(nm.fd, POLLOUT))
    {
      int err = 0; socklen_t l = sizeof(err);
      if (getsockopt(nm.fd, SOL_SOCKET, SO_ERROR, &err, &l) != 0 || err != 0)
	{ nm_close(1); return; }
      char hello[128];
      snprintf(hello, sizeof(hello), "HELLO consumer=dnsmasq.%d\n", (int)getpid());
      if (!nm_send(hello)) { nm_close(1); return; }
      nm.state = NM_GREETING;
      return;
    }

  if (nm.fd != -1 && poll_check(nm.fd, POLLIN))
    nm_readable();

  /* A doorbell rang: re-take the whole snapshot once the burst settles, so a
     hundred reservations edited at once cost one reload rather than a hundred. */
  if (nm.dirty && nm.state == NM_IDLE && now >= nm.settle_at)
    {
      nm.dirty = 0;
      if (!nm_send("SUBSCRIBE sub=1 mode=snapshot+stream FROM dhcp_reservations\n"))
	{ nm_close(1); return; }
      nm.state = NM_LOADING;
      nm.applied = 0;
      nm.datalen = 0;
    }
}

/* Does the main loop need waking sooner than its default timeout? */
int netmgr_wants_wakeup(void)
{
  return nm.state == NM_WAIT || (nm.dirty && nm.state == NM_IDLE);
}

#endif /* HAVE_DHCP */
