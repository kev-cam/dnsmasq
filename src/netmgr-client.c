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
#define NM_LOAD_TIMEOUT 30     /* seconds to wait for a POLL reply */
#define NM_READY_GRACE  45     /* seconds to wait for a FIRST payload before
                                  serving from the on-disk generation anyway */
/* Defined once: this literal has been mangled by scripted edits more than once,
   and three copies of it is three chances to get an embedded newline wrong. */
#define NM_POLL_CMD   "POLL dnsmasq-conf\n"

enum nm_state {
  NM_OFF = 0,      /* --netmgr not given */
  NM_IDLE,         /* connected, snapshot applied, waiting for a doorbell */
  NM_CONNECTING,
  NM_GREETING,     /* HELLO sent */
  NM_SUBSCRIBING,  /* SUBSCRIBE sent, waiting for its ack */
  NM_LOADING,      /* POLL sent, waiting for the rendered payload */
  NM_WAIT          /* disconnected, backing off */
};

static struct {
  int fd;
  enum nm_state state;
  struct sockaddr_in addr;
  char *line;              /* growable: a POLL reply is one long base64 line */
  size_t linelen, linecap;
  char *data;              /* accumulated dhcp bank lines for this snapshot */
  size_t datalen, datacap;
  char *hdata;             /* accumulated hosts lines for this snapshot */
  size_t hlen, hcap;
  unsigned int hindex;     /* cache source index for our host records */
  time_t retry_at, settle_at, load_deadline, last_load;
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
  nm.load_deadline = 0;
  nm.datalen = 0;
  nm.hlen = 0;
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

/* Append to one of the snapshot buffers, growing as needed. Returns 0 on
   refusal (which is treated as "skip this record", never as fatal). */
static int nm_buf_append(char **buf, size_t *len, size_t *cap,
			 const char *s, size_t slen)
{
  if (*len + slen + 1 > NM_MAXDATA) return 0;
  if (*len + slen + 1 > *cap)
    {
      size_t want = (*cap ? *cap * 2 : 8192);
      while (want < *len + slen + 1) want *= 2;
      char *p = whine_malloc(want);
      if (!p) return 0;
      if (*buf) { memcpy(p, *buf, *len); free(*buf); }
      *buf = p; *cap = want;
    }
  memcpy(*buf + *len, s, slen);
  *len += slen;
  (*buf)[*len] = 0;
  return 1;
}

static int nm_append(const char *s, size_t len)
{ return nm_buf_append(&nm.data, &nm.datalen, &nm.datacap, s, len); }

static int nm_append_host(const char *s, size_t len)
{ return nm_buf_append(&nm.hdata, &nm.hlen, &nm.hcap, s, len); }


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
  nm.last_load = dnsmasq_time();
  /* clear_cache_and_reload() is dnsmasq's own reload, the one SIGHUP runs.
     Hand-rolling reread_dhcp() + cache_reload() here was wrong twice over: it
     skipped dhcp_update_configs / lease_update_from_configs / lease_update_dns,
     so existing leases were not re-pointed at changed config, and it called
     cache_reload() unconditionally - which SEGFAULTS when DNS is disabled
     (--port=0), because the cache is never initialised and add_hosts_entry
     walks a hash table that does not exist. That is not an exotic
     configuration: it is a DHCP-only gateway. The real function guards it with
     `if (daemon->port != 0)`. */
  clear_cache_and_reload(dnsmasq_time());
  my_syslog(MS_DHCP | LOG_INFO,
	    _("netmgr: applied %lu reservation(s), %lu byte(s) of names"),
	    nm.applied, (unsigned long)nm.hlen);
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

char *netmgr_hosts_data(size_t *len)
{
  if (!nm.ever_loaded || !nm.hdata || !nm.hlen) return NULL;
  if (len) *len = nm.hlen;
  return nm.hdata;
}

/* Our slot in the cache's source-index space. Allocated once from the same
   counter the addn-hosts files use, rather than hardcoded: SRC_AH is the BASE
   of a dynamically allocated range, not a reserved value, so a fixed number
   would collide with whichever addn-hosts file happened to take it. */
unsigned int netmgr_hosts_index(void)
{
  return nm.hindex;
}

/* ---- protocol ------------------------------------------------------ */

/* Decode base64 in place-ish; returns length written to out (out may alias in
   only if out <= in, which it does not here). Unknown characters are skipped,
   which is what makes this tolerant of the wire wrapping the payload. */
static size_t nm_b64(const char *in, size_t inlen, char *out)
{
  static const char *T =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
  unsigned int acc = 0; int bits = 0; size_t n = 0;
  for (size_t i = 0; i < inlen; i++)
    {
      const char *q;
      if (in[i] == '=') break;
      if (!(q = strchr(T, in[i]))) continue;
      acc = (acc << 6) | (unsigned int)(q - T);
      bits += 6;
      if (bits >= 8) { bits -= 8; out[n++] = (char)((acc >> bits) & 0xff); }
    }
  return n;
}

/* Split the rendered payload into its two banks.

   The daemon returns one document with '#===' section markers rather than two
   round trips, so DHCP and DNS can never be applied from different generations
   of the database. '#' is a comment to BOTH of dnsmasq's parsers, so a marker
   that ever leaked into a bank is inert rather than a syntax error. */
/* STANDBY.
 *
 * A standby server must be RUNNING but must not answer: it holds its config,
 * its lease file and its sockets, and starts serving the instant it is told
 * to. Stopping the service instead loses all of that and makes failover a
 * restart rather than a flag flip.
 *
 * It also lets the fleet record a standby's DHCP pool as INACTIVE rather than
 * deleting it. Two pools covering one range are a duplicate-assignment fault
 * only if both servers answer; if one is dormant the overlap is intent, not
 * error, and net-reserve can say so instead of flagging a conflict the
 * operator cannot resolve without dismantling the standby.
 */
static int nm_standby = 0;
static int nm_ready   = 0;   /* a full payload has been applied at least once */
static time_t nm_started = 0;

int netmgr_standby(void)
{
  return nm_standby;
}

/* Should this server stay silent?

   Two reasons, and the second is the one that used to be missed. A standby
   must not answer - that is nm_standby. But a server that has not yet been
   handed its configuration must not answer either: between exec and the first
   payload it knows nothing about reservations, names, or whether it is even
   supposed to be the active server, and answering in that window is how a
   standby briefly competed with the live one after every restart.

   Silence is not unbounded. If net-mgr cannot be reached at all, refusing to
   serve would turn a management outage into a network outage, so after
   NM_READY_GRACE we start answering from the on-disk generation - which
   net-mgr itself wrote - and say so loudly. A build with no --netmgr
   configured is stock dnsmasq and is never gated. */
int netmgr_silent(void)
{
  static int warned_grace = 0;

  if (nm.state == NM_OFF || !daemon->netmgr_spec)
    return 0;                      /* not under net-mgr control at all */
  if (nm_standby)
    return 1;
  if (nm_ready)
    return 0;

  if (nm_started && dnsmasq_time() - nm_started >= NM_READY_GRACE)
    {
      if (!warned_grace)
        {
          warned_grace = 1;
          my_syslog(MS_DHCP | LOG_WARNING,
                    _("netmgr: no configuration after %d seconds - serving the "
                      "on-disk generation; reservations may be stale"),
                    NM_READY_GRACE);
        }
      return 0;
    }
  return 1;
}

/* Apply the control directives only.

   Run before the data sections so that a standby stops answering BEFORE it is
   handed anything, no matter where the server placed the control block. The
   server does emit it first, but a client that depends on the order of a
   remote peer's output is one reordering away from serving as an active
   server for the length of a payload. */
static void nm_scan_control(char *p, size_t len)
{
  int in_control = 0;
  size_t i = 0;

  while (i < len)
    {
      size_t j = i;
      while (j < len && p[j] != '\n') j++;
      size_t linelen = j - i;
      char *line = p + i;

      if (linelen >= 4 && strncmp(line, "#===", 4) == 0)
        in_control = (memmem(line, linelen, "control", 7) != NULL);
      else if (linelen && in_control
               && linelen >= 8 && strncmp(line, "standby ", 8) == 0)
        {
          int want = (line[8] == '1');
          if (want != nm_standby)
            my_syslog(MS_DHCP | LOG_WARNING,
                      want ? _("netmgr: entering STANDBY — DHCP and DNS will not be answered")
                           : _("netmgr: leaving standby — now serving DHCP and DNS"));
          nm_standby = want;
        }
      i = j + 1;
    }
}

static void nm_split_payload(char *p, size_t len)
{
  nm_scan_control(p, len);

  nm.datalen = 0;
  nm.hlen = 0;
  int sec = 0;                       /* 0 none, 1 dhcp, 2 hosts, 3 control */
  size_t i = 0;
  nm.applied = 0;
  while (i < len)
    {
      size_t j = i;
      while (j < len && p[j] != '\n') j++;
      size_t linelen = j - i;
      char *line = p + i;
      if (linelen >= 4 && strncmp(line, "#===", 4) == 0)
	{
	  if (memmem(line, linelen, "dhcp", 4))         sec = 1;
	  else if (memmem(line, linelen, "hosts", 5))   sec = 2;
	  else if (memmem(line, linelen, "control", 7)) sec = 3;
	  else                                          sec = 0;
	}
      else if (linelen && sec)
	{
	  if (sec == 1) { nm_append(line, linelen); nm_append("\n", 1); nm.applied++; }
	  else if (sec == 3)
	    {
	      /* Already applied by nm_scan_control() before this walk started,
	         and deliberately NOT appended to the dhcp bank: control
	         directives steer this process, they are not dnsmasq config. */
	    }
	  else          { nm_append_host(line, linelen); nm_append_host("\n", 1); }
	}
      i = j + 1;
    }
}

static void nm_line(char *line)
{
  if (nm.state == NM_GREETING)
    {
      if (strncmp(line, "OK", 2) != 0)
	{
	  my_syslog(MS_DHCP | LOG_WARNING, _("netmgr: HELLO refused: %s"), line);
	  nm_close(1);
	  return;
	}
      /* mode=stream, NOT snapshot+stream: this subscription is only a doorbell.
	 The content comes from POLL, so we do not want a snapshot of raw rows
	 interleaving with the reply - and we do not want to render names here
	 at all. That policy lives in one place, on the daemon side. */
      if (!nm_send("SUBSCRIBE sub=1 mode=stream FROM dhcp_reservations\n"))
	{ nm_close(1); return; }
      nm.state = NM_SUBSCRIBING;
      return;
    }

  if (nm.state == NM_SUBSCRIBING)
    {
      if (strncmp(line, "ERR", 3) == 0)
	{
	  my_syslog(MS_DHCP | LOG_WARNING, _("netmgr: SUBSCRIBE: %s"), line);
	  nm_close(1);
	  return;
	}
      if (strncmp(line, "OK", 2) != 0) return;      /* ignore anything else */
      if (!nm_send("POLL dnsmasq-conf\n")) { nm_close(1); return; }
      nm.state = NM_LOADING;
      /* Arm the deadline HERE too. Without this the reconnect path
         inherited whatever deadline the previous connection left
         behind - a time already past - so the timeout fired before
         the reply could arrive, closing the connection and retrying
         forever. A cold start escaped it only because the field is
         still 0 then, and the check is guarded on non-zero. */
      nm.load_deadline = dnsmasq_time() + NM_LOAD_TIMEOUT;
      return;
    }

  if (nm.state == NM_LOADING)
    {
      if (strncmp(line, "ERR", 3) == 0)
	{
	  my_syslog(MS_DHCP | LOG_WARNING, _("netmgr: POLL: %s"), line);
	  nm_close(1);
	  return;
	}
      /* Key on the PAYLOAD, not on the line merely starting with OK. Other OK
	 acks share the connection, and treating the first one as the reply made
	 the real payload arrive after we had already gone IDLE - where it was
	 dropped as unknown. Symptom was a reload that logged "no output" and
	 silently kept the previous generation. */
      char *o = strstr(line, "output=");
      if (!o) return;                    /* not our reply; keep waiting */
      o += 7;
      if (*o == '"') o++;
      size_t enc = strlen(o);
      char *dec = whine_malloc(enc + 1);
      if (!dec) { nm.state = NM_IDLE; return; }
      size_t dlen = nm_b64(o, enc, dec);
      if (dlen)
	{
	  nm_split_payload(dec, dlen);
	  nm_apply();
	  nm_ready = 1;      /* configuration is complete: answering is allowed */
	}
      free(dec);
      nm.state = NM_IDLE;
      nm.backoff = NM_BACKOFF_MIN;      /* a good load resets the backoff */
      return;
    }

  /* IDLE: any streamed ROW is a doorbell and nothing more. */
  if (strncmp(line, "ROW", 3) == 0)
    {
      if (!nm.dirty)
	my_syslog(MS_DHCP | LOG_INFO,
		  _("netmgr: change notified, reloading in %ds"), NM_SETTLE);
      nm.dirty = 1;
      nm.settle_at = dnsmasq_time() + NM_SETTLE;
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
	  if (nm.linelen)
	    {
	      nm.line[nm.linelen] = 0;
	      nm_line(nm.line);
	    }
	  nm.linelen = 0;
	}
      else
	{
	  /* Grow rather than truncate: the rendered config arrives base64'd on
	     a single line and is tens of kilobytes. A fixed buffer here would
	     silently drop it and look like an empty config. */
	  if (nm.linelen + 2 > nm.linecap)
	    {
	      size_t want = nm.linecap ? nm.linecap * 2 : NM_BUFSZ;
	      while (want < nm.linelen + 2) want *= 2;
	      if (want > NM_MAXDATA) { nm.linelen = 0; continue; }
	      char *p = whine_malloc(want);
	      if (!p) { nm.linelen = 0; continue; }
	      if (nm.line) { memcpy(p, nm.line, nm.linelen); free(nm.line); }
	      nm.line = p; nm.linecap = want;
	    }
	  nm.line[nm.linelen++] = buf[i];
	}
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
  nm_started = dnsmasq_time();
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
  if (daemon->netmgr_refresh <= 0) daemon->netmgr_refresh = 30;
  nm.hindex = alloc_hosts_index();
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

  /* A reply that never arrives must not wedge us in LOADING forever - drop the
     connection and let the normal backoff/reconnect path retry. */
  if (nm.state == NM_LOADING && nm.load_deadline && now > nm.load_deadline)
    {
      my_syslog(MS_DHCP | LOG_WARNING, _("netmgr: POLL timed out, reconnecting"));
      nm_close(1);
      return;
    }

  /* Periodic re-fetch, and the reason it is not merely a belt-and-braces extra:
     the doorbell only rings on the node where a change ORIGINATES. Relay.pm
     writes replicated rows straight to the DB without going through the
     emit_change pipeline - deliberately, since that is what stops replication
     loops - so a FOLLOWER never sees a stream event for a change made on the
     master. On a gateway, whose changes all arrive by replication from nas3,
     the doorbell therefore never rings at all: without this timer it would load
     once at startup and then serve stale data forever. net-mgr's own file path
     carries the same backstop in _sync_dnsmasq's signature poll. */
  if (nm.state == NM_IDLE && !nm.dirty && daemon->netmgr_refresh > 0
      && now >= nm.last_load + daemon->netmgr_refresh)
    {
      if (!nm_send(NM_POLL_CMD)) { nm_close(1); return; }
      nm.state = NM_LOADING;
      nm.load_deadline = now + NM_LOAD_TIMEOUT;
      return;
    }

  /* A doorbell rang: re-fetch the whole rendered config once the burst settles,
     so a hundred reservations edited at once cost one reload rather than a
     hundred. POLL is request/response, so this is one more request on the
     connection we already have - no reconnect and no re-SUBSCRIBE. */
  if (nm.dirty && nm.state == NM_IDLE && now >= nm.settle_at)
    {
      nm.dirty = 0;
      if (!nm_send(NM_POLL_CMD)) { nm_close(1); return; }
      nm.state = NM_LOADING;
      nm.load_deadline = now + NM_LOAD_TIMEOUT;
    }
}

/* Does the main loop need waking sooner than its default timeout? */
/* Milliseconds until this module next has something to do, or -1.
   A boolean "do I want waking" forced the main loop to a 500ms tick forever,
   which is a lot of wakeups on an idle gateway just to watch a 30s timer. */
int netmgr_next_wakeup_ms(void)
{
  time_t now = dnsmasq_time();
  time_t due = 0;

  if (nm.state == NM_OFF) return -1;
  if (nm.state == NM_WAIT)                    due = nm.retry_at;
  else if (nm.dirty && nm.state == NM_IDLE)   due = nm.settle_at;
  else if (nm.state == NM_LOADING)            due = nm.load_deadline;
  else if (nm.state == NM_IDLE && daemon->netmgr_refresh > 0)
    due = nm.last_load + daemon->netmgr_refresh;
  else return -1;

  if (due <= now) return 0;
  if (due - now > 3600) return -1;
  return (int)((due - now) * 1000);
}

#endif /* HAVE_DHCP */
