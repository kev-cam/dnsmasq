/* dnsmasq is Copyright (c) 2000-2022 Simon Kelley
 *
 * event-socket.c — local addition: TCP listen socket that broadcasts
 * DHCP lease state changes to attached consumers (e.g. net-mgr). One
 * line per event; consumers read passively.
 *
 * Wire format:
 *   EVENT action=add ts=<unix> expires=<unix|0> mac=<hex:..> ip=<v4-or-v6>
 *         hostname=<name>
 *
 * action ∈ { add, del, old, have }. "have" is sent once per current
 * lease when a consumer connects, so it doesn't need to wait for the
 * next renewal to see who's already on the network.
 */

#include "dnsmasq.h"

#ifdef HAVE_DHCP

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/wait.h>

/* Single linked list of attached consumers. Small (a handful at most). */
struct event_client {
  int fd;
  struct event_client *next;
  char inbuf[256];         /* inbound query assembly - queries are short */
  size_t inlen;
  int authed;              /* 1 ok, 0 still proving itself, -1 doomed */
  time_t joined;           /* when it connected, for the auth deadline */
  char nonce[33];          /* challenge we issued; the signed payload */
  char principal[128];     /* identity it claims, checked against signers */
  int role;                /* ROLE_READER or ROLE_UPDATER once authed */
  int sigfd;               /* temp file collecting the armored signature */
  size_t siglen;           /* bytes taken, so a client cannot fill the disk */
  char sigpath[64];
};

static int listen_fd = -1;
static struct event_client *clients = NULL;
static time_t start_time = 0;
static int warned_open = 0;   /* log the open-socket warning once */     /* set in event_socket_init */

/* Parse "host:port" into sockaddr_in. host may be a v4 dotted-quad
   or 0.0.0.0 / *. Stored in *sa_out, port stored separately. */
static int parse_listen_spec(const char *spec, struct sockaddr_in *sa)
{
  char *colon, *host;
  int port;

  memset(sa, 0, sizeof(*sa));
  sa->sin_family = AF_INET;

  host = strdup(spec);
  if (!host)
    return 0;

  colon = strrchr(host, ':');
  if (!colon)
    {
      free(host);
      return 0;
    }
  *colon = 0;
  port = atoi(colon + 1);
  if (port <= 0 || port > 65535)
    {
      free(host);
      return 0;
    }
  sa->sin_port = htons(port);

  if (host[0] == 0 || strcmp(host, "*") == 0)
    sa->sin_addr.s_addr = htonl(INADDR_ANY);
  else if (inet_pton(AF_INET, host, &sa->sin_addr) != 1)
    {
      free(host);
      return 0;
    }

  free(host);
  return 1;
}

void event_socket_init(void)
{
  struct sockaddr_in sa;
  int yes = 1;
  const char *spec;

  if (daemon->event_listen_disabled)
    return;

  /* Default to all-interfaces:7532 if --event-listen= wasn't given.
     The patched build's broadcast socket is on by default; pass
     --no-event-listen to disable it. */
  spec = daemon->event_listen ? daemon->event_listen : "0.0.0.0:7532";

  if (!parse_listen_spec(spec, &sa))
    {
      my_syslog(LOG_ERR, _("event-socket: bad --event-listen spec '%s'"), spec);
      return;
    }

  listen_fd = socket(AF_INET, SOCK_STREAM, 0);
  if (listen_fd == -1)
    {
      my_syslog(LOG_ERR, _("event-socket: socket() failed: %s"), strerror(errno));
      return;
    }

  setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

  if (bind(listen_fd, (struct sockaddr *)&sa, sizeof(sa)) == -1)
    {
      my_syslog(LOG_ERR, _("event-socket: bind %s failed: %s"),
                spec, strerror(errno));
      close(listen_fd);
      listen_fd = -1;
      return;
    }

  if (listen(listen_fd, 8) == -1)
    {
      my_syslog(LOG_ERR, _("event-socket: listen failed: %s"), strerror(errno));
      close(listen_fd);
      listen_fd = -1;
      return;
    }

  /* Non-blocking accept — consumers come and go. */
  fcntl(listen_fd, F_SETFL, O_NONBLOCK);

  start_time = time(NULL);
  my_syslog(LOG_INFO, _("event-socket: listening on %s"), spec);
}

/* Format a single line into buf. `tag` is the line type (EVENT or INFO).
   Returns bytes written (excluding null), 0 on overflow. */
static size_t fmt_line(char *buf, size_t buflen,
                       const char *tag,
                       const char *action,
                       struct dhcp_lease *lease,
                       const char *hostname)
{
  char macbuf[64];
  char addrbuf[ADDRSTRLEN];
  unsigned char *p;
  int i;

  if (!hostname)
    hostname = "";

#ifdef HAVE_DHCP6
  if (lease->flags & (LEASE_TA | LEASE_NA))
    {
      print_mac(macbuf, lease->clid, lease->clid_len);
      inet_ntop(AF_INET6, &lease->addr6, addrbuf, ADDRSTRLEN);
    }
  else
#endif
    {
      p = extended_hwaddr(lease->hwaddr_type, lease->hwaddr_len,
                          lease->hwaddr, lease->clid_len, lease->clid, &i);
      print_mac(macbuf, p, i);
      inet_ntop(AF_INET, &lease->addr, addrbuf, ADDRSTRLEN);
    }

  /* expires is the lease's own expiry, NOT ts (which is merely when we emitted
     this line). Without it the consumer had no expiry at all, and every lease it
     learned this way became immortal in net-mgr: a NULL expires reads as a
     static binding, so the address never ages out of the map and
     purge_expired_leases can never reach it.

     Emitted verbatim in dnsmasq's own convention, the same value the lease FILE
     carries (lease.c writes `%lu` of this field), so the socket and file import
     paths agree: 0 means an INFINITE lease, otherwise an absolute unix time -
     except under HAVE_BROKEN_RTC, where dnsmasq stores a duration here
     (lease.c: `expires = ei` rather than `ei + now`). The consumer separates
     those by magnitude rather than us second-guessing the build. */
  return (size_t)snprintf(buf, buflen,
                          "%s action=%s ts=%lld expires=%lld mac=%s ip=%s hostname=%s\n",
                          tag, action, (long long)time(NULL),
                          (long long)lease->expires,
                          macbuf, addrbuf, hostname);
}

static size_t fmt_event(char *buf, size_t buflen,
                        const char *action,
                        struct dhcp_lease *lease,
                        const char *hostname)
{
  return fmt_line(buf, buflen, "EVENT", action, lease, hostname);
}

/* Best-effort write. Drop the client on EPIPE/closed-connection
   so a stuck consumer can't block dnsmasq's main loop. */
static int try_write(int fd, const char *buf, size_t len)
{
  ssize_t n = write(fd, buf, len);
  if (n == (ssize_t)len)
    return 1;
  /* Partial or error: treat as fatal for that client. */
  return 0;
}

void emit_event_signal(int action, struct dhcp_lease *lease, char *hostname)
{
  char buf[512];
  const char *action_str;
  size_t len;
  struct event_client **pp, *c;

  if (listen_fd == -1 || !clients)
    return;

  if (action == ACTION_ADD)
    action_str = "add";
  else if (action == ACTION_DEL)
    action_str = "del";
  else if (action == ACTION_OLD || action == ACTION_OLD_HOSTNAME)
    action_str = "old";
  else
    return;

  len = fmt_event(buf, sizeof(buf), action_str, lease, hostname);
  if (len == 0 || len >= sizeof(buf))
    return;

  pp = &clients;
  while ((c = *pp))
    {
      if (c->authed != 1)
        {
          pp = &c->next;      /* still proving itself: tell it nothing */
          continue;
        }
      if (try_write(c->fd, buf, len))
        pp = &c->next;
      else
        {
          close(c->fd);
          *pp = c->next;
          free(c);
        }
    }
}

/* Walk the current lease table and send a "have" line for each entry
   to one specific fd. Used right after accept() so a fresh consumer
   has full state without waiting for the next renewal. */
static void send_initial_state(int fd)
{
  char buf[512];
  size_t len;
  struct dhcp_lease *l;

  for (l = lease_get_head(); l; l = l->next)
    {
      len = fmt_event(buf, sizeof(buf), "have", l, l->hostname);
      if (len == 0 || len >= sizeof(buf))
        continue;
      if (!try_write(fd, buf, len))
        return; /* client gone already */
    }
}


/* ---- inbound queries ------------------------------------------------
 *
 * The socket was broadcast-only: it accepted connections, pushed lease events,
 * and never read a byte. That meant nothing could ask dnsmasq the one question
 * only dnsmasq can answer -- "what address would you actually give this MAC?"
 * Outside tools had to re-implement the allocation algorithm and hope; the
 * result is necessarily a guess, because the answer depends on this daemon's
 * own lease table and on ICMP probing.
 *
 *   WHATIF mac=aa:bb:cc:dd:ee:ff [subnet=192.168.15.0]
 *     -> WHATIF mac=... ip=... rule=reservation|lease|pool
 *     -> WHATIF mac=... rule=none            (nothing would be offered)
 *     -> WHATIF error=...
 *
 * The rules are evaluated in the same order dhcp_packet() would: a configured
 * dhcp-host wins, then a live lease for that client, then allocation from a
 * pool. `rule` is reported so a caller knows how much to trust the answer.
 */

static int wi_hex(const char *s, unsigned char *out, int max)
{
  int n = 0;
  unsigned int v = 0;
  int nyb = 0;
  for (; *s; s++)
    {
      int d;
      if (*s == ':' || *s == '-') continue;
      if      (*s >= '0' && *s <= '9') d = *s - '0';
      else if (*s >= 'a' && *s <= 'f') d = *s - 'a' + 10;
      else if (*s >= 'A' && *s <= 'F') d = *s - 'A' + 10;
      else return -1;
      v = (v << 4) | (unsigned int)d;
      if (++nyb == 2)
	{
	  if (n >= max) return -1;
	  out[n++] = (unsigned char)v;
	  v = 0; nyb = 0;
	}
    }
  return nyb ? -1 : n;
}

static void wi_reply(int fd, const char *s)
{
  size_t len = strlen(s);
  while (len)
    {
      ssize_t w = write(fd, s, len);
      if (w <= 0) { if (errno == EINTR) continue; return; }
      s += w; len -= w;
    }
}

static void whatif(int fd, char *args)
{
  char out[256];
  unsigned char hw[DHCP_CHADDR_MAX];
  char macstr[64] = "", subnet[64] = "";
  char *p;
  int hwlen;

  if ((p = strstr(args, "mac=")))
    sscanf(p + 4, "%63[^ \t\r\n]", macstr);
  if ((p = strstr(args, "subnet=")))
    sscanf(p + 7, "%63[^ \t\r\n]", subnet);

  if (!macstr[0] || (hwlen = wi_hex(macstr, hw, sizeof(hw))) <= 0)
    {
      wi_reply(fd, "WHATIF error=need mac=aa:bb:cc:dd:ee:ff" "\n");
      return;
    }

#ifdef HAVE_DHCP
  {
    struct dhcp_config *cfg;
    struct dhcp_lease *lease;
    struct dhcp_context *ctx, *pick = NULL;
    struct in_addr want;
    int have_subnet = subnet[0] && inet_pton(AF_INET, subnet, &want) == 1;

    /* 1. a configured dhcp-host beats everything */
    cfg = find_config(daemon->dhcp_conf, NULL, NULL, 0, hw, hwlen, ARPHRD_ETHER, NULL, NULL);
    if (cfg && (cfg->flags & CONFIG_ADDR))
      {
	snprintf(out, sizeof(out), "WHATIF mac=%s ip=%s rule=reservation\n",
		 macstr, inet_ntoa(cfg->addr));
	wi_reply(fd, out);
	return;
      }

    /* 2. a live lease for this client is handed back unchanged */
    if ((lease = lease_find_by_client(hw, hwlen, ARPHRD_ETHER, NULL, 0)))
      {
	snprintf(out, sizeof(out), "WHATIF mac=%s ip=%s rule=lease\n",
		 macstr, inet_ntoa(lease->addr));
	wi_reply(fd, out);
	return;
      }

    /* 3. otherwise allocate, using dnsmasq's real algorithm. */
    for (ctx = daemon->dhcp; ctx; ctx = ctx->next)
      {
	if (!have_subnet) { pick = ctx; break; }
	/* Match on the RANGE, not on start&netmask. A context's netmask is
	   only filled in by complete_context() once an interface matches, so
	   on a box where this pool's subnet is not local it is still 0.0.0.0 -
	   and `x & 0 == y & 0` is true for every address, which silently
	   matched any subnet at all. Compare with the mask only when we
	   actually have one. */
	if (ctx->netmask.s_addr != 0)
	  {
	    if ((ctx->start.s_addr & ctx->netmask.s_addr) ==
		(want.s_addr & ctx->netmask.s_addr))
	      { pick = ctx; break; }
	  }
	else
	  {
	    unsigned long w = ntohl(want.s_addr);
	    unsigned long a = ntohl(ctx->start.s_addr);
	    unsigned long b = ntohl(ctx->end.s_addr);
	    /* treat the query as "the /24 this pool lives in" */
	    if ((w & 0xffffff00UL) >= (a & 0xffffff00UL) &&
		(w & 0xffffff00UL) <= (b & 0xffffff00UL))
	      { pick = ctx; break; }
	  }
      }
    if (!pick)
      {
	snprintf(out, sizeof(out), "WHATIF mac=%s rule=none reason=no pool%s\n",
		 macstr, have_subnet ? " on that subnet" : "");
	wi_reply(fd, out);
	return;
      }
    {
      struct dhcp_context *saved = pick->current;
      struct in_addr addr;
      int ok;
      /* Consider just this context, then restore the chain. loopback=1 is not
	 a lie about the transport: it is how address_allocate is told to skip
	 the ICMP probe, which must not happen here - a query has no business
	 putting packets on the wire or blocking the daemon while it waits. */
      pick->current = NULL;
      ok = address_allocate(pick, &addr, hw, hwlen, NULL, dnsmasq_time(), 1);
      pick->current = saved;
      if (ok)
	snprintf(out, sizeof(out), "WHATIF mac=%s ip=%s rule=pool\n",
		 macstr, inet_ntoa(addr));
      else
	snprintf(out, sizeof(out), "WHATIF mac=%s rule=none reason=pool full\n",
		 macstr);
      wi_reply(fd, out);
    }
  }
#else
  wi_reply(fd, "WHATIF error=this dnsmasq has no DHCP support\n");
#endif
}

/* Read whatever a client has sent and act on complete lines. */
/* ---- AUTH GATE -------------------------------------------------------
 *
 * This socket used to answer every connection with the entire lease table:
 * send_initial_state() ran straight off accept(), before a single byte had
 * been read. Anything able to reach the port learned every MAC, IP and
 * hostname on the segment, with no credential of any kind.
 *
 * A client now proves who it is before it is told anything. We issue a
 * random nonce; the client returns an SSHSIG over it; we hand the pair to
 * `ssh-keygen -Y verify` against /etc/net-mgr/allowed_dns, which nas3
 * installs with the dnsmasq deploy.
 *
 * That file is an ssh allowed_signers list split into two sections:
 *
 *     [readers]     may attach and consume the lease stream
 *     [updaters]    may additionally issue commands on the socket
 *
 * ssh-keygen knows nothing about sections and would reject a header, so
 * section_to_file() resolves one section at a time into a temp file in the
 * bare format before handing it over. Lines appearing before any header are
 * treated as [readers], so a plain unsectioned list still works and grants
 * only read access - the safe reading of an ambiguous file.
 *
 * nas3 goes in [updaters]: the master is the authority here, and every
 * other node gets lease data by normal replication rather than by reading
 * this socket directly.
 *
 * THE FILE IS THE GATE. With no allowed-signers file we keep the old open
 * behaviour and say so in the log, so a gateway rebuilt before its key has
 * arrived keeps feeding events instead of going silently deaf. The moment
 * nas3 lands the key the gate closes by itself, with nothing to restart.
 *
 * Verification forks ssh-keygen and waits, which stalls the DHCP loop for
 * a few tens of ms. That is confined to the connect path - consumers
 * attach once and hold - so no lease traffic is delayed by it.
 */
#define EVENT_ALLOWED   "/etc/net-mgr/allowed_dns"
#define EVENT_SEC_READERS  "readers"
#define EVENT_SEC_UPDATERS "updaters"
#define ROLE_READER   0
#define ROLE_UPDATER  1
#define EVENT_SIG_NS    "netmgr-event"
#define EVENT_AUTH_SECS 20        /* prove it inside this, or be dropped */
#define EVENT_SIG_MAX   8192      /* an SSHSIG is ~600 bytes; cap the rest */

static int event_auth_enabled(void)
{
  return access(EVENT_ALLOWED, R_OK) == 0;
}

/* 32 hex chars from the kernel. Failure is fatal to the connection: we
   must never fall back to a guessable challenge. */
static int make_nonce(char *out, size_t outsz)
{
  unsigned char raw[16];
  int fd, i;
  ssize_t got;

  if (outsz < sizeof(raw) * 2 + 1)
    return 0;
  if ((fd = open("/dev/urandom", O_RDONLY)) == -1)
    return 0;
  got = read(fd, raw, sizeof(raw));
  close(fd);
  if (got != (ssize_t)sizeof(raw))
    return 0;
  for (i = 0; i < (int)sizeof(raw); i++)
    sprintf(out + i * 2, "%02x", raw[i]);
  out[sizeof(raw) * 2] = 0;
  return 1;
}

/* The principal reaches ssh-keygen as an argv entry, so it can never be
   shell-interpreted, but a leading '-' would still be read as an option
   and an odd charset makes for unreadable logs. Keep it boring. */
static int principal_ok(const char *p)
{
  size_t i, n = strlen(p);

  if (n == 0 || n > 120 || p[0] == '-')
    return 0;
  for (i = 0; i < n; i++)
    if (!((p[i] >= 'a' && p[i] <= 'z') || (p[i] >= 'A' && p[i] <= 'Z') ||
          (p[i] >= '0' && p[i] <= '9') ||
          p[i] == '.' || p[i] == '_' || p[i] == '-' || p[i] == '@'))
      return 0;
  return 1;
}

/* Copy one [section] of EVENT_ALLOWED into a temp allowed_signers file.
   The stored format is AUTHORIZED_KEYS - the fleet convention, matching
   allowed_chat / allowed_internet / allowed_signers - so the principal is
   the OPTIONAL TRAILING COMMENT, not a leading field. This mirrors
   NetMgr::Auth::_authorized_to_allowed exactly: comment becomes the
   principal, an absent comment becomes key-<12 chars of the key>, spaces
   in it become underscores, and hostwild() lowercases the user part and
   wildcards the host so one key works from whatever host presents it -
   what stops an impostor is possession of the private key, not the label.
   ssh-keygen would reject a section header, so headers are resolved here
   and lines before any header count as [readers]. Returns 1 and fills
   pathbuf when the section held at least one usable key. */
static int section_to_file(const char *want, char *pathbuf, size_t pathsz)
{
  FILE *in, *out;
  int fd, n = 0, in_section;
  char line[1024];

  if (pathsz < 32 || !(in = fopen(EVENT_ALLOWED, "r")))
    return 0;

  strcpy(pathbuf, "/tmp/dnsmasq-evsec-XXXXXX");
  if ((fd = mkstemp(pathbuf)) == -1)
    {
      fclose(in);
      return 0;
    }
  if (!(out = fdopen(fd, "w")))
    {
      close(fd);
      unlink(pathbuf);
      fclose(in);
      return 0;
    }

  in_section = (strcmp(want, EVENT_SEC_READERS) == 0);
  while (fgets(line, sizeof(line), in))
    {
      char *s = line, *kt, *kd, *cm, *p;
      char principal[160];
      size_t i;

      while (*s == ' ' || *s == '\t')
        s++;
      if (*s == '[')
        {
          char *e = strchr(s, ']');
          if (e)
            {
              *e = 0;
              in_section = (strcmp(s + 1, want) == 0);
            }
          continue;
        }
      if (*s == '#' || *s == '\n' || *s == '\r' || *s == 0 || !in_section)
        continue;
      for (p = s + strlen(s); p > s && (p[-1] == '\n' || p[-1] == '\r'); p--)
        p[-1] = 0;

      /* Find the key type, stepping over any leading options group. */
      kt = s;
      for (;;)
        {
          if (strncmp(kt, "ssh-", 4) == 0 || strncmp(kt, "ecdsa-", 6) == 0 ||
              strncmp(kt, "sk-", 3) == 0)
            break;
          if (!(kt = strpbrk(kt, " \t")))
            break;
          while (*kt == ' ' || *kt == '\t')
            kt++;
          if (*kt == 0)
            {
              kt = NULL;
              break;
            }
        }
      if (!kt)
        continue;                      /* no key on this line */

      if (!(kd = strpbrk(kt, " \t")))
        continue;
      *kd++ = 0;
      while (*kd == ' ' || *kd == '\t')
        kd++;
      cm = strpbrk(kd, " \t");
      if (cm)
        {
          *cm++ = 0;
          while (*cm == ' ' || *cm == '\t')
            cm++;
        }

      if (cm && *cm)
        {
          snprintf(principal, sizeof(principal), "%s", cm);
          for (i = 0; principal[i]; i++)          /* spaces -> underscores */
            if (principal[i] == ' ' || principal[i] == '\t')
              principal[i] = '_';
        }
      else
        snprintf(principal, sizeof(principal), "key-%.12s", kd);

      /* hostwild: user@host -> user@*, and a bare name gains @* too. */
      if ((p = strchr(principal, '@')))
        *p = 0;
      for (i = 0; principal[i]; i++)
        if (principal[i] >= 'A' && principal[i] <= 'Z')
          principal[i] = (char)(principal[i] - 'A' + 'a');

      fprintf(out, "%s@* namespaces=\"%s\" %s %s\n",
              principal, EVENT_SIG_NS, kt, kd);
      n++;
    }
  fclose(in);
  fclose(out);

  if (n == 0)
    {
      unlink(pathbuf);
      pathbuf[0] = 0;
      return 0;
    }
  return 1;
}

/* ssh-keygen -Y verify reads the signed message on stdin. Exit 0 means the
   signature is good AND the signers file vouches for that principal. */
static int verify_sig(const char *principal, const char *sigpath,
                      const char *nonce, const char *signers)
{
  int p[2], status;
  pid_t pid;
  size_t len;
  ssize_t w;

  if (pipe(p) == -1)
    return 0;

  if ((pid = fork()) == -1)
    {
      close(p[0]); close(p[1]);
      return 0;
    }

  if (pid == 0)
    {
      int devnull = open("/dev/null", O_WRONLY);
      close(p[1]);
      dup2(p[0], STDIN_FILENO);
      close(p[0]);
      if (devnull != -1)
        {
          dup2(devnull, STDOUT_FILENO);
          dup2(devnull, STDERR_FILENO);
          close(devnull);
        }
      execlp("ssh-keygen", "ssh-keygen", "-Y", "verify",
             "-f", signers, "-I", principal,
             "-n", EVENT_SIG_NS, "-s", sigpath, (char *)NULL);
      _exit(127);
    }

  close(p[0]);
  len = strlen(nonce);
  w = write(p[1], nonce, len);
  close(p[1]);
  if (w != (ssize_t)len)
    {
      waitpid(pid, &status, 0);
      return 0;
    }
  if (waitpid(pid, &status, 0) != pid)
    return 0;
  return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

/* Mark for reaping rather than freeing here: event_socket_check() is
   walking the client list when this runs, so freeing now would pull the
   ground out from under its iterator. */
static void auth_fail(struct event_client *c, const char *why)
{
  my_syslog(LOG_WARNING, _("event-socket: auth refused (%s)"), why);
  try_write(c->fd, "ERR auth\n", 9);
  c->authed = -1;
}

static void sig_append(struct event_client *c, const char *line)
{
  size_t n = strlen(line);

  if (c->siglen + n + 1 > EVENT_SIG_MAX)
    {
      auth_fail(c, "signature too large");
      return;
    }
  if (write(c->sigfd, line, n) != (ssize_t)n ||
      write(c->sigfd, "\n", 1) != 1)
    {
      auth_fail(c, "signature write");
      return;
    }
  c->siglen += n + 1;
}

static void auth_finish(struct event_client *c)
{
  char signers[64];
  int ok = 0;

  close(c->sigfd);
  c->sigfd = -1;

  /* [updaters] is tried first so a principal listed in both sections gets
     the higher role rather than whichever section happened to come first. */
  if (section_to_file(EVENT_SEC_UPDATERS, signers, sizeof(signers)))
    {
      ok = verify_sig(c->principal, c->sigpath, c->nonce, signers);
      unlink(signers);
      if (ok)
        c->role = ROLE_UPDATER;
    }
  if (!ok && section_to_file(EVENT_SEC_READERS, signers, sizeof(signers)))
    {
      ok = verify_sig(c->principal, c->sigpath, c->nonce, signers);
      unlink(signers);
      if (ok)
        c->role = ROLE_READER;
    }

  unlink(c->sigpath);
  c->sigpath[0] = 0;

  if (!ok)
    {
      auth_fail(c, "no [readers] or [updaters] entry verified the signature");
      return;
    }

  c->authed = 1;
  my_syslog(LOG_INFO, _("event-socket: authenticated %s as %s"), c->principal,
            c->role == ROLE_UPDATER ? "updater" : "reader");
  try_write(c->fd, "OK\n", 3);
  send_initial_state(c->fd);
}

/* One line from a client that has not proved itself yet. The armored
   signature is streamed to a 0600 temp file a line at a time, so the
   256-byte inbuf never limits how big a signature we can accept. */
static void auth_line(struct event_client *c, const char *line)
{
  if (strncmp(line, "AUTH principal=", 15) == 0)
    {
      if (c->principal[0])
        { auth_fail(c, "principal repeated"); return; }
      if (!principal_ok(line + 15))
        { auth_fail(c, "malformed principal"); return; }
      strncpy(c->principal, line + 15, sizeof(c->principal) - 1);
      c->principal[sizeof(c->principal) - 1] = 0;
      return;
    }

  if (strcmp(line, "-----BEGIN SSH SIGNATURE-----") == 0)
    {
      if (!c->principal[0])
        { auth_fail(c, "signature before principal"); return; }
      if (c->sigfd != -1)
        { auth_fail(c, "signature repeated"); return; }
      strcpy(c->sigpath, "/tmp/dnsmasq-evsig-XXXXXX");
      if ((c->sigfd = mkstemp(c->sigpath)) == -1)
        { c->sigpath[0] = 0; auth_fail(c, "no temp file"); return; }
      c->siglen = 0;
      sig_append(c, line);
      return;
    }

  if (c->sigfd != -1)
    {
      sig_append(c, line);
      if (c->authed != -1 && strcmp(line, "-----END SSH SIGNATURE-----") == 0)
        auth_finish(c);
      return;
    }

  if (line[0])
    auth_fail(c, "expected AUTH");
}

/* Drop doomed clients and any that sat past the auth deadline. Called
   only from event_socket_check(), AFTER its read loop has finished. */
static void reap_clients(void)
{
  struct event_client **pp = &clients, *c;
  time_t now = time(NULL);

  while ((c = *pp))
    {
      int drop = (c->authed == -1) ||
                 (c->authed == 0 && now - c->joined > EVENT_AUTH_SECS);

      if (!drop)
        {
          pp = &c->next;
          continue;
        }
      if (c->authed == 0)
        my_syslog(LOG_WARNING,
                  _("event-socket: no valid signature within %d s, dropping client"),
                  EVENT_AUTH_SECS);
      if (c->sigfd != -1)
        close(c->sigfd);
      if (c->sigpath[0])
        unlink(c->sigpath);
      close(c->fd);
      *pp = c->next;
      free(c);
    }
}

static void event_client_readable(struct event_client *c)
{
  char buf[256];
  ssize_t n = read(c->fd, buf, sizeof(buf));
  ssize_t i;

  if (n <= 0)
    return;                     /* EOF/error: reaped by the write path */

  for (i = 0; i < n; i++)
    {
      if (buf[i] == '\n')
	{
	  c->inbuf[c->inlen] = 0;
	  if (c->authed != 1)
	    auth_line(c, c->inbuf);
	  else if (c->inlen && c->role != ROLE_UPDATER)
	    /* [readers] may consume the stream but not drive the socket. */
	    wi_reply(c->fd, "ERR not permitted for a reader\n");
	  else if (strncmp(c->inbuf, "WHATIF", 6) == 0)
	    whatif(c->fd, c->inbuf + 6);
	  else if (c->inlen)
	    wi_reply(c->fd, "WHATIF error=unknown request\n");
	  c->inlen = 0;
	}
      else if (c->inlen + 1 < sizeof(c->inbuf))
	c->inbuf[c->inlen++] = buf[i];
      else
	c->inlen = 0;           /* overlong: drop, stay in sync */
    }
}

void event_socket_check(void)
{
  struct sockaddr_in sa;
  socklen_t slen = sizeof(sa);
  int fd;
  struct event_client *c;
  char ipbuf[ADDRSTRLEN];

  if (listen_fd == -1)
    return;

  /* Service any client that has ASKED us something before looking for new
     connections. */
  for (c = clients; c; c = c->next)
    if (poll_check(c->fd, POLLIN))
      event_client_readable(c);

  /* Safe here and not inside the loop above: this frees list entries. */
  reap_clients();

  if (!poll_check(listen_fd, POLLIN))
    return;

  fd = accept(listen_fd, (struct sockaddr *)&sa, &slen);
  if (fd == -1)
    return;

  /* Disable Nagle so events arrive promptly even with one tiny line. */
  {
    int yes = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));
  }

  if (!(c = whine_malloc(sizeof(*c))))
    {
      close(fd);
      return;
    }
  c->fd = fd;
  c->inlen = 0;
  c->authed = 1;
  c->joined = time(NULL);
  c->role = ROLE_READER;
  c->sigfd = -1;
  c->siglen = 0;
  c->nonce[0] = 0;
  c->principal[0] = 0;
  c->sigpath[0] = 0;
  c->next = clients;
  clients = c;

  inet_ntop(AF_INET, &sa.sin_addr, ipbuf, ADDRSTRLEN);
  my_syslog(LOG_INFO, _("event-socket: client connected from %s"), ipbuf);

  if (event_auth_enabled())
    {
      char chal[128];
      int len;

      c->authed = 0;
      if (!make_nonce(c->nonce, sizeof(c->nonce)))
        {
          my_syslog(LOG_ERR, _("event-socket: no entropy for challenge"));
          c->authed = -1;
          return;
        }
      len = snprintf(chal, sizeof(chal), "AUTH-REQUIRED nonce=%s ns=%s\n",
                     c->nonce, EVENT_SIG_NS);
      if (len > 0 && len < (int)sizeof(chal))
        try_write(fd, chal, (size_t)len);
      return;      /* it is told nothing until it has proved itself */
    }

  if (!warned_open)
    {
      warned_open = 1;
      my_syslog(LOG_WARNING,
                _("event-socket: %s absent - serving lease state to any client"),
                EVENT_ALLOWED);
    }

  send_initial_state(fd);
}

void event_socket_set_listeners(void)
{
  struct event_client *c;

  if (listen_fd != -1)
    poll_listen(listen_fd, POLLIN);

  /* Connected clients are now readable too: the socket used to be
     broadcast-only, so nothing could ever ASK it anything. */
  for (c = clients; c; c = c->next)
    poll_listen(c->fd, POLLIN);
}

/* SIGUSR2 hook: emit an uptime INFO line so consumers can tell how
   long this dnsmasq has been running without consulting systemd. */
void event_socket_dump_uptime(void)
{
  char buf[128];
  size_t len;
  struct event_client **pp, *c;
  time_t now;

  if (listen_fd == -1 || !clients)
    return;
  now = time(NULL);
  len = (size_t)snprintf(buf, sizeof(buf),
                         "INFO action=uptime ts=%lld up=%lld started=%lld\n",
                         (long long)now,
                         (long long)(now - start_time),
                         (long long)start_time);
  if (len == 0 || len >= sizeof(buf))
    return;
  pp = &clients;
  while ((c = *pp))
    {
      if (c->authed != 1)
        {
          pp = &c->next;      /* still proving itself: tell it nothing */
          continue;
        }
      if (try_write(c->fd, buf, len))
        pp = &c->next;
      else
        {
          close(c->fd);
          *pp = c->next;
          free(c);
        }
    }
}

/* SIGUSR1 hook: write one INFO line per current lease to every
   attached consumer. Useful for ad-hoc debugging without forcing
   them to reconnect (which would re-trigger an `action=have` flood
   anyway). */
void event_socket_dump_all(void)
{
  char buf[512];
  size_t len;
  struct dhcp_lease *l;
  struct event_client **pp, *c;

  if (listen_fd == -1 || !clients)
    return;

  for (l = lease_get_head(); l; l = l->next)
    {
      len = fmt_line(buf, sizeof(buf), "INFO", "have", l, l->hostname);
      if (len == 0 || len >= sizeof(buf))
        continue;
      pp = &clients;
      while ((c = *pp))
        {
          if (c->authed != 1)
        {
          pp = &c->next;      /* still proving itself: tell it nothing */
          continue;
        }
      if (try_write(c->fd, buf, len))
            pp = &c->next;
          else
            {
              close(c->fd);
              *pp = c->next;
              free(c);
            }
        }
    }
}

#endif /* HAVE_DHCP */
