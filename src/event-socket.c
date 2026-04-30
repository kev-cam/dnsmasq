/* dnsmasq is Copyright (c) 2000-2022 Simon Kelley
 *
 * event-socket.c — local addition: TCP listen socket that broadcasts
 * DHCP lease state changes to attached consumers (e.g. net-mgr). One
 * line per event; consumers read passively.
 *
 * Wire format:
 *   EVENT action=add ts=<unix> mac=<hex:..> ip=<v4-or-v6> hostname=<name>
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

/* Single linked list of attached consumers. Small (a handful at most). */
struct event_client {
  int fd;
  struct event_client *next;
};

static int listen_fd = -1;
static struct event_client *clients = NULL;
static time_t start_time = 0;     /* set in event_socket_init */

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

  return (size_t)snprintf(buf, buflen,
                          "%s action=%s ts=%lld mac=%s ip=%s hostname=%s\n",
                          tag, action, (long long)time(NULL),
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

void event_socket_check(void)
{
  struct sockaddr_in sa;
  socklen_t slen = sizeof(sa);
  int fd;
  struct event_client *c;
  char ipbuf[ADDRSTRLEN];

  if (listen_fd == -1)
    return;

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
  c->next = clients;
  clients = c;

  inet_ntop(AF_INET, &sa.sin_addr, ipbuf, ADDRSTRLEN);
  my_syslog(LOG_INFO, _("event-socket: client connected from %s"), ipbuf);

  send_initial_state(fd);
}

void event_socket_set_listeners(void)
{
  if (listen_fd != -1)
    poll_listen(listen_fd, POLLIN);
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
