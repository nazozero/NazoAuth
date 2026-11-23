/* Benchmark observer. Match complete PostgreSQL COMMIT protocol messages only.
 * Never log query contents, bind values, or credentials. */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

typedef unsigned long long Tick;
static Tick ticks(clockid_t id) {
  struct timespec t;
  clock_gettime(id, &t);
  return (Tick)t.tv_sec * 1000000000ULL + t.tv_nsec;
}
static int port_of(int fd, bool remote) {
  struct sockaddr_storage addr;
  socklen_t size = sizeof addr;
  if ((remote ? getpeername(fd, (void *)&addr, &size)
              : getsockname(fd, (void *)&addr, &size)) < 0)
    return 0;
  if (addr.ss_family == AF_INET)
    return ntohs(((struct sockaddr_in *)&addr)->sin_port);
  if (addr.ss_family == AF_INET6)
    return ntohs(((struct sockaddr_in6 *)&addr)->sin6_port);
  return 0;
}
static int trace_fd = -1;
static pthread_once_t trace_once = PTHREAD_ONCE_INIT;
static void open_trace(void) {
  trace_fd = open("/tmp/commit-probe.tsv",
                  O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0600);
}
static void record(const char *s, int n) {
  pthread_once(&trace_once, open_trace);
  if (trace_fd >= 0 && n > 0)
    (void)write(trace_fd, s, (size_t)n);
}
static bool commit(const void *data, size_t n) {
  const unsigned char *p = data;
  /* tokio-postgres simple query, with or without a trailing semicolon. */
  return (n == 12 || n == 13) && p[0] == 'Q' && p[4] == n - 1 &&
         !strncasecmp((const char *)p + 5, "COMMIT", 6) && !p[n - 1] &&
         (n == 12 || p[11] == ';');
}
static bool ack(const void *p, size_t n) {
  static const char result[] = "C\0\0\0\013COMMIT\0Z\0\0\0\005I";
  return n == sizeof(result) - 1 && !memcmp(p, result, n);
}
#ifdef PG_PROBE

static unsigned int **wait_info;
static const char *(*event_name)(unsigned int);
static const char *(*event_type)(unsigned int);
static Tick start, sched_start, cpu_start, sync_io, write_io, wal_lock,
    sync_sched, write_sched, lock_sched;
static unsigned sequence;
static int peer_port;
static Tick runqueue(void) {
  static int schedfd = -1;
  if (schedfd < 0)
    schedfd = open("/proc/self/schedstat", O_RDONLY | O_CLOEXEC);
  char s[128];
  ssize_t n = pread(schedfd, s, sizeof(s) - 1, 0);
  if (n <= 0)
    return 0;
  s[n] = 0;
  char *end;
  (void)strtoull(s, &end, 10);
  return strtoull(end, NULL, 10);
}
static bool waiting(const char *type, const char *name) {
  if (!start || !wait_info || !*wait_info || !**wait_info)
    return false;
  unsigned id = **wait_info;
  const char *t = event_type(id), *e = event_name(id);
  return t && e && !strcmp(t, type) && !strcasecmp(e, name);
}
static void server_in(int fd, const void *p, size_t n, Tick now) {
  if (!commit(p, n))
    return;
  start = 0;
  if ((sequence++ & 15) != 0)
    return;
  if (!wait_info) {
    wait_info = dlsym(RTLD_DEFAULT, "my_wait_event_info");
    event_name = dlsym(RTLD_DEFAULT, "pgstat_get_wait_event");
    event_type = dlsym(RTLD_DEFAULT, "pgstat_get_wait_event_type");
  }
  if (!wait_info || !event_name || !event_type)
    return;
  peer_port = port_of(fd, true);
  start = now;
  sched_start = runqueue();
  cpu_start = ticks(CLOCK_THREAD_CPUTIME_ID);
  sync_io = write_io = wal_lock = sync_sched = write_sched = lock_sched = 0;
}
static void server_out(const void *p, size_t n, Tick before) {
  if (!start || !ack(p, n))
    return;
  Tick total_sched = runqueue() - sched_start,
       cpu = ticks(CLOCK_THREAD_CPUTIME_ID) - cpu_start;
  Tick done = ticks(CLOCK_MONOTONIC);
  char s[400];
  int size = snprintf(
      s, sizeof s,
      "P %d %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu %llu\n",
      peer_port, start, before, done, total_sched, cpu, sync_io, write_io,
      wal_lock, sync_sched, write_sched, lock_sched, ticks(CLOCK_REALTIME),
      ticks(CLOCK_MONOTONIC));
  start = 0;
  record(s, size);
}
#define WAIT_HOOK(name, args, call, type, event, wall, ready, ret)             \
  ret name args {                                                              \
    static ret(*real) args;                                                    \
    if (!real)                                                                 \
      real = dlsym(RTLD_NEXT, #name);                                          \
    if (!waiting(type, event))                                                 \
      return real call;                                                        \
    Tick rq = runqueue(), begin = ticks(CLOCK_MONOTONIC);                      \
    ret result = real call;                                                    \
    int err = errno;                                                           \
    wall += ticks(CLOCK_MONOTONIC) - begin;                                    \
    ready += runqueue() - rq;                                                  \
    errno = err;                                                               \
    return result;                                                             \
  }
WAIT_HOOK(fdatasync, (int fd), (fd), "IO", "WalSync", sync_io, sync_sched, int)
WAIT_HOOK(fsync, (int fd), (fd), "IO", "WalSync", sync_io, sync_sched, int)
WAIT_HOOK(pwrite, (int fd, const void *p, size_t n, off_t off), (fd, p, n, off),
          "IO", "WalWrite", write_io, write_sched, ssize_t)
WAIT_HOOK(pwritev, (int fd, const struct iovec *v, int n, off_t off),
          (fd, v, n, off), "IO", "WalWrite", write_io, write_sched, ssize_t)
WAIT_HOOK(sem_wait, (sem_t * s), (s), "LWLock", "WALWrite", wal_lock,
          lock_sched, int)
#else
static void app_boundary(int fd, const void *p, size_t n, Tick now,
                         bool sending) {
  if (!(sending ? commit(p, n) : ack(p, n)))
    return;
  int port = port_of(fd, false);
  if (!port)
    return;
  char s[80];
  int size =
      snprintf(s, sizeof s, "%c %d %llu\n", sending ? 'A' : 'B', port, now);
  record(s, size);
}
#endif
ssize_t recv(int fd, void *p, size_t n, int flags) {
  static _Thread_local ssize_t (*real)(int, void *, size_t, int);
  if (!real)
    real = dlsym(RTLD_NEXT, "recv");
  ssize_t result = real(fd, p, n, flags);
  int err = errno;
  if (result > 0) {
#ifdef PG_PROBE
    server_in(fd, p, (size_t)result, ticks(CLOCK_MONOTONIC));
#else
    app_boundary(fd, p, (size_t)result, ticks(CLOCK_MONOTONIC), false);
#endif
  }
  errno = err;
  return result;
}
ssize_t send(int fd, const void *p, size_t n, int flags) {
  static _Thread_local ssize_t (*real)(int, const void *, size_t, int);
  if (!real)
    real = dlsym(RTLD_NEXT, "send");
  Tick before = ticks(CLOCK_MONOTONIC);
  ssize_t result = real(fd, p, n, flags);
  int err = errno;
  if (result > 0) {
#ifdef PG_PROBE
    server_out(p, (size_t)result, before);
#else
    app_boundary(fd, p, (size_t)result, before, true);
#endif
  }
  errno = err;
  return result;
}
#ifndef PG_PROBE
ssize_t writev(int fd, const struct iovec *v, int cnt) {
  static _Thread_local ssize_t (*real)(int, const struct iovec *, int);
  if (!real)
    real = dlsym(RTLD_NEXT, "writev");
  Tick before = ticks(CLOCK_MONOTONIC);
  ssize_t result = real(fd, v, cnt);
  int err = errno;
  if (result > 0 && cnt > 0 && (size_t)result == v[0].iov_len)
    app_boundary(fd, v[0].iov_base, (size_t)result, before, true);
  errno = err;
  return result;
}
#endif
