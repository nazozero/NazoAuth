#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static int numeric(const char *s) { return isdigit((unsigned char)*s); }

static void mask_from(const char *s, cpu_set_t *expected) {
    CPU_ZERO(expected);
    while (*s) {
        char *end;
        int first = strtol(s, &end, 10);
        int last = first;
        if (*end == '-') last = strtol(end + 1, &end, 10);
        for (int c = first; c <= last; c++) CPU_SET(c, expected);
        if (*end != ',') break;
        s = end + 1;
    }
}

static void sample(pid_t pid, const char *only, const char *mask, cpu_set_t *expected, long long now) {
    char path[128], line[4096];
    snprintf(path, sizeof path, "/proc/%d/stat", pid);
    FILE *stat = fopen(path, "r");
    if (!stat) return;
    char *read = fgets(line, sizeof line, stat);
    fclose(stat);
    if (!read) return;
    char *end = strrchr(line, ')'), *name = strchr(line, '(');
    if (!end || !name) return;
    *end = '\0';
    name++;
    if (only[0] != '\0' && strcmp(only, name)) return;
    if (!strcmp(name, "sample-cpu")) return;
    char state;
    long utime, stime, rss;
    int parsed = sscanf(end + 2, "%c %*d %*d %*d %*d %*d %*u %*u %*u %*u %*u %ld %ld %*d %*d %*d %*d %*d %*d %*u %*u %ld", &state, &utime, &stime, &rss);
    if (parsed != 4 || state == 'Z') return;
    snprintf(path, sizeof path, "/proc/%d/task", pid);
    DIR *tasks = opendir(path);
    if (!tasks) return;
    unsigned num = 0, bad = 0;
    struct dirent *task;
    while ((task = readdir(tasks))) {
        if (!numeric(task->d_name)) continue;
        cpu_set_t actual;
        if (sched_getaffinity(atoi(task->d_name), sizeof actual, &actual) < 0) {
            if (errno == ESRCH) continue;
            bad++;
        } else if (!CPU_EQUAL(&actual, expected)) {
            bad++;
        }
        num++;
    }
    closedir(tasks);
    printf("%lld\t%d\t%s\t%ld\t%ld\t%u\t%u\t%s\n",
           now, pid, name, utime + stime, rss * (sysconf(_SC_PAGESIZE) / 1024), num, bad, mask);
}

#include "cgroup-sample.inc"

int main(int argc, char **argv) {
    if (argc != 4 || sysconf(_SC_CLK_TCK) != 100) return 2;
    cpu_set_t mask;
    mask_from(argv[1], &mask);
    const int count = atoi(argv[2]);
    for (int i = 0; i < count; ++i) {
        struct timespec time;
        clock_gettime(CLOCK_REALTIME, &time);
        long long now = time.tv_sec * 1000LL + time.tv_nsec / 1000000;
        DIR *procs = opendir("/proc");
        if (!procs) return 1;
        struct dirent *proc;
        while ((proc = readdir(procs))) if (numeric(proc->d_name))
            sample(atoi(proc->d_name), argv[3], argv[1], &mask, now);
        closedir(procs);
        if (getenv("OAUTH_BENCH_CGROUPS")) sample_cgroup(now);
        fflush(stdout);
        if (i + 1 < count) sleep(2);
    }
    return 0;
}
