#define _GNU_SOURCE
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char **argv) {
    cpu_set_t mask;
    CPU_ZERO(&mask);
    if (argc < 3) return 2;
    char *start = argv[1];
    for (;;) {
        char *end;
        long first = strtol(start, &end, 10), last = first;
        if (end == start || first < 0 || first >= CPU_SETSIZE) return 2;
        if (*end == '-') last = strtol(end + 1, &end, 10);
        if (last < first || last >= CPU_SETSIZE) return 2;
        for (long cpu = first; cpu <= last; ++cpu) CPU_SET(cpu, &mask);
        if (*end == '\0') break;
        if (*end != ',') return 2;
        start = end + 1;
    }
    if (sched_setaffinity(0, sizeof(mask), &mask) < 0) {
        perror("sched_setaffinity");
        return 1;
    }
    execvp(argv[2], &argv[2]);
    perror("execvp");
    return 1;
}
