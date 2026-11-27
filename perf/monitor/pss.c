/* Sum smaps_rollup for PID 1 and its descendants in this service's PID namespace.
 * docker exec probes are separate process roots and do not own service memory. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int belongs_to_service(int pid) {
    char path[80], line[4096];
    while (pid > 1) {
        snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        FILE *f = fopen(path, "r");
        if (!f) return -1;
        char *end = fgets(line, sizeof(line), f) ? strrchr(line, ')') : NULL;
        fclose(f);
        int parent;
        if (!end || sscanf(end + 1, " %*c %d", &parent) != 1) return -1;
        pid = parent;
    }
    return pid == 1;
}

int main(void) {
    DIR *procs = opendir("/proc");
    if (!procs) return 1;
    struct dirent *entry;
    long total = 0;
    while ((entry = readdir(procs))) {
        char *end;
        int pid = (int)strtol(entry->d_name, &end, 10);
        if (*end || pid <= 0) continue;
        int owned = belongs_to_service(pid);
        if (owned < 0) return 1;
        if (!owned) continue;
        char path[80], line[256];
        snprintf(path, sizeof(path), "/proc/%d/smaps_rollup", pid);
        FILE *f = fopen(path, "r");
        if (!f) return 1;
        long kib = -1;
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "Pss: %ld kB", &kib) == 1) break;
        }
        fclose(f);
        if (kib < 0) return 1;
        total += kib;
    }
    closedir(procs);
    if (total <= 0) return 1;
    printf("%ld\n", total);
    return 0;
}
