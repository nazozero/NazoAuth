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
    long total_pss = 0, total_rss = 0;
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
        long pss = -1, rss = -1;
        while (fgets(line, sizeof(line), f)) {
            if (sscanf(line, "Rss: %ld kB", &rss) == 1) continue;
            if (sscanf(line, "Pss: %ld kB", &pss) == 1 && rss >= 0) break;
        }
        fclose(f);
        if (pss < 0 || rss < pss) return 1;
        total_pss += pss;
        total_rss += rss;
    }
    closedir(procs);
    if (total_pss <= 0) return 1;
    printf("%ld %ld\n", total_pss, total_rss);
    return 0;
}
