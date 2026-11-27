/* PostgreSQL process RSS/PSS and the largest writable shared mapping inherited
 * from the postmaster. Device and inode identify the same object across PIDs. */
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct mapping {
    unsigned major, minor;
    unsigned long inode, size;
};

static int read_maps(int pid, struct mapping *main_map, int discover) {
    char path[64], line[512], flags[5];
    snprintf(path, sizeof path, "/proc/%d/smaps", pid);
    FILE *f = fopen(path, "r");
    if (!f) return 1;
    struct mapping current = {0};
    long rss = 0, pss = 0, shared = 0, private = 0, mapped_rss = 0, mapped_pss = 0;
    int writable_shared = 0, matched = 0;
    while (fgets(line, sizeof line, f)) {
        if (sscanf(line, "%*lx-%*lx %4s %*lx %x:%x %lu", flags, &current.major,
                   &current.minor, &current.inode) == 4) {
            writable_shared = strcmp(flags, "rw-s") == 0 && current.inode != 0;
            matched = writable_shared && current.major == main_map->major &&
                      current.minor == main_map->minor && current.inode == main_map->inode;
            continue;
        }
        if (discover) {
            if (writable_shared && sscanf(line, "Size: %lu kB", &current.size) == 1 &&
                current.size > main_map->size) *main_map = current;
            continue;
        }
        long value;
        if (sscanf(line, "Rss: %ld kB", &value) == 1) {
            rss += value;
            if (matched) mapped_rss += value;
        } else if (sscanf(line, "Pss: %ld kB", &value) == 1) {
            pss += value;
            if (matched) mapped_pss += value;
        } else if (sscanf(line, "Shared_Clean: %ld kB", &value) == 1 ||
                   sscanf(line, "Shared_Dirty: %ld kB", &value) == 1) shared += value;
        else if (sscanf(line, "Private_Clean: %ld kB", &value) == 1 ||
                 sscanf(line, "Private_Dirty: %ld kB", &value) == 1) private += value;
    }
    int failed = ferror(f);
    fclose(f);
    if (failed || (!discover && (rss == 0 || private + shared != rss))) return 1;
    if (!discover) printf("%d %ld %ld %ld %ld %ld %ld\n",
                          pid, rss, pss, private, shared, mapped_rss, mapped_pss);
    return 0;
}

int main(void) {
    struct mapping main_map = {0};
    if (read_maps(1, &main_map, 1) || !main_map.size) return 1;
    printf("%x:%x %lu %lu\n", main_map.major, main_map.minor, main_map.inode, main_map.size);
    DIR *procs = opendir("/proc");
    if (!procs) return 1;
    struct dirent *ent;
    while ((ent = readdir(procs))) {
        char *end, path[64], name[32];
        int pid = (int)strtol(ent->d_name, &end, 10);
        if (*end || pid < 1) continue;
        snprintf(path, sizeof path, "/proc/%d/comm", pid);
        FILE *f = fopen(path, "r");
        if (!f) return 1;
        int postgres = fgets(name, sizeof name, f) && strcmp(name, "postgres\n") == 0;
        fclose(f);
        if (postgres && read_maps(pid, &main_map, 0)) return 1;
    }
    closedir(procs);
    return 0;
}
