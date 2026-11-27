static long long first_number(const char *path) {
    FILE *file = fopen(path, "r");
    long long value = -1;
    if (file) {
        if (fscanf(file, "%lld", &value) != 1) value = -1;
        fclose(file);
    }
    return value;
}

static void keyed_numbers(const char *path, const char *key1, const char *key2,
                          long long *value1, long long *value2) {
    FILE *file = fopen(path, "r");
    char key[128];
    long long value;
    if (!file) return;
    while (fscanf(file, "%127s %lld", key, &value) == 2) {
        if (!strcmp(key, key1)) *value1 = value;
        if (!strcmp(key, key2)) *value2 = value;
    }
    fclose(file);
}

static void network(long long *received, long long *sent) {
    FILE *file = fopen("/proc/net/dev", "r");
    char line[512];
    if (!file) return;
    while (fgets(line, sizeof line, file)) {
        if (sscanf(line, " eth0: %lld %*lld %*lld %*lld %*lld %*lld %*lld %*lld %lld",
                   received, sent) == 2) break;
    }
    fclose(file);
}

static void storage(long long *reads, long long *writes) {
    FILE *file = fopen("/sys/fs/cgroup/blkio/blkio.throttle.io_service_bytes", "r");
    char line[512], direction[32];
    long long value;
    if (!file) return;
    while (fgets(line, sizeof line, file)) {
        if (sscanf(line, "%*u:%*u %31s %lld", direction, &value) != 2) continue;
        if (!strcmp(direction, "Read")) *reads = (*reads < 0 ? 0 : *reads) + value;
        if (!strcmp(direction, "Write")) *writes = (*writes < 0 ? 0 : *writes) + value;
    }
    fclose(file);
}

static void sample_cgroup(long long now) {
    long long rss = -1, cache = -1, throttled = -1, duration = -1;
    long long received = -1, sent = -1, reads = -1, writes = -1;
    keyed_numbers("/sys/fs/cgroup/memory/memory.stat", "total_rss", "total_cache", &rss, &cache);
    keyed_numbers("/sys/fs/cgroup/cpu,cpuacct/cpu.stat", "nr_throttled", "throttled_time",
                  &throttled, &duration);
    network(&received, &sent);
    storage(&reads, &writes);
    fprintf(stderr, "%lld\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld\t%lld\n",
            now, first_number("/sys/fs/cgroup/memory/memory.usage_in_bytes"), rss, cache,
            first_number("/sys/fs/cgroup/cpu,cpuacct/cpuacct.usage"), throttled, duration,
            received, sent, reads, writes);
    fflush(stderr);
}
