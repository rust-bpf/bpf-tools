// This code was taken from https://github.com/iovisor/bcc/blob/master/tools/syscount.py
//
//  Copyright 2017, Sasha Goldshtein.
//  Licensed under the Apache License, Version 2.0 (the "License")

#ifdef LATENCY
struct data_t {
    u64 count;
    u64 total_ns;
};
BPF_HASH(start, u64, u64);
BPF_HASH(data, u32, struct data_t);
#else
BPF_HASH(data, u32, u64);
#endif

#ifdef LATENCY
int sys_enter(struct tracepoint__raw_syscalls__sys_enter *args)  {
    u64 pid_tgid = bpf_get_current_pid_tgid();
#ifdef FILTER_PID
    if (pid_tgid >> 32 != FILTER_PID)
        return 0;
#endif
    u64 t = bpf_ktime_get_ns();
    start.update(&pid_tgid, &t);
    return 0;
}
#endif

int sys_exit(struct tracepoint__raw_syscalls__sys_exit *args) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
#ifdef FILTER_PID
    if (pid_tgid >> 32 != FILTER_PID)
        return 0;
#endif
    
#ifdef FILTER_FAILED
    if (args->ret >= 0)
        return 0;
#endif

#ifdef FILTER_ERRNO
    if (args->ret != -FILTER_ERRNO)
        return 0;
#endif
    u32 key = args->id;

#ifdef LATENCY
    struct data_t *val, zero = {};
    u64 *start_ns = start.lookup(&pid_tgid);
    if (!start_ns)
        return 0;
    val = data.lookup_or_try_init(&key, &zero);
    if (val) {
        val->count++;
        val->total_ns += bpf_ktime_get_ns() - *start_ns;
    }
#else
    u64 *val, zero = 0;
    val = data.lookup_or_try_init(&key, &zero);
    if (val) {
        ++(*val);
    }
#endif
    return 0;
}
