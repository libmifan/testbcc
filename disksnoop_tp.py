#!/usr/bin/env python3

from bcc import BPF
from bcc.utils import printb

REQ_WRITE = 1 # from include/linux/blk_types.h

# load BPF program
b = BPF(text = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

struct pid_t {
    u32 bksize;
    char comm[16];
};
BPF_HASH(size, u64, struct pid_t);
BPF_HASH(time, u64);

TRACEPOINT_PROBE(block, block_rq_issue) {
    struct pid_t data = {};
    u64 pid = args->dev;
    u64 tsp = bpf_ktime_get_ns();
    time.update(&pid, &tsp);
    data.bksize = args->bytes;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    size.update(&pid, &data);
    return 0;
}

TRACEPOINT_PROBE(block, block_rq_complete) {
    u64 pid = (u32)args->dev;
    u64 tsp = bpf_ktime_get_ns();
    u64 *tsp0 = time.lookup(&pid);
    struct pid_t *tdata = size.lookup(&pid);
    if (tsp0 != NULL && tdata != NULL) {
        bpf_trace_printk("%d,%d,%s\\n", 
                        tsp - *tsp0, tdata->bksize, tdata->comm);
    }
    return 0;
}
""", cflags=["-Wno-macro-redefined"])

# header
print("%-18s %-24s %-10s %s" % ("TIME(s)", "PID(comm)", "DELTA(ms)", "BLOCKSIZE(bytes)"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        delta, size, comm = msg.decode('utf8').split(',')
    except ValueError:
        continue

    print("%-18.9f %8s(%-16s) %-10d %s" % (ts, pid, comm, int(delta)/100000, size))