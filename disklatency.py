#!/usr/bin/env python3

from bcc import BPF
from bcc.utils import printb
from time import sleep

REQ_WRITE = 1 # from include/linux/blk_types.h

# load BPF program
b = BPF(text = """
#include <uapi/linux/ptrace.h>
#include <linux/blk-mq.h>

BPF_HASH(start, struct request *);
BPF_HISTOGRAM(dist);

void trace_start(struct pt_regs *ctx, struct request *req) {
    // stash start timestamp by request ptr
    u64 ts = bpf_ktime_get_ns();
    
    start.update(&req, &ts);
}

void trace_completion(struct pt_regs *ctx, struct request *req) {
    u64 *tsp, delta;
    
    tsp = start.lookup(&req);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        // bpf_trace_printk("%d %x %d\\n", req->__data_len, req->cmd_flags, delta/1000);
        dist.increment(bpf_log2l((req->__data_len) / 1024));
        start.delete(&req);
    }
}
""", cflags=["-Wno-macro-redefined"])

if BPF.get_kprobe_functions(b'blk_start_request'):
    b.attach_kprobe(event='blk_start_request', fn_name='trace_start')
b.attach_kprobe(event='blk_mq_start_request', fn_name='trace_start')
if BPF.get_kprobe_functions(b'__blk_account_io_done'):
    b.attach_kprobe(event='__blk_account_io_done', fn_name='trace_completion')
else:
    b.attach_kprobe(event='blk_account_io_done', fn_name='trace_completion')

# header
print("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
try:
    sleep(99999)
except KeyboardInterrupt:
    print()

# output
b["dist"].print_log2_hist("kbytes")
'''
# header
print("%-18s %-2s %-7s %8s" % ("TIME(s)", "T", "BYTES", "LAT(ms)"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        (bytes_s, bflags_s, us_s) = msg.split()

        if int(bflags_s, 16) & REQ_WRITE:
            type_s = b"W"
        elif bytes_s == "0":  # see blk_fill_rwbs() for logic
            type_s = b"M"
        else:
            type_s = b"R"
        ms = float(int(us_s, 10)) / 1000

        printb(b"%-18.9f %-2s %-7s %8.2f" % (ts, type_s, bytes_s, ms))
    except KeyboardInterrupt:
        exit()
'''
