#!/usr/bin/env python3

from bcc import BPF
from time import sleep

# define BPF program
prog = """
//#include <uapi/linux/ptrace.h>
#include <linux/blkdev.h>

BPF_HISTOGRAM(hist);

int kprobe__blk_account_io_done(struct pt_regs *ctx, struct request *req) {
    hist.increment(bpf_log2l(req->__data_len / 1024));
    return 0;
}
"""

# load BPF program
b = BPF(text=prog, cflags=["-Wno-macro-redefined"])

# header
print("Tracing... Hit Ctrl-C to end.")

# trace until Ctrl-C
try:
    sleep(999999999)
except KeyboardInterrupt:
    print()

# output
b["hist"].print_log2_hist("kbytes")
