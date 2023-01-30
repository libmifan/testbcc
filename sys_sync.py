#!/usr/bin/env python3

from bcc import BPF
import sys
import time

prog ='''
int kprobe__sys_sync(void *ctx) {
    bpf_trace_printk("sys_sync() called\\n"); 
    return 0;
}
'''

try:
    print("Tracing sys_sync()... Ctrl-C to end")
    time.sleep(2)
    b = BPF(text=prog)
    b.trace_print()
except KeyboardInterrupt:
    sys.exit(3)
