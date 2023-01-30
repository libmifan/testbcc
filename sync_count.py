#!/usr/bin/env python3

from bcc import BPF

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HASH(last);

int do_trace(struct pt_regs *ctx) {
    u64 ts, *tsp, delta, key = 0;
    u64 *cntp, cnt_key = 1, cnt;
    
    // record sync count
    cntp = last.lookup(&cnt_key);
    if (cntp != NULL) { 
        cnt = *cntp + 1; // cnt = ++*cntp;
        last.delete(&cnt_key);
    } else { // first time
        cnt = 1;
    }
    last.update(&cnt_key, &cnt);
    bpf_trace_printk("cnt:%d\\n", cnt);

    // attempt to read stored timestamp
    tsp = last.lookup(&key);
    if (tsp != NULL) {
        delta = bpf_ktime_get_ns() - *tsp;
        if (delta < 1000000000) {
            // output if time is less than 1 second
            bpf_trace_printk("delta:%d\\n", delta / 1000000);
        }
        last.delete(&key);
    }

    // update stored timestamp
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
""", cflags=["-Wno-macro-redefined"])

# attach probe to a event
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="do_trace")
print("Tracing for quick sync's... Ctrl-C to end")

# format output
start = 0
count = 0
while 1:
    (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    msg = msg.decode('utf-8')
    if msg.startswith('delta:'):
        ms = msg.replace('delta:','')
        if start == 0:
            start = ts
        ts = ts - start
        print("At time %.2f s: multiple syncs detected, last %s ms ago" % (ts, ms))
    elif msg.startswith('cnt:'):
        count = int(msg.replace('cnt:', ''))
        print("sync execute count: %d" % count)
