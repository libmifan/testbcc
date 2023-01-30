#!/usr/bin/env python3

from bcc import BPF

# define BPF program
prog = """

struct data_t {
    u32 pid;
    u64 ts;
    u64 delta;
};

BPF_PERF_OUTPUT(events);
BPF_HASH(last);

int probe_sync(struct pt_regs *ctx) {
    struct data_t data = {};
    u64 *tsp, ts, delta, key = 0;
    
    tsp = last.lookup(&key);
    if (tsp != NULL) {
        ts = bpf_ktime_get_ns();
        delta = ts - *tsp;
        if (delta < 1000000000) {
            data.pid = bpf_get_current_pid_tgid();
            data.ts = ts;
            data.delta = delta / 1000000;
            events.perf_submit(ctx, &data, sizeof(data));
            last.delete(&key);
        }
    }
    
    ts = bpf_ktime_get_ns();
    last.update(&key, &ts);
    return 0;
}
"""

b = BPF(text=prog, cflags=["-Wno-macro-redefined"])
b.attach_kprobe(event=b.get_syscall_fnname("sync"), fn_name="probe_sync")
print("Tracing for quick sync's... Ctrl-C to end")

start = 0
def handle(cpu, data, size):
    global start
    event = b["events"].event(data)
    if start == 0:
        start = event.ts
    ts = (event.ts - start) / 1000000000
    print("[PID:%6s] At time %.2f s, multiple syncs "
          "detected, last %d ms ago" % (event.pid, ts, event.delta))

b["events"].open_perf_buffer(handle)

while 1:
    b.perf_buffer_poll()