#!/usr/bin/env python3

from bcc import BPF
from time import sleep

b = BPF(src_file="task_switch.c")
b.attach_kprobe(event="finish_task_switch.isra.0", fn_name="count_sched")

# generate many schedule events
for i in range(0, 10):
    sleep(0.01)

for k, v in b["stats"].items():
    # print("keys:", type(k))
    # print("vals:", type(v))
    # print()
    v.value = 1000
    print("task_switch[%5d->%5d]=%u" % (k.prev_pid, k.curr_pid, v.value))