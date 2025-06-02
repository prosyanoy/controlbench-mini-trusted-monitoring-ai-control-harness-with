#!/usr/bin/env python3
"""Record ``controlbench demo`` into an asciinema v2 cast (docs/demo.cast).

No asciinema install needed: runs the command in a pty and writes the events
with real timing (idle gaps longer than --max-gap are shortened).
Play with `asciinema play docs/demo.cast` or on https://asciinema.org/ (upload is manual).
"""
import argparse
import json
import os
import pty
import select
import sys
import time

ap = argparse.ArgumentParser()
ap.add_argument("--out", default="docs/demo.cast")
ap.add_argument("--max-gap", type=float, default=30.0)
ap.add_argument("cmd", nargs="*", default=[".venv/bin/controlbench", "demo"])
args = ap.parse_args()

events, clock = [], 0.0


def emit(text: str, gap: float = 0.0) -> None:
    global clock
    clock += gap
    events.append([round(clock, 4), "o", text])


emit("$ ", 0.3)
for ch in "controlbench demo":
    emit(ch, 0.05)
emit("\r\n", 0.4)

pid, fd = pty.fork()
if pid == 0:
    os.environ["COLUMNS"] = "110"
    os.execvp(args.cmd[0], args.cmd)
last = time.monotonic()
while True:
    r, _, _ = select.select([fd], [], [], 0.2)
    if r:
        try:
            data = os.read(fd, 4096)
        except OSError:
            break
        if not data:
            break
        now = time.monotonic()
        emit(data.decode(errors="replace").replace("\r\n", "\n").replace("\n", "\r\n"),
             min(now - last, args.max_gap))
        last = now
os.waitpid(pid, 0)
emit("$ ", 0.5)
header = {"version": 2, "width": 110, "height": 40, "timestamp": int(time.time()),
          "title": "ControlBench-Mini demo", "env": {"SHELL": "/bin/bash", "TERM": "xterm-256color"}}
with open(args.out, "w") as f:
    f.write(json.dumps(header) + "\n")
    for e in events:
        f.write(json.dumps(e) + "\n")
print(f"wrote {args.out}: {len(events)} events, {clock:.1f}s", file=sys.stderr)
