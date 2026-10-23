#!/usr/bin/env python3
"""Log the file calls of a running title through ps5debug-NG.

  open_trace.py --host IP --title TITLEID --hook NAME=ADDRESS [--hook ...]

Waits for the title, attaches, and breaks on each hooked call stub inside the
eboot, printing the arguments at the call and the result when it returns. A
call with no result line never came back. NAME is one of open, stat or
getdirentries, and ADDRESS is the stub's virtual address inside the eboot (the
PLT jump through that import). The payload must already be running on the
console. It connects back on port 755, which needs root and a firewall rule
for the console.
"""
import argparse
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ps5debug import CMD_ATTACH, CMD_DETACH, EVENT_SIZE, MAX_BREAKPOINTS, Link, find_title, regs

PATH_BYTES = 256
KINDS = ("open", "stat", "getdirentries")


def module_base(link, pid, name):
    while True:
        starts = [s for n, s, _e in link.maps(pid) if n == name]
        if starts:
            return min(starts)
        time.sleep(0.05)


def read_path(link, pid, address):
    raw = link.read(pid, address, PATH_BYTES) if address else None
    if raw is None:
        return "?"
    return raw.split(b"\0")[0].decode("utf-8", "replace")


def describe(kind, r, link, pid):
    if kind == "open":
        return f"open flags {r['rsi'] & 0xFFFFFFFF:#x} {read_path(link, pid, r['rdi'])}"
    if kind == "stat":
        return f"stat {read_path(link, pid, r['rdi'])}"
    return f"getdirentries fd {r['rdi'] & 0xFFFFFFFF} room {r['rdx'] & 0xFFFFFFFF}"


def parse_hook(text):
    kind, _, address = text.partition("=")
    if kind not in KINDS or not address:
        raise argparse.ArgumentTypeError(f"--hook expects {'|'.join(KINDS)}=ADDRESS")
    return kind, int(address, 0)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="console address")
    ap.add_argument("--title", required=True, help="title id to attach to")
    ap.add_argument("--hook", action="append", type=parse_hook, required=True,
                    help="call stub to trace, as NAME=ADDRESS")
    ap.add_argument("--module", default="executable", help="map name of the eboot")
    args = ap.parse_args()
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", 755))
    listener.listen(1)
    link = Link(args.host)
    print(f"waiting for {args.title}", flush=True)
    pid = find_title(link, args.title, time.time())
    base = module_base(link, pid, args.module)
    print(f"pid {pid} {args.module} base {base:#x}", flush=True)
    link.send(CMD_ATTACH, struct.pack("<I", pid))
    link.sock.settimeout(60)
    try:
        link.expect("attach")
    except TimeoutError:
        sys.exit("attach got no reply: allow port 755 from the console in the firewall")
    link.sock.settimeout(10)
    listener.settimeout(10)
    events, _ = listener.accept()
    events.settimeout(None)
    entries = {base + address: kind for kind, address in args.hook}
    slots = {}
    for address in entries:
        slots[address] = len(slots)
        link.breakpoint(slots[address], address)
    returns = set()
    pending = {}
    started = time.time()
    try:
        while True:
            event = bytearray()
            while len(event) < EVENT_SIZE:
                chunk = events.recv(EVENT_SIZE - len(event))
                if not chunk:
                    raise ConnectionError("interrupt channel closed")
                event += chunk
            lwp, = struct.unpack_from("<I", event, 0)
            r = regs(event)
            stamp = f"[{time.time() - started:8.3f}]"
            if r["rip"] in entries:
                print(f"{stamp} lwp {lwp} {describe(entries[r['rip']], r, link, pid)}", flush=True)
                ret, = struct.unpack("<Q", link.read(pid, r["rsp"], 8))
                pending[lwp] = ret
                if ret not in returns and len(slots) < MAX_BREAKPOINTS:
                    returns.add(ret)
                    slots[ret] = len(slots)
                    link.breakpoint(slots[ret], ret)
            elif r["rip"] in returns and lwp in pending:
                del pending[lwp]
                print(f"{stamp} lwp {lwp}   -> {r['rax'] & 0xFFFFFFFF:#010x}", flush=True)
            else:
                print(f"{stamp} lwp {lwp} stopped at {r['rip']:#x} (not a hook)", flush=True)
            link.resume()
    except (KeyboardInterrupt, ConnectionError) as err:
        print(f"stopping: {err!r}")
    finally:
        try:
            link.send(CMD_DETACH)
            link.status()
        except OSError:
            pass


if __name__ == "__main__":
    main()
