#!/usr/bin/env python3
"""Show where every thread of a running title is, through ps5debug-NG.

  thread_dump.py --host IP --title TITLEID [--passive]

Attaches to the running title, stops it, and prints each thread's name,
instruction pointer and a frame-pointer backtrace as module+offset, then
resumes and detaches. Meant for a title that hangs. The payload must already
be running on the console. It connects back on port 755, which needs root and
a firewall rule for the console.

--hold attaches immediately, leaves the title running, and dumps when Enter is
pressed. Attaching to a title already stuck in the kernel fails, so start the
script before launching the game.

--passive never attaches, so it works on a process whose threads are stuck in
the kernel. It reads the top of small writable regions and lists the words
that point into module code, lowest address first. Entries can be stale
return addresses.
"""
import argparse
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ps5debug import CMD_ATTACH, CMD_DETACH, EVENT_SIZE, Link, find_title, regs


def resolver(maps):
    base = {}
    for name, start, _end in maps:
        base[name] = min(start, base.get(name, start))

    def where(address):
        for name, start, end in maps:
            if start <= address < end:
                return f"{name or '?'}+{address - base[name]:#x}"
        return f"{address:#x}"
    return where


MAX_STACK_REGION = 16 << 20


def is_return_address(link, pid, address, cache):
    """True when the bytes before address end in a call instruction."""
    page = address & ~0xFFF
    if page not in cache:
        cache[page] = link.read(pid, page - 0x1000, 0x2000)
    data = cache[page]
    if data is None:
        return False
    before = data[address - page + 0x1000 - 8:address - page + 0x1000]
    return (before[3] == 0xE8
            or before[2:4] == b"\xff\x15"
            or (before[6] == 0xFF and 0xD0 <= before[7] <= 0xD7)
            or (before[5] == 0x41 and before[6] == 0xFF and 0xD0 <= before[7] <= 0xD7))


def parse_match(text, maps):
    name, _, offset = text.partition("+")
    base = min((m[1] for m in maps if m[0] == name), default=None)
    if base is None:
        sys.exit(f"{name} is not mapped in the process")
    return base + int(offset, 0)


def passive(link, pid, window=0x4000, match=None):
    """Print the three highest return addresses near the top of each anonymous
    writable region, which are the outermost frames of a stack. With
    match="module+0xoff", only regions holding that address in the top `window`
    bytes are shown, in full."""
    maps = link.maps(pid, with_prot=True)
    where = resolver([m[:3] for m in maps])
    code = [(s, e) for n, s, e, prot in maps if n and prot & 4]
    needle = struct.pack("<Q", parse_match(match, maps)) if match else None
    cache = {}
    for name, start, end, prot in maps:
        if name or not prot & 2 or end - start > MAX_STACK_REGION:
            continue
        top = max(start, end - window)
        data = link.read(pid, top, end - top)
        if data is None:
            continue
        if needle:
            if needle not in data:
                continue
            top = start
            data = link.read(pid, top, end - top)
            if data is None:
                continue
        hits = []
        offsets = range(0, len(data) - 7, 8)
        for i in (offsets if match else reversed(offsets)):
            word, = struct.unpack_from("<Q", data, i)
            if any(s <= word < e for s, e in code) and is_return_address(link, pid, word, cache):
                hits.append((top + i, where(word)))
                if not match and len(hits) == 3:
                    break
        if not hits:
            continue
        print(f"region {start:#x}-{end:#x} size {end - start:#x}")
        for at, w in hits:
            print(f"    {at:#x}: {w}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="console address")
    ap.add_argument("--title", required=True, help="title id to attach to")
    ap.add_argument("--passive", action="store_true", help="read stacks without attaching")
    ap.add_argument("--window", type=lambda v: int(v, 0), default=0x4000,
                    help="bytes read from the top of each region in --passive mode")
    ap.add_argument("--hold", action="store_true",
                    help="stay attached and running until Enter is pressed, then dump")
    ap.add_argument("--match", help="with --passive, list in full the stacks whose top holds this module+0xoffset")
    args = ap.parse_args()
    if args.passive:
        link = Link(args.host)
        pid = find_title(link, args.title, time.time())
        print(f"pid {pid}")
        passive(link, pid, args.window, match=args.match)
        return
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", 755))
    listener.listen(1)
    link = Link(args.host)
    pid = find_title(link, args.title, time.time())
    print(f"pid {pid}")
    link.send(CMD_ATTACH, struct.pack("<I", pid))
    link.sock.settimeout(60)
    try:
        link.expect("attach")
    except TimeoutError:
        sys.exit("attach got no reply: allow port 755 from the console in the firewall")
    listener.settimeout(10)
    events, _ = listener.accept()
    try:
        if args.hold:
            print("attached, title running. Press Enter once it is hung.", file=sys.stderr, flush=True)
            sys.stdin.readline()
        where = resolver(link.maps(pid))
        code = [(s, e) for n, s, e, prot in link.maps(pid, with_prot=True) if n and prot & 4]
        cache = {}
        link.sock.settimeout(20)
        try:
            link.stop()
        except TimeoutError:
            print("the title did not stop: a thread is stuck inside the kernel")
        events.settimeout(3)
        try:
            events.recv(EVENT_SIZE)
        except socket.timeout:
            pass
        link.sock.settimeout(10)
        for lwp in link.threads():
            try:
                priority, name = link.thread_info(lwp)
                r = regs(link.getregs(lwp), 0)
                frames = link.stack(pid, r["rbp"], r["rsp"])
            except (RuntimeError, TimeoutError) as err:
                print(f"lwp {lwp}: {err}")
                continue
            print(f"lwp {lwp} {name!r} prio {priority}")
            print(f"    rip {where(r['rip'])} rax {r['rax']:#x} rdi {r['rdi']:#x} "
                  f"rsi {r['rsi']:#x} rdx {r['rdx']:#x}")
            for ret in frames:
                print(f"    {where(ret)}")
            stack = link.read(pid, r["rsp"], 0x1000) or b""
            found = 0
            for i in range(0, len(stack) - 7, 8):
                word, = struct.unpack_from("<Q", stack, i)
                if any(a <= word < b for a, b in code) and is_return_address(link, pid, word, cache):
                    print(f"    [rsp+{i:#x}] {where(word)}")
                    found += 1
                    if found == 12:
                        break
    finally:
        try:
            link.resume()
            link.send(CMD_DETACH)
            link.status()
        except (OSError, RuntimeError):
            pass


if __name__ == "__main__":
    main()
