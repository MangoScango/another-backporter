#!/usr/bin/env python3
"""Trace libScePad vibration calls in a running title through ps5debug-NG.

  pad_trace.py --host IP --title TITLEID [--dump LIBSCEPAD_ELF]

Waits for the title, attaches, breaks on the entry of scePadOpen,
scePadIsRemoteController, scePadSetVibrationMode and scePadSetVibration, and
breaks again at each caller's return address to read the result. The payload
must already be running on the console and the title must run the unpatched
fakelib build. Export offsets come from the 13.60 libScePad under the
configured libs (PS5BACKPORT_LIBS) or from --dump. The payload connects back
on port 755, which needs root and a firewall rule for the console.
"""
import argparse
import socket
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from ps5backport.config import Config
from ps5backport.patch import Patcher
from ps5debug import (CMD_ATTACH, CMD_BREAKPOINT, CMD_DETACH, EVENT_SIZE, MAX_BREAKPOINTS, REG,
                      Link, find_title, regs)

HOOKS = {
    "xk0AcarP3V4": "scePadOpen",
    "fCWdlnmB1Ks": "scePadIsRemoteController",
    "W2G-yoyMF5U": "scePadSetVibrationMode",
    "yFVnOdGxvZY": "scePadSetVibration",
}


def default_lib():
    return Config.default().system_module("libScePad.sprx", "13.60")


def export_offsets(dump):
    patcher = Patcher(str(dump) if dump else str(default_lib()))
    return {nid: patcher.export_address("libScePad", nid) for nid in HOOKS}


def sdk_global(dump, offsets):
    """Offset of the word libScePad compares against 0x08000000 in SetVibrationMode."""
    patcher = Patcher(str(dump) if dump else str(default_lib()))
    start = offsets["W2G-yoyMF5U"]
    at = patcher.module._vaddr_to_offset(start)
    code = bytes(patcher.data[at:at + 0x60])
    hit = code.find(b"\x8b\x05")
    if hit < 0 or b"\x3d\x00\x00\x00\x08" not in code[hit:hit + 12]:
        raise SystemExit("SDK compare not found in scePadSetVibrationMode")
    return start + hit + 6 + struct.unpack_from("<i", code, hit + 2)[0]


def lib_base(link, pid, name="libScePad"):
    while True:
        starts = [s for n, s, _e in link.maps(pid) if name in n]
        if starts:
            return min(starts)
        time.sleep(0.05)


def describe(name, r, link, pid):
    if name == "scePadOpen":
        return f"user={r['rdi'] & 0xffffffff:#x} type={r['rsi'] & 0xffffffff} index={r['rdx'] & 0xffffffff}"
    if name == "scePadIsRemoteController":
        return f"handle={r['rdi'] & 0xffffffff}"
    if name == "scePadSetVibrationMode":
        return f"handle={r['rdi'] & 0xffffffff} mode={r['rsi'] & 0xffffffff}"
    raw = link.read(pid, r["rsi"], 2) if r["rsi"] else None
    large, small = (raw[0], raw[1]) if raw else (-1, -1)
    return f"handle={r['rdi'] & 0xffffffff} large={large} small={small}"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="console address")
    ap.add_argument("--title", required=True, help="title id to attach to")
    ap.add_argument("--dump", help="libScePad ELF to read export offsets from")
    ap.add_argument("--sdk", type=lambda v: int(v, 0),
                    help="write this compiled-SDK word into libScePad before SetVibrationMode runs")
    ap.add_argument("--mode", type=int, help="replace SetVibrationMode's mode argument")
    args = ap.parse_args()
    offsets = export_offsets(args.dump)
    sdk_at = sdk_global(args.dump, offsets) if args.sdk is not None else None
    listener = socket.socket()
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", 755))
    listener.listen(1)
    link = Link(args.host)
    print(f"waiting for {args.title}")
    pid = find_title(link, args.title, time.time())
    base = lib_base(link, pid)
    print(f"pid {pid} libScePad base {base:#x}")
    link.send(CMD_ATTACH, struct.pack("<I", pid))
    link.sock.settimeout(60)
    try:
        link.expect("attach")
    except TimeoutError:
        sys.exit("attach got no reply: the console connects back to port 755 before it "
                 "answers, so allow it through the firewall:\n"
                 f"  sudo ufw allow from {args.host} to any port 755 proto tcp\n"
                 "then relaunch the title, which the failed attach may have left stopped")
    link.sock.settimeout(10)
    listener.settimeout(10)
    events, _ = listener.accept()
    events.settimeout(None)
    entries = {base + off: HOOKS[nid] for nid, off in offsets.items()}
    returns = {}
    pending = {}
    slots = {}
    for address in entries:
        slots[address] = len(slots)
        link.breakpoint(slots[address], address)

    started = time.time()
    rumble, calls, peak = False, 0, 0
    failures = set()
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
            at = r["rip"]
            stamp = f"[{time.time() - started:8.3f}]"
            if at in entries:
                name = entries[at]
                if name == "scePadSetVibrationMode":
                    if args.sdk is not None:
                        link.write(pid, base + sdk_at, struct.pack("<I", args.sdk))
                        print(f"{stamp} wrote SDK word {args.sdk:#x} at {base + sdk_at:#x}")
                    if args.mode is not None:
                        blob = link.getregs(lwp)
                        struct.pack_into("<Q", blob, REG["rsi"], args.mode)
                        link.setregs(lwp, blob)
                        r["rsi"] = args.mode
                        print(f"{stamp} mode argument replaced with {args.mode}")
                text = describe(name, r, link, pid)
                ret = struct.unpack("<Q", link.read(pid, r["rsp"], 8))[0]
                pending[lwp] = (name, text)
                if ret not in returns and len(slots) < MAX_BREAKPOINTS:
                    returns[ret] = True
                    slots[ret] = len(slots)
                    link.breakpoint(slots[ret], ret)
                if name != "scePadSetVibration":
                    print(f"{stamp} {name}({text})")
                else:
                    large = int(text.split("large=")[1].split()[0])
                    small = int(text.split("small=")[1])
                    active = large > 0 or small > 0
                    if active and not rumble:
                        print(f"{stamp} rumble start ({text})")
                        peak = 0
                    if active:
                        calls += 1
                        peak = max(peak, large, small)
                    if rumble and not active:
                        print(f"{stamp} rumble stop: {calls} calls, peak {peak}")
                        calls = 0
                    rumble = active
            elif at in returns and lwp in pending:
                name, text = pending.pop(lwp)
                code = r["rax"] & 0xffffffff
                if name != "scePadSetVibration":
                    print(f"{stamp} {name} -> {code:#010x}")
                elif code and code not in failures:
                    failures.add(code)
                    print(f"{stamp} {name} -> {code:#010x}")
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
