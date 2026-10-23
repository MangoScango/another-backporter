#!/usr/bin/env python3
"""Print the wait message and wait channel of every thread of a running title.

  kthread.py --host IP --title TITLEID

Needs no attach. Walks the kernel process list through ps5debug-NG's kernel
read command and reads each thread structure, the same 0x680 bytes its
thread-info command reads. Pointers inside the structure are never followed,
so kernel code and read-protected memory are not touched. The one exception
is the named thread's saved user trap frame, reached through the frame
pointer stored in the thread structure; the user stack is then read with the
ordinary process read. Wait values are printed raw; subtract the kernel
slide and look them up in a dump of the same firmware. Offsets are the ones ps5debug-NG uses for 7.00 to 7.61.
"""
import argparse
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from ps5debug import Link, find_title
from thread_dump import is_return_address, resolver

CMD_KERN_BASE, CMD_KERN_READ = 0xBDCC0001, 0xBDCC0002
ALLPROC = 0x2859D50
PROC_PID, PROC_THREADS = 0xBC, 0x10
THREAD_NEXT, THREAD_TID, THREAD_NAME, THREAD_SIZE = 0x10, 0x9C, 0x294, 0x680
THREAD_WMESG, THREAD_WCHAN = 0x560, 0x4A8
THREAD_KSTACK, THREAD_FRAME, THREAD_PCB = 0x470, 0x460, 0x3F8
USER_CS, USER_SS = 0x43, 0x3B
FRAME_SIZE, FRAME_RIP = 0xC0, 0x98
FRAME_REGS = {"rdi": 0x00, "rsi": 0x08, "rdx": 0x10, "rcx": 0x18, "r8": 0x20, "r9": 0x28, "rax": 0x30,
              "rbp": 0x40, "rsp": FRAME_RIP + 0x18}


def kread(link, address, length):
    link.send(CMD_KERN_READ, struct.pack("<QI", address, length))
    link.expect("kernel read")
    return link.recv(length)


def qword(link, address):
    return struct.unpack("<Q", kread(link, address, 8))[0]


def user_frame(link, blob):
    """Read the saved user trap frame through the thread's own frame pointer.
    The pointer must sit inside the kernel stack and below the pcb pointer,
    which keeps the read within memory the thread structure shows is mapped."""
    stack, frame_at, pcb = (struct.unpack_from("<Q", blob, off)[0]
                            for off in (THREAD_KSTACK, THREAD_FRAME, THREAD_PCB))
    if not (stack <= frame_at and frame_at + FRAME_SIZE <= pcb <= stack + 0x4000):
        return None
    frame = kread(link, frame_at, FRAME_SIZE)
    rip, cs, _flags, rsp, ss = struct.unpack_from("<5Q", frame, FRAME_RIP)
    print(f"    trap frame cs {cs:#x} ss {ss:#x}")
    if cs != USER_CS or ss != USER_SS:
        return None
    return {"rip": rip, **{n: struct.unpack_from("<Q", frame, o)[0] for n, o in FRAME_REGS.items()}}


def show_user_state(link, pid, frame):
    where = resolver(link.maps(pid))
    code = [(s, e) for n, s, e, prot in link.maps(pid, with_prot=True) if n and prot & 4]
    print(f"    rip {where(frame['rip'])}")
    print("    " + " ".join(f"{n} {frame[n]:#x}" for n in ("rax", "rdi", "rsi", "rdx", "rcx", "r8", "r9")))
    stack = link.read(pid, frame["rsp"], 0x800) or b""
    cache = {}
    shown = 0
    for i in range(0, len(stack) - 7, 8):
        word, = struct.unpack_from("<Q", stack, i)
        if any(a <= word < b for a, b in code) and is_return_address(link, pid, word, cache):
            print(f"    [rsp+{i:#x}] {where(word)}")
            shown += 1
            if shown == 16:
                break


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="console address")
    ap.add_argument("--title", required=True, help="title id")
    ap.add_argument("--name", default="eboot.bin", help="thread whose user state is shown")
    args = ap.parse_args()
    link = Link(args.host)
    pid = find_title(link, args.title, time.time())
    link.send(CMD_KERN_BASE)
    link.expect("kernel base")
    data_base, = struct.unpack("<Q", link.recv(8))
    print(f"pid {pid} kernel data base {data_base:#x}")

    proc = qword(link, data_base + ALLPROC)
    while proc:
        if struct.unpack("<I", kread(link, proc + PROC_PID, 4))[0] == pid:
            break
        proc = qword(link, proc)
    else:
        sys.exit("process not found in the kernel list")

    thread = qword(link, proc + PROC_THREADS)
    while thread:
        blob = kread(link, thread, THREAD_SIZE)
        tid, = struct.unpack_from("<I", blob, THREAD_TID)
        name = blob[THREAD_NAME:THREAD_NAME + 32].split(b"\0")[0].decode("latin1")
        wmesg, = struct.unpack_from("<Q", blob, THREAD_WMESG)
        wchan, = struct.unpack_from("<Q", blob, THREAD_WCHAN)
        print(f"tid {tid} {name!r} wmesg {wmesg:#x} wchan {wchan:#x}")
        if name == args.name:
            frame = user_frame(link, blob)
            if frame:
                show_user_state(link, pid, frame)
            else:
                print("    no user trap frame found")
        thread, = struct.unpack_from("<Q", blob, THREAD_NEXT)


if __name__ == "__main__":
    main()
