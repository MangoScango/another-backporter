"""ps5debug-NG wire protocol: framing, commands and register layouts used by the tools."""
import socket
import struct
import sys
import time

MAGIC = 0xFFAABBCC
SUCCESS = 0x80000000
CMD_PROC_LIST, CMD_PROC_READ, CMD_PROC_WRITE, CMD_PROC_MAPS, CMD_PROC_INFO = (
    0xBDAA0001, 0xBDAA0002, 0xBDAA0003, 0xBDAA0004, 0xBDAA000A)
CMD_PROC_READ_STACK = 0xBDAA0023
CMD_ATTACH, CMD_DETACH, CMD_BREAKPOINT, CMD_THREAD_LIST = 0xBDBB0001, 0xBDBB0002, 0xBDBB0003, 0xBDBB0005
CMD_GETREGS, CMD_SETREGS, CMD_CONTINUE, CMD_THREAD_INFO = 0xBDBB0008, 0xBDBB0009, 0xBDBB0010, 0xBDBB0011
EVENT_SIZE = 0x4A0
REG = dict(r15=0x00, r14=0x08, r13=0x10, r12=0x18, r11=0x20, r10=0x28, r9=0x30, r8=0x38,
           rdi=0x40, rsi=0x48, rbp=0x50, rbx=0x58, rdx=0x60, rcx=0x68, rax=0x70, rip=0x88, rsp=0xA0)
REG_BASE = 0x30
MAX_BREAKPOINTS = 30



class Link:
    def __init__(self, host, port=744):
        self.sock = socket.create_connection((host, port), timeout=10)

    def recv(self, n):
        out = bytearray()
        while len(out) < n:
            chunk = self.sock.recv(n - len(out))
            if not chunk:
                raise ConnectionError("console closed the connection")
            out += chunk
        return bytes(out)

    def send(self, cmd, body=b""):
        self.sock.sendall(struct.pack("<III", MAGIC, cmd, len(body)) + body)

    def status(self):
        return struct.unpack("<I", self.recv(4))[0]

    def expect(self, what):
        got = self.status()
        if got != SUCCESS:
            raise RuntimeError(f"{what}: status {got:#x}")

    def processes(self):
        self.send(CMD_PROC_LIST)
        self.expect("proc list")
        count, = struct.unpack("<I", self.recv(4))
        data = self.recv(36 * count)
        return [(data[i * 36:i * 36 + 32].split(b"\0")[0].decode("latin1"),
                 struct.unpack_from("<i", data, i * 36 + 32)[0]) for i in range(count)]

    def title_of(self, pid):
        self.send(CMD_PROC_INFO, struct.pack("<I", pid))
        if self.status() != SUCCESS:
            return ""
        data = self.recv(188)
        return data[108:124].split(b"\0")[0].decode("latin1")

    def maps(self, pid, with_prot=False):
        self.send(CMD_PROC_MAPS, struct.pack("<I", pid))
        self.expect("proc maps")
        count, = struct.unpack("<I", self.recv(4))
        data = self.recv(58 * count)
        out = []
        for i in range(count):
            name = data[i * 58:i * 58 + 32].split(b"\0")[0].decode("latin1")
            start, end = struct.unpack_from("<QQ", data, i * 58 + 32)
            prot, = struct.unpack_from("<H", data, i * 58 + 56)
            out.append((name, start, end, prot) if with_prot else (name, start, end))
        return out

    def read(self, pid, address, length):
        self.send(CMD_PROC_READ, struct.pack("<IQI", pid, address, length))
        if self.status() != SUCCESS:
            return None
        return self.recv(length)

    def write(self, pid, address, data):
        self.send(CMD_PROC_WRITE, struct.pack("<IQI", pid, address, len(data)))
        self.expect("write")
        self.sock.sendall(data)
        self.expect("write data")

    def getregs(self, lwp):
        self.send(CMD_GETREGS, struct.pack("<I", lwp))
        self.expect("getregs")
        return bytearray(self.recv(176))

    def setregs(self, lwp, blob):
        self.send(CMD_SETREGS, struct.pack("<II", lwp, len(blob)))
        self.expect("setregs")
        self.sock.sendall(bytes(blob))
        self.expect("setregs data")

    def breakpoint(self, index, address, enabled=1):
        self.send(CMD_BREAKPOINT, struct.pack("<IIQ", index, enabled, address))
        self.expect(f"breakpoint {index}")

    def resume(self):
        self.send(CMD_CONTINUE, struct.pack("<I", 0))
        self.expect("continue")

    def stop(self):
        self.send(CMD_CONTINUE, struct.pack("<I", 1))
        self.expect("stop")

    def threads(self):
        self.send(CMD_THREAD_LIST)
        self.expect("thread list")
        count, = struct.unpack("<I", self.recv(4))
        return list(struct.unpack(f"<{count}I", self.recv(4 * count)))

    def thread_info(self, lwp):
        self.send(CMD_THREAD_INFO, struct.pack("<I", lwp))
        self.expect("thread info")
        _lwp, priority, name = struct.unpack("<II32s", self.recv(40))
        return priority, name.split(b"\0")[0].decode("latin1")

    def stack(self, pid, rbp, rsp, depth=24):
        """Return addresses from a server-side RBP chain walk."""
        self.send(CMD_PROC_READ_STACK, struct.pack("<IQQI", pid, rbp, rsp, depth))
        self.expect("read stack")
        length, = struct.unpack("<I", self.recv(4))
        bundle = self.recv(length)
        frames, at = [], 4
        for _ in range(struct.unpack_from("<I", bundle, 0)[0]):
            header = struct.Struct("<QQQQIII")
            _rbp, _rsp, _saved, ret, _flags, locals_len, code_len = header.unpack_from(bundle, at)
            frames.append(ret)
            at += header.size + locals_len + code_len
        return frames


def find_title(link, title, stamp):
    while True:
        for name, pid in link.processes():
            if name == "eboot.bin" and link.title_of(pid).startswith(title):
                return pid
        time.sleep(0.25)
        if time.time() - stamp > 600:
            sys.exit("title never appeared")


def regs(event, base=REG_BASE):
    return {k: struct.unpack_from("<Q", event, base + o)[0] for k, o in REG.items()}


