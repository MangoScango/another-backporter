"""Find executable path strings whose case differs from the shipped file's name.

NSFS redirects match the requested path case-sensitively, so a game that asks for
"Foo.prx" while the image holds "foo.prx" bypasses the backport's copy.
"""
import re
from pathlib import Path

RUN = re.compile(rb"[\x20-\x7e]{4,300}(?=\0)")
# Only module names are rewritten; other matches (e.g. "EBOOT.BIN") are reported.
PATCHABLE = (".prx", ".sprx")


def mismatches(executables, shipped):
    """executables: {rel: bytes} to scan; shipped: rel paths that will be redirected.

    Returns [(owner, offset, found, ondisk)] for names that match a shipped file
    ignoring case but not exactly.
    """
    names = {}
    for rel in shipped:
        name = Path(rel).name
        names.setdefault(name.lower(), set()).add(name)
    found = []
    for owner, data in executables.items():
        for m in RUN.finditer(data):
            base = m.group().rsplit(b"/", 1)[-1].decode("ascii")
            real = names.get(base.lower())
            if real and base not in real and len(real) == 1:
                found.append((owner, m.end() - len(base), base, next(iter(real))))
    return found


def patchable(ondisk):
    return ondisk.lower().endswith(PATCHABLE)
