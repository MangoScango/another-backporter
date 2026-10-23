"""Acquire a title's executables into the cache and record its full file list.

Loose dumps are walked, including sce_sys, and copied; packages are listed with
img_file_list and the executables pulled out one by one with img_extract. The
full file list — executables and data alike — goes into files.csv next to the
cache; case fixes need it. Read-only against the source; re-running replaces
cached executables whose bytes changed.
"""
import csv
import filecmp
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

from . import elf

_TITLE_ID = re.compile(r"[A-Z]{4}\d{5}")


def _default_title(name):
    """The title id inside a dump/pkg name, falls back to the name."""
    m = _TITLE_ID.search(name)
    return m.group() if m else name


def is_binary(name):
    low = os.path.basename(name).lower()
    return low == "eboot.bin" or low.endswith(elf.EXEC_SUFFIXES)


def magic_of(path):
    with open(path, "rb") as f:
        m = f.read(4)
    if m == b"\x7fELF":
        return "ELF"
    if m in elf.SELF_MAGICS:
        return "SELF"
    return "?" + m.hex()


def _write_file_list(out, rows):
    with open(out / "files.csv", "w", newline="") as fh:
        w = csv.writer(fh)
        w.writerow(["rel", "size"])
        w.writerows(rows)


def _append_manifest(cfg, title, kind, src_name, entries):
    with open(cfg.cache / "manifest.csv", "a", newline="") as fh:
        w = csv.writer(fh)
        for rel, dst in entries:
            w.writerow([title, kind, src_name, rel, os.path.getsize(dst), magic_of(dst)])


def _prune_stale(root, keep):
    for path in sorted((p for p in root.rglob("*") if p.is_file()), reverse=True):
        if path == root / "files.csv":
            continue
        if path.relative_to(root) not in keep:
            path.unlink()
    for path in sorted((p for p in root.rglob("*") if p.is_dir()),
                       key=lambda p: len(p.parts), reverse=True):
        try:
            path.rmdir()
        except OSError:
            pass


def acquire_loose(cfg, src, title=None):
    """Cache a loose dump. Returns the title's cache directory."""
    src = Path(src)
    title = title or _default_title(src.name)
    out = cfg.cache / title
    out.mkdir(parents=True, exist_ok=True)
    rows, entries = [], []
    for root, dirs, files in os.walk(src):
        # sce_sys is walked too: sce_sys/about/right.sprx is a real executable
        # whose imports the plan must satisfy.
        dirs.sort()
        for name in sorted(files):
            full = Path(root) / name
            rel = full.relative_to(src)
            rows.append((str(rel), full.stat().st_size))
            if not is_binary(name):
                continue
            dst = out / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            unchanged = (dst.exists()
                         and dst.stat().st_size == full.stat().st_size
                         and filecmp.cmp(full, dst, shallow=False))
            if not unchanged:
                shutil.copyfile(full, dst)
            entries.append((str(rel), dst))
    _prune_stale(out, {Path(rel) for rel, _dst in entries})
    _write_file_list(out, rows)
    _append_manifest(cfg, title, "loose", src.name, entries)
    return out


def _pub_argv(cfg, args):
    """prospero-pub-cmd invocation: natively on Windows, via wine elsewhere."""
    if not cfg.pub_cmd:
        raise RuntimeError("pkg input needs PS5BACKPORT_PUB_CMD (prospero-pub-cmd.exe)")
    cmd = [str(cfg.pub_cmd), *args]
    return cmd if os.name == "nt" else ["wine", *cmd]


def _pub(cfg, *args):
    env = dict(os.environ, WINEDEBUG="-all")
    return subprocess.run(_pub_argv(cfg, args), env=env,
                          capture_output=True, text=True, errors="replace", timeout=3600)


def _extract_pkg_file(cfg, pkg, rel, dst):
    fd, tmp_name = tempfile.mkstemp(prefix=dst.name + ".", dir=dst.parent)
    os.close(fd)
    tmp = Path(tmp_name)
    tmp.unlink()
    try:
        r = _pub(cfg, "img_extract", "--passcode", cfg.passcode,
                 "--no_progress_bar", f"{pkg}:{rel}", str(tmp))
        if not tmp.exists():
            raise RuntimeError(f"extract failed: {rel}: {r.stdout[-200:]!r}")
        if dst.exists() and filecmp.cmp(tmp, dst, shallow=False):
            tmp.unlink()
        else:
            os.replace(tmp, dst)
    finally:
        if tmp.exists():
            tmp.unlink()


def acquire_pkg(cfg, pkg, title=None):
    """Cache the executables of a pkg. Returns the title's cache directory."""
    pkg = Path(pkg)
    title = title or _default_title(pkg.name.split(".")[0])
    out = cfg.cache / title
    out.mkdir(parents=True, exist_ok=True)
    r = _pub(cfg, "img_file_list", "--passcode", cfg.passcode, str(pkg))
    rows, binaries = [], []
    for line in r.stdout.splitlines():
        if not line.startswith("F "):
            continue
        parts = line.split(None, 2)
        if len(parts) != 3:
            continue
        size, rel = int(parts[1]), parts[2]
        rows.append((rel, size))
        if is_binary(rel):
            binaries.append((size, rel))
    if not binaries:
        raise RuntimeError(f"img_file_list gave no binaries (rc={r.returncode}): "
                           f"{r.stdout[-300:]!r} {r.stderr[-200:]!r}")
    entries = []
    for _size, rel in binaries:
        dst = out / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        _extract_pkg_file(cfg, pkg, rel, dst)
        entries.append((rel, dst))
    _prune_stale(out, {Path(rel) for rel, _dst in entries})
    _write_file_list(out, rows)
    _append_manifest(cfg, title, "pkg", pkg.name, entries)
    return out


def unwrap(cfg, title):
    """Turn a cached title's SELFs into ELFs under elf_cache/<title>.

    Only Sony-built SELFs may go through unself: running it on our own
    make_fself output shifts the version records by 8 bytes. The cache holds
    only originals, so that cannot happen here. Returns (stats, failures).
    """
    src, dst_root = cfg.cache / title, cfg.elf_cache / title
    stats, failures = {"elf": 0, "ok": 0, "ok-noparam": 0}, []
    keep = set()
    for root, _dirs, files in os.walk(src):
        for name in sorted(files):
            if name == "files.csv":
                continue
            full = Path(root) / name
            rel = full.relative_to(src)
            keep.add(rel)
            dst = dst_root / rel
            dst.parent.mkdir(parents=True, exist_ok=True)
            if dst.exists():
                dst.unlink()
            if magic_of(full) == "ELF":
                os.link(full, dst)
                stats["elf"] += 1
                continue
            try:
                dst.write_bytes(elf.unself(full.read_bytes()))
                stats["ok" if elf.read(dst) else "ok-noparam"] += 1
            except Exception as e:
                failures.append((str(rel), str(e)))
    if dst_root.exists():
        _prune_stale(dst_root, keep)
    return stats, failures
