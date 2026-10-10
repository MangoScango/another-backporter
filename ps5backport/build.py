"""Build the fakelib set and the per-title backport folder.

A title's folder holds only files that must differ from the game: fakelibs
under fakelib/, plus game executables whose stamp exceeds the tier or whose
imports need stubs. Stamps are lowered, never raised. Everything written is
fake-signed. Nothing is written when the registry refuses any stub — the
refusals are collected and reported as one full list first.
"""
import json
import os
import shutil
import struct
import subprocess
import sys
import tempfile
from pathlib import Path

from . import casefix, elf
from .config import APP_SUPPLIED_MODULES, NOT_FAKELIBBABLE
from .patch import Patcher
from .registry import RegistryError

PAID = "0x3100000000000002"


class BuildError(Exception):
    pass


def fake_sign(cfg, elf_path, dest):
    """make_fself --ptype fake --paid 0x3100000000000002; plain ELFs fail auth."""
    subprocess.run([sys.executable, str(cfg.make_fself), "--ptype", "fake",
                    "--paid", PAID, str(elf_path), str(dest)],
                   check=True, capture_output=True)


def game_executables(dump):
    """Title-relative paths of ELF executables in dump, skipping sce_sys."""
    for dirpath, dirnames, filenames in os.walk(dump):
        dirnames[:] = sorted(d for d in dirnames if d != "sce_sys")
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.stat().st_size < 64:
                continue
            with open(path, "rb") as fh:
                if fh.read(4) != b"\x7fELF":
                    continue
            yield path.relative_to(dump)


def stamp_words(module):
    """(ps5, ps4) SDK words from the param segment, or None."""
    if module.param is None:
        return None
    ps4, ps5 = struct.unpack_from("<II", module.data, module.param + 0x10)
    return ps5, ps4


def _check_refused(registry, plan, allow_unreviewed=False):
    """Collect every refused stub across the plan; raise with the full list."""
    refused = {}
    for rel, _, stubs in plan:
        for pair, why in registry.refused(stubs, allow_unreviewed):
            row = registry.entry(pair) or {}
            key = f"{pair[0]}:{pair[1]}"
            entry = refused.setdefault(key, {"why": why, "name": row.get("name") or "", "in": []})
            entry["in"].append(str(rel))
    if refused:
        lines = [f"{len(refused)} import(s) need a registry entry or review; nothing written:"]
        for key, info in sorted(refused.items()):
            lines.append(f"  {key} ({info['why']}) {info['name']} — in {', '.join(info['in'])}")
        raise BuildError("\n".join(lines))


def _stub_report(registry, placed):
    return {f"{addr:#x}": {"key": f"{pair[0]}:{pair[1]}",
                           "name": registry.entry(pair)["name"],
                           "status": registry.entry(pair)["status"],
                           "tells_game": registry.entry(pair)["tells_game"]}
            for addr, pair in sorted(placed.items())}


def build_fakelib_set(cfg, tier, registry, fakelib_plan, out_dir,
                      allow_unreviewed=False, unpeg_shim=False):
    """Build the tier's fakelibs into out_dir/fakelib/.

    fakelib_plan maps module name to its stub set {(library, nid)}; sources
    come from the configured firmware (and its overrides).
    """
    bad = set(fakelib_plan) & NOT_FAKELIBBABLE
    if bad:
        raise BuildError(f"cannot be fakelibs (load before the overlay): {sorted(bad)}")
    _check_refused(registry, [(Path("fakelib") / n, None, s)
                              for n, s in fakelib_plan.items()], allow_unreviewed)

    dest_dir = Path(out_dir) / "fakelib"
    dest_dir.mkdir(parents=True, exist_ok=True)
    report = {"level": tier.level, "allow_unreviewed": allow_unreviewed, "files": {}}
    vrr_src = Path(__file__).with_name("vrr_shim.s")
    with tempfile.TemporaryDirectory() as tmp:
        for name in sorted(fakelib_plan):
            src = cfg.system_module(name)
            patcher = Patcher(str(src))
            patcher.stamp(tier)
            placed = patcher.stub_registered(fakelib_plan[name], registry, allow_unreviewed)
            if unpeg_shim and name == "libSceVideoOut.sprx":
                patcher.vrr_shims(str(vrr_src))
            unsigned = Path(tmp) / "unsigned.elf"
            patcher.write(unsigned)
            dest = dest_dir / name
            fake_sign(cfg, unsigned, dest)
            report["files"][name] = {
                "source": cfg.source_override.get(name, cfg.source_fw),
                "bytes": dest.stat().st_size,
                "stubs": _stub_report(registry, placed),
                "log": patcher.log}
    return report


def build_title(cfg, tier, registry, db, dump, out, fakelibs,
                allow_unreviewed=False, unpeg_shim=False, hooks=None):
    """Build the backport folder for one title. Returns the report dict.

    hooks maps an executable's basename to a callable run on its Patcher after
    stubs and case fixes, before signing (the diagnostics mode uses this).
    """
    dump, out = Path(dump), Path(out)
    fakelibs = sorted(fakelibs)
    bad = set(fakelibs) & NOT_FAKELIBBABLE
    if bad:
        raise BuildError(f"cannot be fakelibs (load before the overlay): {sorted(bad)}")

    sources = {name: cfg.system_module(name) for name in fakelibs}
    modules = {name: elf.read(path) for name, path in sources.items()}
    game = sorted(game_executables(dump))
    game_modules = {rel: elf.read(dump / rel) for rel in game}
    provided = set().union(set(), *(m.export_pairs() for m in modules.values()),
                           *(m.export_pairs() for m in game_modules.values()))

    plan = []
    for name, module in modules.items():
        siblings = set().union(set(), *(m.export_pairs() for n, m in modules.items() if n != name))
        stubs = {p for p in set(module.imports)
                 if not db.exported_at(p, tier.level) and p not in siblings}
        plan.append((Path("fakelib") / name, sources[name], stubs))
    unchanged = []
    unshipped = {}
    for rel, module in game_modules.items():
        stubs = set()
        for p in set(module.imports):
            if db.exported_at(p, tier.level) or p in provided:
                continue
            # Game-supplied libraries (libkernel's table) the title doesn't
            # carry are left unbound, not stubbed: it is not asking the
            # firmware for anything (Astro's libSceJobManager precedent).
            if p not in db.ranges and p[0] in APP_SUPPLIED_MODULES:
                unshipped.setdefault(p, set()).add(str(rel))
                continue
            stubs.add(p)
        words = stamp_words(module)
        too_new = (words is not None
                   and (words[0] > tier.stamp_ps5 or words[1] > tier.stamp_ps4))
        if stubs or too_new:
            plan.append((rel, dump / rel, stubs))
        else:
            unchanged.append(str(rel))

    shipped = [rel for rel, _, _ in plan if rel.parts[0] != "fakelib"]
    case_warnings = [
        f"{owner} @{off:#x}: {found!r} vs shipped {real!r}"
        for owner, off, found, real in casefix.mismatches(
            {str(r): m.data for r, m in game_modules.items() if str(r) in unchanged}, shipped)]

    _check_refused(registry, plan, allow_unreviewed)

    if out.exists():
        shutil.rmtree(out)
    report = {"dump": str(dump), "level": tier.level,
              "stamps": {"ps5": tier.stamp_ps5, "ps4": tier.stamp_ps4},
              "source": cfg.source_fw, "overrides": cfg.source_override,
              "allow_unreviewed": allow_unreviewed, "files": {},
              "unchanged": unchanged, "case_warnings": case_warnings,
              "unshipped": [{"library": p[0], "nid": p[1], "in": sorted(files)}
                            for p, files in sorted(unshipped.items())]}
    vrr_src = Path(__file__).with_name("vrr_shim.s")
    hook_sites = {}
    with tempfile.TemporaryDirectory() as tmp:
        for rel, src, stubs in plan:
            patcher = Patcher(str(src))
            patcher.stamp(tier)
            placed = patcher.stub_registered(stubs, registry, allow_unreviewed)
            if rel.parts[0] != "fakelib":
                for _, off, found, real in casefix.mismatches({str(rel): bytes(patcher.data)}, shipped):
                    if casefix.patchable(real):
                        patcher.data[off:off + len(real)] = real.encode()
                        patcher.log.append(f"case {found} -> {real} @{off:#x}")
                    else:
                        case_warnings.append(f"{rel} @{off:#x}: {found!r} vs shipped {real!r}")
            if unpeg_shim and rel == Path("fakelib/libSceVideoOut.sprx"):
                patcher.vrr_shims(str(vrr_src))
            if hooks and rel.name in hooks:
                hook_sites[str(rel)] = hooks[rel.name](patcher)
            unsigned = Path(tmp) / "unsigned.elf"
            patcher.write(unsigned)
            dest = out / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            fake_sign(cfg, unsigned, dest)
            report["files"][str(rel)] = {
                "stubs": _stub_report(registry, placed),
                "retargeted": [l for l in patcher.log if l.startswith(
                    ("retargeted", "unpeg shim", "vrr shims", "case "))],
                "warnings": [l for l in patcher.log if l.startswith("WARNING")]}
    (out.parent / f"{out.name}-report.json").write_text(json.dumps(report, indent=1))
    if hook_sites:
        report["hook_sites"] = hook_sites
    return report


def run_title(cfg, tier, registry, db, src, out, title=None,
              allow_unreviewed=False, unpeg_shim=False):
    """End to end for one title: acquire -> unwrap -> plan -> build.

    src is a loose dump folder or a .pkg. The title is planned on its own;
    per the tier design it gets exactly the fakelibs its own closure selects.
    Returns (plan, report).
    """
    from .acquire import acquire_loose, acquire_pkg, unwrap
    from .plan import Planner

    src = Path(src)
    cached = acquire_loose(cfg, src, title) if src.is_dir() else acquire_pkg(cfg, src, title)
    title = cached.name
    _stats, failures = unwrap(cfg, title)
    # Ununwrapable files (e.g. the encrypted sce_sys/about/right.sprx) cannot
    # be scanned or patched; warn and continue without them.
    for rel, err in failures:
        print(f"warning: unwrap failed: {rel}: {err}", file=sys.stderr)
    dump = cfg.elf_cache / title
    plan = Planner(cfg, db, tier, registry).plan([dump])
    out = Path(out)
    out.parent.mkdir(parents=True, exist_ok=True)
    plan_path = out.parent / f"{out.name}-plan.json"
    plan_path.write_text(json.dumps(plan.to_json(), indent=1))
    fakelibs = sorted(plan.titles[title]["fakelibs"])
    report = build_title(cfg, tier, registry, db, dump, out, fakelibs,
                         allow_unreviewed=allow_unreviewed, unpeg_shim=unpeg_shim)
    if failures:
        report["unwrap_failures"] = [{"file": rel, "error": err} for rel, err in failures]
    return plan, report
