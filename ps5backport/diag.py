"""Diagnostic trap builds: the method that found the Unity 6 bug.

Build the title normally, then put ud2 at chosen sites: load-failure branches,
or the null checks after symbol lookups. A SIGILL rip in the UART log
identifies the site, and the registers hold the failing value. The site list
goes to sites.txt in the output folder.

"""
from pathlib import Path

from .build import build_title


def trap_at(vaddrs):
    """A build hook putting ud2 at each given vaddr. Use for chosen sites:
    load-failure branches, or the null checks after symbol lookups."""
    def hook(patcher):
        off = patcher.module._vaddr_to_offset
        for va in vaddrs:
            patcher.data[off(va):off(va) + 2] = b"\x0f\x0b"
        return {"traps": vaddrs}
    return hook


def diag_title(cfg, tier, registry, db, dump, out, fakelibs, traps,
               allow_unreviewed=False):
    """Build title with ud2 traps; writes sites.txt.

    traps maps an executable's basename to a list of vaddrs and is required —
    there is no default site heuristic.
    """
    if not traps:
        raise ValueError("no trap sites given; pass --trap file:vaddr "
                         "(a load-failure branch, or the null check after a symbol lookup)")
    hooks = {name: trap_at(vaddrs) for name, vaddrs in traps.items()}
    report = build_title(cfg, tier, registry, db, dump, out, fakelibs,
                         allow_unreviewed=allow_unreviewed, hooks=hooks)
    lines = []
    for name in sorted(traps):
        rel = next((r for r in report.get("hook_sites", {}) if Path(r).name == name), None)
        if rel is None:
            raise ValueError(f"{name} was not written (no stamp or stub need); nothing to trap")
        sites = report["hook_sites"][rel]["traps"]
        lines.append(f"{rel} traps ({len(sites)}): "
                     + " ".join("%#x" % s for s in sites))
    out = Path(out)
    (out / "sites.txt").write_text("\n".join(lines) + "\n")
    return report
