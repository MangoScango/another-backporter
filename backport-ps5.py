#!/usr/bin/env python3
"""Backport a PS5 title to a lower firmware.

  backport-ps5.py run SRC OUT                  end to end: acquire, unwrap, plan, build
  backport-ps5.py acquire SRC [--title ID]   cache a dump or pkg's executables
  backport-ps5.py unwrap TITLE               SELF -> ELF into the ELF cache
  backport-ps5.py plan [--tier 7xx]          fakelib plan over the ELF cache
  backport-ps5.py build DUMP OUT             build one title's backport folder
  backport-ps5.py diag DUMP OUT              build with diagnostic traps

"""
import argparse
import json
import sys
from pathlib import Path

from ps5backport import acquire as acq
from ps5backport.build import BuildError, build_fakelib_set, build_title
from ps5backport.callsites import CallsiteRuleError
from ps5backport.fakelib_patches import FakelibPatchError
from ps5backport.translations import TranslationError
from ps5backport.rules import RuleSet
from ps5backport.config import TIERS, Config
from ps5backport.diag import diag_title
from ps5backport.exportdb import ExportDB
from ps5backport.plan import Planner, UnresolvedImports
from ps5backport.registry import RegistryError, StubRegistry


def load_db(cfg):
    db = ExportDB(cfg.fwdb)
    db.load_priv(cfg.libs, cfg.cache / "priv-exports.pkl")
    return db


def named_patches(args):
    """The named fakelib patch ids asked for with --apply."""
    return [i for i in args.apply.split(",") if i]
def fakelibs_for(args, cfg):
    """The title's fakelib list from --plan, or the explicit --fakelibs."""
    if args.plan:
        plan = json.loads(Path(args.plan).read_text())
        title = Path(args.dump).name
        try:
            return plan["titles"][title]["fakelibs"]
        except KeyError:
            sys.exit(f"error: {title} is not in {args.plan}")
    return [f for f in args.fakelibs.split(",") if f]


def cmd_plan(args, cfg):
    db = load_db(cfg)
    registry = StubRegistry(cfg.registry)
    titles = [Path(t) for t in args.titles] if args.titles else \
        sorted(p for p in cfg.elf_cache.iterdir() if p.is_dir())
    if not titles:
        sys.exit("error: no titles to plan over (empty ELF cache?)")
    tier = TIERS[args.tier]
    plan = Planner(cfg, db, tier, registry).plan(titles)
    path = plan.write(args.out or f"fakelibs-{args.tier}")
    report = plan.to_json()
    print(f"target {tier.level}: {len(plan.universe)} fakelibs cover {len(titles)} titles")
    for m in plan.universe:
        info = report["fakelibs"][m]
        counts = {}
        for s in info["stubs"]:
            counts[s["status"]] = counts.get(s["status"], 0) + 1
        print(f"  {m:28} from {info['source']:5} titles={len(info['titles']):2} "
              f"(direct {len(info['direct']):2}) stubs={len(info['stubs']):3} {counts}")
    print(f"\ngame-side stubs (modules that cannot be fakelibs): {len(report['game_side'])}")
    for g in report["game_side"]:
        print(f"  {g['library']:26} {g['nid']:14} {g['name']:44} {g['status']:10} "
              f"titles={len(g['titles'])}")
    print(f"\nwrote {path}")


def cmd_build(args, cfg):
    db = load_db(cfg)
    registry = StubRegistry(cfg.registry)
    tier = TIERS[args.tier]
    fakelibs = fakelibs_for(args, cfg)
    report = build_title(cfg, tier, registry, db, args.dump, args.out, fakelibs,
                         allow_unreviewed=args.allow_unreviewed,
                         unpeg_shim=args.unpeg_shim,
                         rules=RuleSet.load(cfg), apply=named_patches(args))
    _print_build_summary(args.out, report)


def cmd_diag(args, cfg):
    db = load_db(cfg)
    registry = StubRegistry(cfg.registry)
    tier = TIERS[args.tier]
    fakelibs = fakelibs_for(args, cfg)
    traps = {}
    for spec in args.trap:
        name, _, va = spec.partition(":")
        traps.setdefault(name, []).append(int(va, 16))
    report = diag_title(cfg, tier, registry, db, args.dump, args.out, fakelibs,
                        traps=traps,
                        allow_unreviewed=args.allow_unreviewed,
                        rules=RuleSet.load(cfg), apply=named_patches(args))
    _print_build_summary(args.out, report)
    print(Path(args.out, "sites.txt").read_text())


def _print_build_summary(out, report):
    applied = [s for f in report["files"].values() for s in f["stubs"].values()]
    unreviewed = sum(s["status"] != "reviewed" for s in applied)
    cased = sum(1 for f in report["files"].values()
                for l in f["retargeted"] if l.startswith("case "))
    patched = sum(len(r["sites"]) for f in report["files"].values()
                  for r in f.get("callsite_rules", ()))
    module_patches = sum(len(f.get("fakelib_patches", ())) for f in report["files"].values())
    translated = sum(len(r["sites"]) for f in report["files"].values()
                     for r in f.get("translations", ()))
    print(f"wrote {out}: {len(report['files'])} files "
          f"({len(report['unchanged'])} unchanged, skipped), "
          f"{len(applied)} stubs ({unreviewed} unreviewed), "
          f"{cased} case fixes, {patched} call-site patches, "
          f"{module_patches} fakelib patches, {translated} constant translations, "
          f"{len(report['case_warnings'])} case warnings, "
          f"{len(report['unshipped'])} unshipped imports left unbound")
    for line in report.get("warnings", ()):
        print(f"warning: {line}", file=sys.stderr)


def cmd_run(args, cfg):
    from ps5backport.build import run_title
    db = load_db(cfg)
    registry = StubRegistry(cfg.registry)
    tier = TIERS[args.tier]
    print(f"acquire {args.src} ...")
    plan, report = run_title(cfg, tier, registry, db, args.src, args.out,
                             title=args.title,
                             allow_unreviewed=args.allow_unreviewed,
                             unpeg_shim=args.unpeg_shim,
                             rules=RuleSet.load(cfg), apply=named_patches(args))
    title = next(iter(plan.titles))
    print(f"plan {title}: {sorted(plan.titles[title]['fakelibs'])}")
    _print_build_summary(args.out, report)


def cmd_acquire(args, cfg):
    src = Path(args.src)
    if src.is_dir():
        out = acq.acquire_loose(cfg, src, args.title)
    else:
        out = acq.acquire_pkg(cfg, src, args.title)
    print(f"cached {out.name}: {sum(1 for _ in out.rglob('*'))} files")


def cmd_unwrap(args, cfg):
    stats, failures = acq.unwrap(cfg, args.title)
    print(f"{args.title}: {stats}")
    # Encrypted files (e.g. sce_sys/about/right.sprx) cannot be unwrapped or
    # patched; warn and leave them out of the ELF cache.
    for rel, err in failures:
        print(f"  warning: unwrap failed: {rel}: {err}")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="backport-ps5.py",
                                 description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("acquire", help="cache a dump or pkg's executables")
    p.add_argument("src", help="loose dump directory or .pkg")
    p.add_argument("--title")
    p.set_defaults(run=cmd_acquire)

    p = sub.add_parser("unwrap", help="SELF -> ELF into the ELF cache")
    p.add_argument("title")
    p.set_defaults(run=cmd_unwrap)

    p = sub.add_parser("plan", help="fakelib plan over the ELF cache")
    p.add_argument("--tier", default="7xx", choices=sorted(TIERS))
    p.add_argument("--titles", nargs="+", help="title dirs (default: the ELF cache)")
    p.add_argument("--out", help="plan output directory")
    p.set_defaults(run=cmd_plan)

    p = sub.add_parser("run", help="end to end: acquire, unwrap, plan, build")
    p.add_argument("src", help="loose dump directory or .pkg")
    p.add_argument("out", help="backport output folder")
    p.add_argument("--title", help="title id (default: source name)")
    p.add_argument("--tier", default="7xx", choices=sorted(TIERS))
    p.add_argument("--allow-unreviewed", action="store_true")
    p.add_argument("--apply", default="", metavar="ID[,ID]",
                   help="named fakelib patches to apply (see registry/fakelib-patches.csv)")
    p.add_argument("--unpeg-shim", action="store_true",
                   help="experimental: VideoOut fakelib unpegs VRR for VRR-aware apps")
    p.set_defaults(run=cmd_run)

    for name, run, help_ in (("build", cmd_build, "build one title's backport folder"),
                             ("diag", cmd_diag, "build with diagnostic traps")):
        p = sub.add_parser(name, help=help_)
        p.add_argument("dump", help="title directory (e.g. the ELF cache dir)")
        p.add_argument("out", help="backport output folder")
        p.add_argument("--tier", default="7xx", choices=sorted(TIERS))
        p.add_argument("--fakelibs", default="",
                       help="comma-separated module names")
        p.add_argument("--plan", help="plan JSON to take the title's fakelibs from")
        p.add_argument("--allow-unreviewed", action="store_true")
        p.add_argument("--apply", default="", metavar="ID[,ID]",
                       help="named fakelib patches to apply (see registry/fakelib-patches.csv)")
        p.add_argument("--unpeg-shim", action="store_true",
                       help="experimental: VideoOut fakelib unpegs VRR for VRR-aware apps")
        if name == "diag":
            p.add_argument("--trap", action="append", required=True, metavar="FILE:VADDR",
                           help="ud2 at this vaddr in this file (repeatable; required)")
        p.set_defaults(run=run)

    args = ap.parse_args(argv)
    cfg = Config.default()
    try:
        args.run(args, cfg)
    except (UnresolvedImports, RegistryError, BuildError, CallsiteRuleError, FakelibPatchError, TranslationError) as e:
        sys.exit(f"error:\n{e}")


if __name__ == "__main__":
    main()
