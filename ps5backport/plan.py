"""Plan the fakelib set for a tier over every title at once.

Seed: route each import missing at the target level to the system module that
carries it at the source firmware — fakelib-able common/lib modules join the
seed, non-fakelib-able modules make the import game-side (stubbed in the
importing file), and no carrier at all makes it a blocker.

Closure: a fakelib's own imports must resolve against the target plus its
sibling fakelibs; whatever still doesn't resolve gets stubbed in the fakelib.

Planning never emits a partial result: any blocker aborts the plan with the
full list of unresolved imports, not just the first failure.
"""
import json
import os
from pathlib import Path

from . import elf
from .config import APP_SUPPLIED_MODULES, NOT_FAKELIBBABLE

SELF_MAGICS = {b"\x4f\x15\x3d\x1d": "PS4 SELF", b"\x54\x14\xf5\xee": "PS5 SELF"}


class UnresolvedImports(Exception):
    """Imports no firmware module can carry. The plan is aborted; nothing is
    built. `unresolved` holds every (title, file, library, nid)."""

    def __init__(self, unresolved):
        self.unresolved = sorted(unresolved)
        lines = ["%d unresolved import(s); no plan written:" % len(self.unresolved)]
        for title, rel, library, nid in self.unresolved:
            lines.append(f"  {title}: {rel} imports {library}:{nid} — no carrier module")
        super().__init__("\n".join(lines))


def find_content(dump):
    """-> (executables relative to dump, param.sfo path or None)"""
    execs, sfo = [], None
    for root, dirs, files in os.walk(dump):
        dirs.sort()
        for name in sorted(files):
            full = os.path.join(root, name)
            rel = os.path.relpath(full, dump)
            low = name.lower()
            if low == 'param.sfo' and os.path.basename(root) == 'sce_sys':
                sfo = full
            elif low == 'eboot.bin' or low.endswith(elf.EXEC_SUFFIXES):
                execs.append(rel)
    return execs, sfo


def collect_modules(dump):
    """Parse every executable in a title. -> (modules, blanked library names)"""
    modules, blanked = [], set()
    for rel in find_content(dump)[0]:
        full = os.path.join(dump, rel)
        module = elf.read(full)
        if module is not None:
            modules.append(module)
        elif os.path.getsize(full) == 0:
            blanked.add(os.path.basename(rel).rsplit('.', 1)[0])
    return modules, blanked


def title_imports(title_dir, db):
    """Sort a title's imports into what nothing inside it satisfies.

    -> (modules, importers, unshipped, superseded, unreadable)

    importers and unshipped map (library, nid) to the set of title-relative
    files importing it: unshipped holds game-supplied libraries no firmware
    exports and the title does not carry, importers everything else.
    """
    modules, blanked = collect_modules(title_dir)
    parsed = {m.path for m in modules}
    unreadable = []
    for rel in find_content(title_dir)[0]:
        full = os.path.join(title_dir, rel)
        if full in parsed or os.path.getsize(full) == 0:
            continue
        with open(full, 'rb') as fh:
            magic = fh.read(4)
        unreadable.append((rel, SELF_MAGICS.get(
            magic, 'unparsable ELF' if magic == b'\x7fELF' else 'not an ELF')))

    provided = set()
    for module in modules:
        provided |= module.export_pairs()
    importers, unshipped, superseded = {}, {}, set()
    for module in modules:
        rel = os.path.relpath(module.path, title_dir)
        for pair in module.imports:
            if pair in provided:
                continue
            if pair[0] in blanked:
                superseded.add(pair[0])
                continue
            bucket = (unshipped if pair not in db.ranges
                      and pair[0] in APP_SUPPLIED_MODULES else importers)
            bucket.setdefault(pair, set()).add(rel)
    return modules, importers, unshipped, superseded, unreadable


class Planner:
    def __init__(self, cfg, db, tier, registry=None):
        self.cfg = cfg
        self.db = db
        self.tier = tier
        self.registry = registry
        self._modules = {}

    def module_at(self, name):
        """The module's ELF at its source firmware, or None when absent."""
        if name not in self._modules:
            fw = self.cfg.source_override.get(name)
            path = self.cfg.system_module(name, fw)
            self._modules[name] = elf.read(path) if path.exists() else None
        return self._modules[name]

    def carrier_of(self, pair):
        module, _ = self.db.carrier(pair[0], self.cfg.source_fw)
        return module

    def closure(self, seed):
        """Add every fakelib-able module whose newer export a selected one
        imports; stub whatever still doesn't resolve. -> (selected, stubs)"""
        selected = set(seed)
        while True:
            provided = set().union(*(self.module_at(m).export_pairs()
                                     for m in selected)) if selected else set()
            added, stubs = set(), {}
            for m in selected:
                for pair in self.module_at(m).imports:
                    if pair in provided or self.db.exported_at(pair, self.tier.level):
                        continue
                    carrier = self.carrier_of(pair)
                    other = (self.module_at(carrier)
                             if carrier and carrier not in NOT_FAKELIBBABLE else None)
                    if (other is not None and carrier not in selected
                            and pair[1] in other.exports.get(pair[0], ())):
                        added.add(carrier)
                    else:
                        stubs.setdefault(m, set()).add(pair)
            if not added:
                return selected, stubs
            selected |= added

    def plan_title(self, title_dir):
        """-> (seed, fakelibs, game_side, blockers, stubs) for one title.

        game_side maps (library, nid) to importing files; blockers maps
        (library, nid) to importing files for pairs with no carrier.
        """
        _m, importers, _u, _s, _r = title_imports(str(title_dir), self.db)
        seed, game_side, blockers = set(), {}, {}
        for pair, files in importers.items():
            if pair not in self.db.ranges or self.db.exported_at(pair, self.tier.level):
                continue
            carrier = self.carrier_of(pair)
            if carrier in NOT_FAKELIBBABLE:
                game_side[pair] = files
            elif carrier is None or self.module_at(carrier) is None:
                blockers[pair] = files
            else:
                seed.add(carrier)
        selected, stubs = self.closure(seed)
        return seed, selected, game_side, blockers, stubs

    def plan(self, title_dirs):
        """The tier's plan over every title. Raises UnresolvedImports listing
        every unresolved import when any title has a blocker."""
        titles, unresolved = {}, []
        for title_dir in sorted(title_dirs, key=lambda p: Path(p).name):
            name = Path(title_dir).name
            seed, selected, game_side, blockers, stubs = self.plan_title(title_dir)
            titles[name] = {"seed": seed, "fakelibs": selected,
                            "game_side": game_side, "blockers": blockers,
                            "stubs": stubs}
            for pair, files in blockers.items():
                for rel in files:
                    unresolved.append((name, rel, pair[0], pair[1]))
        if unresolved:
            raise UnresolvedImports(unresolved)

        universe, stubs_all = self.closure(
            set().union(*(t["seed"] for t in titles.values())))
        # A title's closed subset needs the same stubs as the universe build.
        for name, t in titles.items():
            for m in t["fakelibs"]:
                assert t["stubs"].get(m, set()) == stubs_all.get(m, set()), (name, m)
        return Plan(self.cfg, self.tier, universe, stubs_all, titles,
                    registry=self.registry, db=self.db)


class Plan:
    def __init__(self, cfg, tier, universe, stubs_all, titles, registry=None, db=None):
        self.cfg = cfg
        self.tier = tier
        self.universe = sorted(universe)
        self.stubs = stubs_all          # {module: {(library, nid)}}
        self.titles = titles            # per-title planner output
        self.registry = registry
        self.db = db

    def status(self, pair):
        row = self.registry.entry(pair) if self.registry else None
        return row["status"] if row else "MISSING"

    def label(self, pair):
        name = self.db.names.get(pair) if self.db else None
        if name:
            return name
        row = self.registry.entry(pair) if self.registry else None
        return (row or {}).get("name") or ""

    def to_json(self):
        report = {"level": self.tier.level,
                  "stamps": {"ps5": self.tier.stamp_ps5, "ps4": self.tier.stamp_ps4},
                  "fakelibs": {}, "titles": {}, "game_side": []}
        for m in self.universe:
            users = sorted(n for n, t in self.titles.items() if m in t["fakelibs"])
            direct = sorted(n for n, t in self.titles.items() if m in t["seed"])
            report["fakelibs"][m] = {
                "source": self.cfg.source_override.get(m, self.cfg.source_fw),
                "titles": users, "direct": direct,
                "stubs": [{"library": p[0], "nid": p[1], "name": self.label(p),
                           "status": self.status(p)}
                          for p in sorted(self.stubs.get(m, ()))]}
        game = {}
        for name, t in self.titles.items():
            for pair in t["game_side"]:
                game.setdefault(pair, set()).add(name)
        for pair, users in sorted(game.items()):
            report["game_side"].append({"library": pair[0], "nid": pair[1],
                                        "name": self.label(pair),
                                        "status": self.status(pair),
                                        "titles": sorted(users)})
        for name, t in self.titles.items():
            report["titles"][name] = {
                "fakelibs": sorted(t["fakelibs"]), "direct": sorted(t["seed"]),
                "game_side": sorted(f"{p[0]}:{p[1]}" for p in t["game_side"])}
        return report

    def write(self, out_dir):
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        path = out_dir / f"plan-{self.tier.level}.json"
        path.write_text(json.dumps(self.to_json(), indent=1))
        return path
