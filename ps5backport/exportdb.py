"""The firmware export database: which (library, NID) each firmware exports,
and which system module carries a library.

The CSVs under fwdb/ cover system/common/lib only, so priv/lib exports are
scanned from the firmware dumps themselves and cached next to the ELF cache.
"""
import csv
import pickle
from pathlib import Path

from . import elf


def fw_key(name):
    return tuple(int(part) for part in name.split('.'))


class ExportDB:
    """levels is oldest-first; ranges maps (library, nid) to (min_fw, max_fw),
    the oldest and newest firmware seen exporting it. holes lists firmware
    inside that span that do not export it."""

    def __init__(self, fwdb_dir):
        fwdb_dir = Path(fwdb_dir)
        self.levels, self.stamps = [], {}
        with open(fwdb_dir / 'fw-levels.csv') as fh:
            for row in csv.DictReader(fh):
                self.levels.append(row['ps5_system_software'])
                self.stamps[row['ps5_system_software']] = int(row['ps4_stamp'], 16)

        self.ranges, self.names = {}, {}
        with open(fwdb_dir / 'fw-exports.csv') as fh:
            for row in csv.DictReader(fh):
                key = (row['library'], row['nid'])
                self.ranges[key] = (row['min_fw'], row['max_fw'])
                if row['name']:
                    self.names[key] = row['name']

        self.holes = {}
        gaps = fwdb_dir / 'fw-export-gaps.csv'
        if gaps.exists():
            with open(gaps) as fh:
                for row in csv.DictReader(fh):
                    self.holes[(row['library'], row['nid'])] = row['missing_fw'].split(';')

        # {library: [(sprx filename, min_fw, max_fw)]}
        self.module_table = {}
        with open(fwdb_dir / 'fw-modules.csv') as fh:
            for row in csv.DictReader(fh):
                self.module_table.setdefault(row['library'], []).append(
                    (row['module'], row['min_fw'], row['max_fw']))

        self.rank = {name: i for i, name in enumerate(self.levels)}
        self._priv = None

    def load_priv(self, libs_dir, cache_path):
        """priv/lib exports per level, scanned from the dumps (cached)."""
        cache_path = Path(cache_path)
        if cache_path.exists():
            self._priv = pickle.loads(cache_path.read_bytes())
            return
        out = {}
        for level in self.levels:
            pairs = set()
            for path in Path(libs_dir).glob(f"{level}/**/priv/lib/*.sprx"):
                module = elf.read(path)
                if module:
                    pairs |= module.export_pairs()
            out[level] = pairs
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(pickle.dumps(out))
        self._priv = out

    def exported_at(self, pair, level):
        """True when firmware level exports (library, nid)."""
        if self._priv is not None and pair in self._priv.get(level, ()):
            return True
        span = self.ranges.get(pair)
        if not span:
            return False
        at = self.rank[level]
        return (self.rank[span[0]] <= at <= self.rank[span[1]]
                and level not in self.holes.get(pair, ()))

    def carrier(self, library, target):
        """-> (sprx filename a library at target comes from, alternatives)."""
        rows = self.module_table.get(library)
        if not rows:
            return None, []
        at = self.rank[target]
        found = [r for r in rows if self.rank[r[1]] <= at <= self.rank[r[2]]]
        if not found:
            later = [r for r in rows if self.rank[r[1]] > at]
            if later:
                first = min(self.rank[r[1]] for r in later)
                found = [r for r in later if self.rank[r[1]] == first]
            else:
                last = max(self.rank[r[2]] for r in rows)
                found = [r for r in rows if self.rank[r[2]] == last]
        files = sorted({r[0] for r in found})
        exact = [f for f in files
                 if _module_key(f.rsplit('.', 1)[0]) == _module_key(library)]
        primary = exact[0] if exact else min(files, key=lambda f: (len(f), f))
        return primary, [f for f in files if f != primary]


def _module_key(name):
    return name.lower().replace('.', '_')
