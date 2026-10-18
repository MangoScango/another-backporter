"""Governed byte patches to fakelibs built from a newer firmware.

A fakelib is a newer firmware's module running on an older kernel. Where the
two disagree on an interface the module calls into (an ioctl request number,
a struct size), the module needs the older value. Each row of
registry/fakelib-patches.csv replaces an exact byte string inside the module's
executable segments, expects an exact number of hits and fails the build on any
other count. Same-length replacements only, so the module keeps its shape.
Columns:
  id          short unique name of the row, used to ask for it
  apply       auto: applied whenever its module is shipped and the tier matches
              named: applied only when asked for by id (--apply ID); asking for
              a row whose module the title does not ship is an error, and a
              named row never causes a fakelib to be shipped
  watch       library:nid; for a named row, a build that does not apply it warns
              when a game module imports this (empty for none)
  module      fakelib file name, e.g. libSceAcm.sprx
  find, replace   hex bytes of equal length
  expect      how many times find must occur
  below       the patch applies to tiers whose level is under this firmware
  status      reviewed | unreviewed | rejected, gated like the stub registry;
              theoretical rows are kept on file and never applied
  name, tells_game, prior_art   what the bytes are, the effect, the evidence
"""
import csv
import re

from .callsites import version


class FakelibPatchError(Exception):
    """A patch row is malformed, refused, or does not match its module."""


class FakelibPatches:
    def __init__(self, path):
        self.path = str(path)
        self.rules = []
        with open(path, newline="") as fh:
            for row in csv.DictReader(fh):
                self.rules.append(self._validate(row))
        ids = [r["id"] for r in self.rules]
        if len(set(ids)) != len(ids):
            raise FakelibPatchError(f"{path}: duplicate ids")

    @staticmethod
    def _validate(row):
        key = f"{row['module']} {row['find']}"
        for column in ("find", "replace"):
            if not re.fullmatch(r"(?:[0-9a-fA-F]{2})+", row[column]):
                raise FakelibPatchError(f"{key}: {column} is not hex")
        if len(row["find"]) != len(row["replace"]):
            raise FakelibPatchError(f"{key}: find and replace differ in length")
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", row["id"]):
            raise FakelibPatchError(f"{key}: id must be lowercase letters, digits and dashes")
        if row["apply"] not in ("auto", "named"):
            raise FakelibPatchError(f"{key}: apply must be auto or named")
        if row["watch"] and not re.fullmatch(r"[^:\s]+:\S+", row["watch"]):
            raise FakelibPatchError(f"{key}: watch must be library:nid")
        rule = dict(row)
        rule["watch"] = tuple(row["watch"].split(":", 1)) if row["watch"] else None
        rule["find"] = bytes.fromhex(row["find"])
        rule["replace"] = bytes.fromhex(row["replace"])
        rule["expect"] = int(row["expect"])
        rule["key"] = key
        return rule

    def applicable(self, level, module, requested=()):
        return [r for r in self.rules
                if r["status"] != "theoretical"
                and r["module"] == module and version(level) < version(r["below"])
                and (r["apply"] == "auto" or r["id"] in requested)]
    def named(self, level):
        """Named rows that would apply at this level, whether or not asked for."""
        return [r for r in self.rules
                if r["status"] != "theoretical" and r["apply"] == "named"
                and version(level) < version(r["below"])]
    def problems(self, level, requested, shipped):
        """Why each requested id cannot be applied, for ids that cannot."""
        by_id = {r["id"]: r for r in self.rules}
        out = []
        for ident in sorted(requested):
            rule = by_id.get(ident)
            if rule is None:
                out.append(f"  {ident}: no such patch")
            elif rule["status"] == "theoretical":
                out.append(f"  {ident}: theoretical rows are never applied")
            elif version(level) >= version(rule["below"]):
                out.append(f"  {ident}: does not apply at {level} (below {rule['below']} only)")
            elif rule["module"] not in shipped:
                out.append(f"  {ident}: {rule['module']} is not a fakelib for this title, "
                           f"and patches never pull one in")
        return out

    @staticmethod
    def refused(rules, allow_unreviewed=False):
        out = []
        for rule in rules:
            if rule["status"] == "rejected":
                out.append((rule, "rejected"))
            elif rule["status"] != "reviewed" and not allow_unreviewed:
                out.append((rule, "unreviewed"))
        return out
