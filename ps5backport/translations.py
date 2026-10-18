"""Governed translations of an SDK constant the target firmware cannot honour.

Some SDK-defined codes (a channel layout, a flag) are loaded as immediates in
the title's code and passed to an API the older firmware cannot serve. A row of
registry/constant-translations.csv names the constant, its older-firmware
equivalent and an import that marks a module as a user of the API, and the build
rewrites every `mov reg, imm` that loads the constant in those modules. The
constant, not a title or an offset, selects the sites. Same-size edits only.
Columns:
  name         what the constant is
  library, nid the import that gates the rule: modules not importing it are untouched
  constant, replacement   32-bit hex values
  below_sdk    applies to modules whose built PS5 SDK stamp is under this word
  unless_import, unless_since
               library:nid of an import that makes a module exempt, honoured only
               from the firmware where that export exists; both empty for none
  status       reviewed | unreviewed | rejected, gated like the stub registry;
               theoretical rows are kept on file and never applied
  tells_game, prior_art   the effect and the evidence
"""
import csv
import re

from .callsites import version


class TranslationError(Exception):
    """A translation row is malformed or refused."""


class ConstantTranslations:
    def __init__(self, path):
        self.path = str(path)
        self.rules = []
        with open(path, newline="") as fh:
            for row in csv.DictReader(fh):
                self.rules.append(self._validate(row))

    @staticmethod
    def _validate(row):
        key = f"{row['library']}:{row['nid']} {row['constant']}"
        for column in ("constant", "replacement"):
            if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,8}", row[column]):
                raise TranslationError(f"{key}: {column} is not a 32-bit hex value")
        rule = dict(row)
        rule["pair"] = (row["library"], row["nid"])
        if not re.fullmatch(r"0x[0-9a-fA-F]{1,8}", row["below_sdk"]):
            raise TranslationError(f"{key}: below_sdk is not a 32-bit hex word")
        rule["below_sdk"] = int(row["below_sdk"], 16)
        unless = row["unless_import"]
        if bool(unless) != bool(row["unless_since"]):
            raise TranslationError(f"{key}: unless_import and unless_since go together")
        rule["unless"] = tuple(unless.split(":", 1)) if unless else None
        rule["constant"] = int(row["constant"], 16)
        rule["replacement"] = int(row["replacement"], 16)
        rule["key"] = key
        return rule

    def applicable(self, level, sdk, imports):
        return [r for r in self.rules
                if r["status"] != "theoretical"
                and r["pair"] in imports and sdk < r["below_sdk"]
                and not self._exempt(r, level, imports)]
    @staticmethod
    def _exempt(rule, level, imports):
        return (rule["unless"] in imports
                and version(level) >= version(rule["unless_since"]))

    @staticmethod
    def refused(rules, allow_unreviewed=False):
        out = []
        for rule in rules:
            if rule["status"] == "rejected":
                out.append((rule, "rejected"))
            elif rule["status"] != "reviewed" and not allow_unreviewed:
                out.append((rule, "unreviewed"))
        return out
