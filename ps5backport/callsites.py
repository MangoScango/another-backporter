"""Governed call-site rules: patches to how a game reacts to an import's result.

A stub answers for a missing import. A call-site rule covers the opposite
case: the import exists on the target, but rejects arguments the title passes
(a value added by a later firmware), and the title treats the failure as
fatal. The rule names the import, the exact argument that triggers it and the
firmware that first accepts it, and the build rewrites only the branch that
consumes the result. Every edit is the same size as the bytes it replaces.

registry/callsite-rules.csv is the only source of rules and fails closed like
the stub registry: a rejected row, or an unreviewed one without
--allow-unreviewed, refuses the build. Columns:
  library, nid, name   the import
  since                first firmware accepting the argument; the rule applies below it
  status               reviewed | unreviewed | rejected | theoretical (never applied)
  match                <reg>=<imm>, an immediate loaded just before the call
  action               ignore_result
  tells_game           what the title observes afterwards
  prior_art            where else the behaviour was seen
"""
import csv
import re

ACTIONS = ("ignore_result",)
ARG_REGISTERS = ("edi", "esi", "edx", "ecx")


class CallsiteRuleError(Exception):
    """One or more rules the registry refuses, or a site it cannot patch."""


def version(text):
    return tuple(int(part) for part in text.split("."))


class CallsiteRules:
    def __init__(self, path):
        self.path = str(path)
        self.rules = []
        with open(path, newline="") as fh:
            for row in csv.DictReader(fh):
                self.rules.append(self._validate(row))

    def _validate(self, row):
        key = f"{row['library']}:{row['nid']}"
        if row["action"] not in ACTIONS:
            raise CallsiteRuleError(f"{key}: unknown action {row['action']!r}")
        found = re.fullmatch(r"(\w+)=(\d+)", row["match"])
        if not found or found.group(1) not in ARG_REGISTERS:
            raise CallsiteRuleError(f"{key}: match must be <{'|'.join(ARG_REGISTERS)}>=<imm>")
        if not row["since"]:
            raise CallsiteRuleError(f"{key}: a rule needs the firmware that first accepts the argument")
        rule = dict(row)
        rule["pair"] = (row["library"], row["nid"])
        rule["register"] = found.group(1)
        rule["value"] = int(found.group(2))
        return rule

    def applicable(self, level, imports):
        """Rules whose import is in imports and whose argument the level rejects."""
        return [r for r in self.rules
                if r["status"] != "theoretical"
                and r["pair"] in imports and version(level) < version(r["since"])]

    @staticmethod
    def refused(rules, allow_unreviewed=False):
        out = []
        for rule in rules:
            if rule["status"] == "rejected":
                out.append((rule, "rejected"))
            elif rule["status"] != "reviewed" and not allow_unreviewed:
                out.append((rule, "unreviewed"))
        return out
