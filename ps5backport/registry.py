"""The stub registry: every import we are willing to stub and what it returns.

registry/backport-stubs.csv is the only source of stub behaviour, and the
build fails closed: an import missing from the registry, a rejected row, or an
unreviewed row (without --allow-unreviewed) refuses the build. Refusals are
always collected and reported as one full list, never one at a time.
"""
import csv


class RegistryError(Exception):
    """One or more imports the registry refuses to stub."""

    def __init__(self, refusals):
        self.refusals = refusals  # [((library, nid), reason)]
        lines = ["the registry refuses %d import(s):" % len(refusals)]
        for (library, nid), reason in refusals:
            lines.append(f"  {library}:{nid} — {reason}")
        super().__init__("\n".join(lines))


class StubRegistry:
    def __init__(self, path):
        self.path = str(path)
        with open(path, newline="") as fh:
            self.entries = {(row["library"], row["nid"]): row
                            for row in csv.DictReader(fh)}

    def entry(self, pair):
        return self.entries.get(pair)

    def refused(self, pairs, allow_unreviewed=False):
        """[((library, nid), reason)] for every pair the registry refuses."""
        out = []
        for pair in sorted(pairs):
            e = self.entry(pair)
            if e is None:
                out.append((pair, "not in registry"))
            elif e["status"] == "rejected":
                out.append((pair, "rejected"))
            elif e["status"] != "reviewed" and not allow_unreviewed:
                out.append((pair, "unreviewed"))
        return out

    def require(self, pairs, allow_unreviewed=False):
        """Raise RegistryError listing every refused pair, or return None."""
        refusals = self.refused(pairs, allow_unreviewed)
        if refusals:
            raise RegistryError(refusals)

    def code(self, pair, allow_unreviewed=False):
        """The stub's bytes: return0, trap (ud2), or custom hex.

        Retarget rows bind to a real function instead and have no code.
        """
        e = self.entry(pair)
        if (e is None or e["status"] == "rejected"
                or (e["status"] != "reviewed" and not allow_unreviewed)):
            raise RegistryError([(pair, "refused")])
        stub = e["stub"]
        if stub.startswith("retarget:"):
            raise ValueError(f"{pair[0]}:{pair[1]} is a retarget, not stub code")
        if stub == "return0":
            return GADGET
        if stub == "trap":
            return TRAP
        return bytes.fromhex(stub)


GADGET = b"\x31\xc0\xc3"  # xor eax,eax; ret
TRAP = b"\x0f\x0b"        # ud2: proves whether a stub is ever reached
