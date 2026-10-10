"""Paths and per-tier constants for the backport build.

Every path defaults into this repo (the data/ symlinks resolve to the large
inputs) and can be overridden with an environment variable or a Config()
argument. Nothing here hard-codes a machine-specific absolute path.
"""
import os
from dataclasses import dataclass, field
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

NOT_FAKELIBBABLE = frozenset({
    "libkernel.sprx", "libkernel_sys.sprx", "libkernel_web.sprx",
    "libSceLibcInternal.sprx", "libSceSysmodule.sprx", "libSceAmpr.sprx",
})

SOURCE_FW = "13.60"
# Source firmware per module when SOURCE_FW misbehaves on the target.
# libSceVideoOut comes from 10.01: the 13.60 build broke VRR on 7.61
# (Cyberpunk tests). Keep the reason with the override.
SOURCE_OVERRIDE = {"libSceVideoOut.sprx": "10.01"}

# libkernel's table of modules a game supplies from /app0/sce_module rather
# than the firmware, each with the first PS5 firmware whose libkernel lists it.
APP_SUPPLIED_MODULES = {
    'libSceFios2': '1.00',
    'libc': '1.00',
    'libSceFace': '1.00',
    'libSceHand': '1.00',
    'libSceSmart': '1.00',
    'libSceS3DConversion': '1.00',
    'libSceHeadTracker': '1.00',
    'libSceFaceTracker': '1.00',
    'libSceHandTracker': '1.00',
    'libSceAudioLatencyEstimation': '1.00',
    'libSceNpToolkit': '1.00',
    'libSceJobManager': '1.00',
    'libSceNpToolkit2': '1.00',
    'libSceNpCppWebApi': '1.00',
    'libScePfs': '1.00',
    'libSceFontGsm': '6.00',
}


@dataclass(frozen=True)
class Tier:
    """One backport tier: the level imports resolve against and the
    param-segment stamp pair written into every built file."""
    name: str
    level: str          # firmware level imports resolve against
    stamp_ps5: int      # module param word at +0x14
    stamp_ps4: int      # module param word at +0x10


TIERS = {
    # 7.xx: built and boot-tested. For consoles on 7.00 and later.
    "7xx": Tier("7xx", "7.01", 0x07000038, 0x10590001),
    # 4.xx: designed, not built. Needs registry review first.
    "4xx": Tier("4xx", "4.00", 0x04000031, 0x09040001),
}


def _env_path(env, default):
    value = os.environ.get(env)
    return Path(value) if value else default


@dataclass
class Config:
    """Everything the pipeline needs to find on disk."""
    libs: Path        # firmware dumps: <libs>/<fw>/system/{common,priv}/lib
    cache: Path       # acquired title executables and the full file lists
    elf_cache: Path   # unwrapped Sony ELFs, keyed by title and relative path
    fwdb: Path        # fw-levels/fw-exports/fw-modules CSVs
    registry: Path    # backport-stubs.csv
    make_fself: Path  # fake-signs every written file
    pub_cmd: Path = None  # prospero-pub-cmd.exe (via wine), needed only for pkg input
    passcode: str = "0" * 32
    source_fw: str = SOURCE_FW
    source_override: dict = field(default_factory=lambda: dict(SOURCE_OVERRIDE))

    @staticmethod
    def default():
        data = REPO_ROOT / "data"
        return Config(
            libs=_env_path("PS5BACKPORT_LIBS", data / "PS5_Libs"),
            cache=_env_path("PS5BACKPORT_CACHE", data / "binaries"),
            elf_cache=_env_path("PS5BACKPORT_ELF_CACHE", data / "binaries-elf"),
            fwdb=_env_path("PS5BACKPORT_FWDB", REPO_ROOT / "fwdb"),
            registry=_env_path("PS5BACKPORT_REGISTRY",
                               REPO_ROOT / "registry" / "backport-stubs.csv"),
            make_fself=_env_path("PS5BACKPORT_MAKE_FSELF",
                                 REPO_ROOT / "reference" / "legacy" / "make_fself.py"),
            pub_cmd=_env_path("PS5BACKPORT_PUB_CMD", None),
        )

    def system_module(self, name, fw=None):
        """Path of a system module at the given (or source) firmware.

        Newer dumps keep modules under system/common/lib; the oldest dumps
        have a flat lib/ instead."""
        base = self.libs / (fw or self.source_fw)
        new = base / "system/common/lib" / name
        return new if new.exists() else base / "lib" / name
