"""The governed rule files a build consults, loaded together."""
from dataclasses import dataclass
from pathlib import Path

from .callsites import CallsiteRules
from .fakelib_patches import FakelibPatches
from .translations import ConstantTranslations


@dataclass
class RuleSet:
    callsites: CallsiteRules = None
    fakelib_patches: FakelibPatches = None
    translations: ConstantTranslations = None

    @staticmethod
    def load(cfg):
        """Each rule file that exists; a missing file is simply no rules."""
        def read(path, cls):
            return cls(path) if path and Path(path).exists() else None
        return RuleSet(read(cfg.callsites, CallsiteRules),
                       read(cfg.fakelib_patches, FakelibPatches),
                       read(cfg.translations, ConstantTranslations))
