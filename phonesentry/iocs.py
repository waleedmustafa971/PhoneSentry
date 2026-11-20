"""Threat-indicator database: MVT's STIX2 feeds (Pegasus, Predator, stalkerware, ...)."""
import logging
import time
from datetime import datetime
from typing import Optional

from . import paths  # noqa: F401  (sets MVT_DATA_FOLDER before mvt imports)
from mvt.common.indicators import Indicators

log = logging.getLogger("phonesentry.iocs")

# Feed names that mean "mercenary / state-grade spyware" rather than commodity malware.
MERCENARY = ("pegasus", "predator", "candiru", "quadream", "kingspawn", "rcs", "triangulation",
             "helios", "novispy", "cellebrite", "coruna", "darksword", "morpheus", "spyrtacus",
             "residentbat", "wyrmspy", "dragonegg", "eaglemsgspy", "intellexa", "nso")

_cache: Optional[Indicators] = None


def load(force: bool = False) -> Indicators:
    global _cache
    if _cache is None or force:
        paths.seed_indicators()
        iocs = Indicators(log)
        iocs.load_indicators_files([], load_default=True)
        _cache = iocs
    return _cache


def summary() -> dict:
    iocs = load()
    folder = paths.MVT_DATA / "indicators"
    files = list(folder.glob("*.stix2"))
    newest = max((f.stat().st_mtime for f in files), default=0)
    return {
        "sets": [c.get("name") or c.get("stix2_file_name") for c in iocs.ioc_collections],
        "set_count": len({c.get("stix2_file_name") for c in iocs.ioc_collections}),
        "total": iocs.total_ioc_count,
        "updated": datetime.fromtimestamp(newest).strftime("%Y-%m-%d") if newest else "never",
    }


def update() -> dict:
    """Download the latest feeds from the MVT indicator index."""
    from mvt.common.updates import IndicatorsUpdates
    before = time.time()
    IndicatorsUpdates().update()
    folder = paths.MVT_DATA / "indicators"
    fresh = [f for f in folder.glob("*.stix2") if f.stat().st_mtime >= before - 1]
    if not fresh:
        raise RuntimeError("Could not download indicator updates (offline?)")
    load(force=True)
    return summary()


def classify(collection_name: str) -> str:
    n = (collection_name or "").lower()
    if "stalkerware" in n:
        return "stalkerware"
    if any(k in n for k in MERCENARY):
        return "spyware"
    return "malware"
