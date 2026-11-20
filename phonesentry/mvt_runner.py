"""Runs MVT forensic commands in-process and condenses their alerts."""
import logging
import re

from . import iocs as ioc_db
from .models import CRITICAL, HIGH, Finding

_NOISE = re.compile(r"Running module|Loaded a total|produced no detections|does not support checking", re.I)


class _Forward(logging.Handler):
    def __init__(self, progress):
        super().__init__(logging.INFO)
        self.progress = progress

    def emit(self, record):
        try:
            msg = record.getMessage()
        except Exception:
            return
        if record.levelno >= logging.WARNING or not _NOISE.search(msg):
            self.progress.log("  " + msg.splitlines()[0][:220])


def run(cmd_cls, target: str, out_dir: str, progress, module_options=None) -> dict:
    indicators = ioc_db.load()
    lg = logging.getLogger("mvt")
    lg.setLevel(logging.INFO)
    lg.propagate = False
    fwd = _Forward(progress)
    lg.addHandler(fwd)
    try:
        cmd = cmd_cls(target_path=target, results_path=out_dir, iocs=indicators,
                      module_options=module_options or {}, disable_version_check=True,
                      disable_indicator_check=True)
        cmd.run()
    finally:
        lg.removeHandler(fwd)
        for h in list(lg.handlers):           # release command.log
            if isinstance(h, logging.FileHandler):
                h.close()
                lg.removeHandler(h)
    return summarise(cmd.alertstore.as_json(), out_dir)


def summarise(alerts: list, out_dir: str) -> dict:
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0}
    ioc_hits, notable, notes = [], [], []
    for a in alerts:
        lvl = a.get("level", "INFORMATIONAL")
        counts[lvl] = counts.get(lvl, 0) + 1
        item = {"level": lvl, "module": a.get("module", ""), "message": a.get("message", ""),
                "time": a.get("event_time", ""), "indicator": a.get("matched_indicator")}
        if item["indicator"]:
            ioc_hits.append(item)
        elif lvl in ("CRITICAL", "HIGH"):
            notable.append(item)
        else:
            notes.append(item)
    return {"ran": True, "counts": counts, "ioc_hits": ioc_hits, "notable": notable,
            "notes": notes[:150], "notes_total": len(notes), "output_dir": out_dir}


def findings_from(summary: dict) -> list:
    out = []
    for i, hit in enumerate(summary.get("ioc_hits", [])):
        ind = hit["indicator"] or {}
        name = ind.get("name") or ind.get("stix2_file_name") or "indicator"
        cat = ioc_db.classify(f'{name} {ind.get("stix2_file_name", "")}')
        out.append(Finding(
            id=f"forensic-ioc:{i}", title=f"Forensic trace matches {name}",
            severity=CRITICAL, category=cat,
            reasons=[hit["message"], f'Indicator: {ind.get("value", "")} ({ind.get("type", "")})',
                     f'Found by MVT module "{hit["module"]}"' + (f' at {hit["time"]}' if hit["time"] else "")],
            details={"indicator": ind}))
    for i, hit in enumerate(summary.get("notable", [])):
        out.append(Finding(
            id=f"forensic:{i}", title=hit["message"][:120], severity=HIGH, category="forensic",
            reasons=[hit["message"], f'MVT module "{hit["module"]}"']))
    return out
