"""Filesystem locations. Imported first: it points MVT at our own data folder
before any `mvt` module is imported (MVT reads the variable at import time)."""
import json
import os
import shutil
import sys
from pathlib import Path

from . import APP_NAME

FROZEN = getattr(sys, "frozen", False)

# Bundled, read-only resources (assets/, vendor/) next to the code or inside the exe.
RESOURCE_DIR = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent.parent))

LOCAL = Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local")) / APP_NAME
WORK_DIR = LOCAL / "work"              # bugreports / iOS backups while a scan runs
TOOLS_DIR = LOCAL / "platform-tools"   # adb is run from here, not the exe's temp dir
MVT_DATA = LOCAL / "mvt"
SETTINGS_FILE = LOCAL / "settings.json"
REPORTS_DIR = Path.home() / "Documents" / f"{APP_NAME} Reports"

os.environ["MVT_DATA_FOLDER"] = str(MVT_DATA)
os.environ.setdefault("MVT_CONFIG_FOLDER", str(LOCAL / "mvt-config"))

for d in (LOCAL, WORK_DIR, MVT_DATA / "indicators"):
    d.mkdir(parents=True, exist_ok=True)


def resource(*parts: str) -> Path:
    return RESOURCE_DIR.joinpath(*parts)


def adb_path() -> str:
    """Copy the bundled adb to a stable folder. A one-file exe unpacks to a temp
    dir that is deleted on exit, while the adb server keeps running from it."""
    src = resource("vendor", "platform-tools")
    exe = TOOLS_DIR / "adb.exe"
    marker = TOOLS_DIR / ".version"
    stamp = str((src / "adb.exe").stat().st_size) if (src / "adb.exe").exists() else ""
    if src.exists() and (not exe.exists() or not marker.exists() or marker.read_text() != stamp):
        TOOLS_DIR.mkdir(parents=True, exist_ok=True)
        for name in ("adb.exe", "AdbWinApi.dll", "AdbWinUsbApi.dll"):
            try:
                shutil.copy2(src / name, TOOLS_DIR / name)
            except PermissionError:
                pass  # adb server from a previous run holds the file; the old copy works
        marker.write_text(stamp)
    if exe.exists():
        return str(exe)
    found = shutil.which("adb")
    if found:
        return found
    raise FileNotFoundError("adb.exe not found")


def seed_indicators() -> None:
    """Install the indicator snapshot shipped with the app if none are present."""
    dest = MVT_DATA / "indicators"
    if any(dest.glob("*.stix2")):
        return
    for f in resource("assets", "iocs").glob("*.stix2"):
        shutil.copy2(f, dest / f.name)


DEFAULT_SETTINGS = {
    "deep_scan": True,
    "cloud_lookup": True,
    "vt_api_key": "",
    "mb_api_key": "",
    "keep_raw_backup": False,
}


def load_settings() -> dict:
    s = dict(DEFAULT_SETTINGS)
    try:
        s.update(json.loads(SETTINGS_FILE.read_text(encoding="utf-8")))
    except (OSError, ValueError):
        pass
    return s


def save_settings(s: dict) -> None:
    SETTINGS_FILE.write_text(json.dumps(s, indent=2), encoding="utf-8")
