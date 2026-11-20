"""Command-line mode (also used for testing without the GUI).

  PhoneSentry.exe --list
  PhoneSentry.exe --scan [--deep] [--serial X]
  PhoneSentry.exe --analyze-bugreport bugreport.zip
  PhoneSentry.exe --update-iocs
"""
import argparse
import shutil
import sys
from datetime import datetime
from pathlib import Path

from . import paths  # noqa: F401
from .models import DeviceInfo, Progress, ScanResult


def _progress():
    return Progress(log=lambda m: print(m, flush=True), step=lambda s: print(f"\n== {s}", flush=True))


def cleanup_raw(r: ScanResult, keep: bool):
    raw = r.forensic.get("raw_input")
    if raw and not keep:
        p = Path(raw)
        target = p.parent if p.is_file() else p
        if paths.WORK_DIR in target.parents:
            shutil.rmtree(target, ignore_errors=True)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="PhoneSentry")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--scan", action="store_true")
    ap.add_argument("--deep", action="store_true")
    ap.add_argument("--serial", default="")
    ap.add_argument("--analyze-bugreport", metavar="ZIP")
    ap.add_argument("--update-iocs", action="store_true")
    ap.add_argument("--out", metavar="DIR")
    a = ap.parse_args(argv)
    from . import iocs, report
    settings = paths.load_settings()

    if a.update_iocs:
        print(iocs.update())
        return 0
    if a.list:
        from .android_scan import Adb
        from .ios_scan import list_devices
        print("Android:", Adb().devices())
        print("iOS:", list_devices())
        return 0
    if a.analyze_bugreport:
        from mvt.android.cmd_check_bugreport import CmdAndroidCheckBugreport
        from . import mvt_runner
        p = _progress()
        s = iocs.summary()
        r = ScanResult(device=DeviceInfo(platform="android", model="Bug report file"),
                       started=datetime.now().isoformat(timespec="seconds"), deep_scan=True,
                       ioc_sets=s["sets"], ioc_total=s["total"])
        out = paths.WORK_DIR / "cli-bugreport"
        shutil.rmtree(out, ignore_errors=True)
        r.forensic = mvt_runner.run(CmdAndroidCheckBugreport, a.analyze_bugreport, str(out), p)
        r.forensic["source"] = "Android bug report file"
        r.findings = mvt_runner.findings_from(r.forensic)
        r.finished = datetime.now().isoformat(timespec="seconds")
        print("Report:", report.build(r, Path(a.out) if a.out else None))
        return 0
    if a.scan:
        from .android_scan import Adb, AndroidScanner
        from .ios_scan import IOSScanner, list_devices
        p = _progress()
        serial = a.serial
        android = [d["serial"] for d in Adb().devices() if d["state"] == "device"]
        _, ios = list_devices()
        if serial and serial in ios or (not serial and not android and ios):
            sc = IOSScanner(serial or ios[0], settings, p)
        elif android:
            sc = AndroidScanner(serial or android[0], settings, p)
        else:
            print("No authorised device connected.")
            return 2
        r = sc.scan(a.deep)
        path = report.build(r, Path(a.out) if a.out else None)
        cleanup_raw(r, settings.get("keep_raw_backup", False))
        for f in r.findings:
            print(f"[{f.severity.upper():8}] {f.title}: {f.reasons[0] if f.reasons else ''}")
        print("Report:", path)
        return 0
    ap.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
