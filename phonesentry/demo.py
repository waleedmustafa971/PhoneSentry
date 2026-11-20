"""Fictional sample scans for documentation, screenshots and the website.

  python -m phonesentry.demo OUT_DIR     # writes sample-threats/ and sample-clean/ reports

Every package name, serial and finding here is made up; reports carry a
"Sample report" banner.
"""
import hashlib
import sys
from pathlib import Path

from . import iocs, report
from .models import CRITICAL, FAIL, HIGH, LOW, MEDIUM, PASS, UNKNOWN, WARN, Check, DeviceInfo, Finding, ScanResult


def _sets():
    try:
        s = iocs.summary()
        return s["sets"], s["total"]
    except Exception:
        return ["Pegasus", "Predator", "Stalkerware"], 11494


def threats_sample() -> ScanResult:
    sets, total = _sets()
    d = DeviceInfo(platform="android", serial="DEMO00000000A1B2", brand="Samsung", manufacturer="samsung",
                   model="Galaxy A-Series (demo)", model_code="SM-DEMO1", os_name="Android", os_version="14",
                   build="DEMO.240501.001", security_patch="2024-03-01",
                   extra={"skin": "One UI 6.1", "storage": "84G used of 128G", "battery": "72%", "hardware": "demo-soc"})
    r = ScanResult(device=d, started="2026-11-20T14:02:11", finished="2026-11-20T14:11:48", deep_scan=True,
                   apps_scanned=96, system_apps=341, ioc_sets=sets, ioc_total=total, sample=True)
    r.findings = [
        Finding(id="app:com.demo.syncservice", title="com.demo.syncservice", severity=CRITICAL, category="stalkerware",
                reasons=['Found a known suspicious app with ID "com.demo.syncservice" matching indicators from "DemoSpy" (sample)',
                         "Has no app icon (hidden from the app drawer)",
                         "Permission: tracks location in the background", "Permission: reads your SMS messages",
                         "Permission: can record audio"],
                target="com.demo.syncservice", target_kind="android-app", removable=True, recommended_removal=True,
                details={"store": "Sideloaded", "version": "4.2", "installed": "2026-10-02 21:14:09",
                         "sha256": hashlib.sha256(b"phonesentry-demo-1").hexdigest()},
                status="removed", status_note="Uninstalled"),
        Finding(id="app:com.android.systemupdate.demo", title="com.android.systemupdate.demo", severity=HIGH,
                category="malware",
                reasons=["Sideloaded: installed by com.android.chrome, not an app store",
                         "Uses a system/Google-style package name but did not come from the vendor or Play Store (impersonation)",
                         "Accessibility service is ON: it can read the screen, see what you type and tap for you",
                         "Can draw over other apps (fake login screens)", "Permission: intercepts incoming SMS (2FA codes)",
                         "Combination typical of banking trojans: accessibility + SMS/notification access"],
                target="com.android.systemupdate.demo", target_kind="android-app", removable=True,
                recommended_removal=True,
                details={"store": "Sideloaded", "version": "1.0", "installed": "2026-11-18 09:40:51",
                         "sha256": hashlib.sha256(b"phonesentry-demo-2").hexdigest(), "risk_score": 19.5},
                status="needs-user-action",
                status_note="It is a device administrator. On the phone open Settings › Security › Device admin apps, "
                            "turn it off, then press Remove again."),
        Finding(id="app:com.demo.freevpn", title="com.demo.freevpn", severity=MEDIUM, category="suspicious-app",
                reasons=["Sideloaded: installed by com.google.android.packageinstaller, not an app store",
                         "Reads all your notifications (messages, codes)", "Permission: starts automatically at boot"],
                target="com.demo.freevpn", target_kind="android-app", removable=True,
                details={"store": "Sideloaded", "version": "2.3.1", "installed": "2026-08-30 17:05:12"}, status="kept"),
        Finding(id="app:com.demo.wallpapers", title="com.demo.wallpapers", severity=LOW, category="suspicious-app",
                reasons=["Sideloaded: installed via adb or an unknown source", "Permission: lists every installed app"],
                target="com.demo.wallpapers", target_kind="android-app", removable=True,
                details={"store": "Sideloaded", "version": "1.8"}),
    ]
    r.checks = [
        Check("Bootloader & verified boot", PASS, "Locked, verified (green)"),
        Check("SELinux", PASS, "Enforcing"), Check("Root access", PASS, "Not rooted"),
        Check("Security patch level", FAIL, "2024-03-01 (994 days old)",
              "Over 6 months without security fixes. Update now; if no update is offered, the phone is out of support."),
        Check("Google Play Protect", FAIL, "Off", "Turn Play Protect on: Play Store › profile › Play Protect."),
        Check("USB debugging", WARN, "On (needed for this scan)",
              "Turn it off after the scan: Settings › Developer options › USB debugging."),
        Check("HTTP proxy", PASS, "None"), Check("Private DNS", WARN, "Off",
                                                 "Turn on Private DNS (e.g. dns.google or one.one.one.one) to encrypt DNS lookups."),
        Check("Apps allowed to install other apps", WARN, "com.android.chrome",
              "Revoke 'Install unknown apps' for apps that don't need it (Settings › Apps › Special access)."),
        Check("Accessibility services on", WARN, "com.android.systemupdate.demo",
              "Accessibility services can read everything on screen. Keep only ones you recognise."),
        Check("Device administrator apps", WARN, "com.android.systemupdate.demo",
              "Review device admin apps (Settings › Security › Device admin apps)."),
    ]
    r.forensic = {"ran": True, "source": "Android bug report", "ioc_hits": [{}], "notable": [],
                  "counts": {"CRITICAL": 1, "HIGH": 0, "MEDIUM": 14, "LOW": 2, "INFORMATIONAL": 0},
                  "notes": [{"level": "MEDIUM", "module": "dumpsys_appops",
                             "message": 'Package "com.android.systemupdate.demo" had SYSTEM_ALERT_WINDOW access (sample)'},
                            {"level": "MEDIUM", "module": "dumpsys_accessibility",
                             "message": 'Found accessibility service "com.android.systemupdate.demo/.A11y" (enabled) (sample)'}],
                  "notes_total": 16}
    r.cloud = {"ran": True, "checked": 4, "hits": 1}
    return r


def clean_sample() -> ScanResult:
    sets, total = _sets()
    d = DeviceInfo(platform="ios", serial="DEMOIPHONE01", brand="Apple", manufacturer="Apple",
                   model="iPhone 15 Pro", model_code="iPhone16,1", os_name="iOS", os_version="26.1",
                   build="DEMO1", extra={"model_number": "MDEMO1LL/A", "storage": "61 GB used of 256 GB",
                                         "battery": "88%", "hardware": "D83AP"})
    r = ScanResult(device=d, started="2026-11-20T15:20:03", finished="2026-11-20T15:47:29", deep_scan=True,
                   apps_scanned=74, system_apps=118, ioc_sets=sets, ioc_total=total, sample=True)
    r.checks = [Check("iOS version", PASS, "26.1 (latest)"), Check("Encrypted backups", PASS, "On"),
                Check("Developer Mode", PASS, "Off"), Check("Jailbreak tools", PASS, "None found"),
                Check("Configuration profiles", PASS, "None"), Check("Apps not from the App Store", PASS, "None"),
                Check("Lockdown Mode", UNKNOWN, "Cannot be read over USB",
                      "If you may be targeted (journalist, activist, official), turn on Lockdown Mode: Settings › Privacy & Security.")]
    r.forensic = {"ran": True, "source": "iPhone backup (encrypted)", "ioc_hits": [], "notable": [],
                  "counts": {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 3, "LOW": 1, "INFORMATIONAL": 0},
                  "notes": [{"level": "MEDIUM", "module": "tcc", "message": "App with microphone access: com.demo.recorder (sample)"}],
                  "notes_total": 4}
    return r


def main(out: str) -> None:
    out_dir = Path(out)
    for name, r in (("sample-threats", threats_sample()), ("sample-clean", clean_sample())):
        print(report.build(r, out_dir / name))


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "samples")
