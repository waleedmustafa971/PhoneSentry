"""Android scanning over adb: device facts, posture, apps, indicators,
behavioural analysis, optional cloud reputation and an MVT bugreport scan."""
import os
import re
import shutil
import subprocess
from datetime import date, datetime
from pathlib import Path

from . import heuristics as H
from . import iocs as ioc_db
from . import paths
from .models import (CRITICAL, FAIL, HIGH, INFO, LOW, MEDIUM, PASS, UNKNOWN, WARN, Check,
                     DeviceInfo, Finding, ScanResult)

NO_WINDOW = 0x08000000 if os.name == "nt" else 0


class AdbError(RuntimeError):
    pass


class Adb:
    def __init__(self, serial: str = ""):
        self.exe = paths.adb_path()
        self.serial = serial

    def run(self, *args, timeout=90, check=False) -> str:
        cmd = [self.exe] + (["-s", self.serial] if self.serial else []) + list(args)
        try:
            p = subprocess.run(cmd, capture_output=True, timeout=timeout, creationflags=NO_WINDOW)
        except subprocess.TimeoutExpired:
            raise AdbError(f"adb timed out: {' '.join(args)[:80]}")
        out = p.stdout.decode("utf-8", "replace")
        if check and p.returncode != 0:
            raise AdbError((p.stderr.decode("utf-8", "replace") or out).strip())
        return out

    def sh(self, command: str, timeout=90) -> str:
        return self.run("shell", command, timeout=timeout).replace("\r\n", "\n").strip()

    def devices(self) -> list[dict]:
        out = self.run("devices", "-l", timeout=20)
        devs = []
        for line in out.splitlines()[1:]:
            parts = line.split()
            if len(parts) < 2:
                continue
            d = {"serial": parts[0], "state": parts[1]}
            for p in parts[2:]:
                if ":" in p:
                    k, v = p.split(":", 1)
                    d[k] = v
            devs.append(d)
        return devs

    def kill_server(self):
        try:
            subprocess.run([self.exe, "kill-server"], capture_output=True, timeout=10,
                           creationflags=NO_WINDOW)
        except Exception:
            pass


def parse_getprop(text: str) -> dict:
    return dict(re.findall(r"^\[([^\]]+)\]: \[(.*)\]$", text, re.M))


def device_info(adb: Adb, props: dict | None = None) -> DeviceInfo:
    p = props if props is not None else parse_getprop(adb.sh("getprop"))
    g = lambda *keys: next((p[k] for k in keys if p.get(k)), "")  # noqa: E731
    brand = g("ro.product.brand", "ro.product.vendor.brand", "ro.product.system.brand")
    market = g("ro.product.marketname", "ro.product.vendor.marketname", "ro.product.odm.marketname",
               "ro.config.marketing_name", "ro.vendor.oplus.market.name", "ro.vivo.market.name")
    skin = ""
    if g("ro.mi.os.version.name"):
        skin = f'HyperOS {g("ro.mi.os.version.incremental", "ro.mi.os.version.name")}'
    elif g("ro.miui.ui.version.name"):
        skin = f'MIUI {g("ro.miui.ui.version.name")}'
    elif g("ro.build.version.oneui"):
        v = g("ro.build.version.oneui")
        skin = f"One UI {int(v) // 10000}.{int(v) // 100 % 100}" if v.isdigit() else f"One UI {v}"
    elif g("ro.build.version.emui"):
        skin = g("ro.build.version.emui")
    elif g("ro.build.version.opporom"):
        skin = f'ColorOS {g("ro.build.version.opporom")}'
    info = DeviceInfo(
        platform="android", serial=adb.serial or g("ro.serialno"),
        brand=brand.title() if brand.islower() else brand,
        manufacturer=g("ro.product.manufacturer"), model=market,
        model_code=g("ro.product.model", "ro.product.vendor.model"),
        os_name="Android", os_version=g("ro.build.version.release"),
        build=g("ro.build.display.id"), security_patch=g("ro.build.version.security_patch"),
        extra={"skin": skin, "sdk": g("ro.build.version.sdk"), "device": g("ro.product.device"),
               "fingerprint": g("ro.build.fingerprint"), "hardware": g("ro.hardware", "ro.board.platform")})
    if not info.model:
        name = adb.sh("settings get global device_name")
        info.model = name if name and name != "null" else info.model_code
    return info


def _set(value: str) -> set:
    if not value or value == "null":
        return set()
    return {c.split("/")[0] for c in value.split(":") if c}


def parse_package_dump(dump: str) -> dict:
    pkgs, cur, section, sec_indent = {}, None, None, 0
    for line in dump.splitlines():
        m = re.match(r"^  Package \[([^\]]+)\] \(", line)
        if m:
            cur = pkgs.setdefault(m.group(1), {"requested": set(), "granted": set()})
            section = None
            continue
        if cur is None:
            continue
        if line and not line.startswith(" "):
            cur, section = None, None
            continue
        stripped = line.strip()
        indent = len(line) - len(line.lstrip())
        if stripped in ("requested permissions:", "install permissions:", "runtime permissions:"):
            section, sec_indent = stripped, indent
            continue
        if section and indent <= sec_indent:
            section = None
        g = re.match(r"([A-Za-z0-9_.]+): granted=(true|false)", stripped)
        if g:
            if g.group(2) == "true":
                cur["granted"].add(g.group(1))
            continue
        if section == "requested permissions:":
            cur["requested"].add(stripped.split(":")[0])
            continue
        for key in ("versionName", "firstInstallTime", "lastUpdateTime", "installerPackageName"):
            if stripped.startswith(key + "="):
                val = stripped.split("=", 1)[1].strip()
                # Keep the package-level value; per-user lines can be epoch 0.
                if val and not val.startswith("1970-01-01") and not cur.get(key):
                    cur[key] = val
    return pkgs


def _patch_age_days(patch: str):
    try:
        return (date.today() - datetime.strptime(patch, "%Y-%m-%d").date()).days
    except ValueError:
        return None


class AndroidScanner:
    def __init__(self, serial: str, settings: dict, progress):
        self.adb = Adb(serial)
        self.settings, self.p = settings, progress

    # ------------------------------------------------------------------ scan
    def scan(self, deep: bool) -> ScanResult:
        p = self.p
        p.step("Reading device information")
        props = parse_getprop(self.adb.sh("getprop"))
        if not props:
            raise AdbError("The phone did not answer. Unlock it and allow USB debugging, then retry.")
        info = device_info(self.adb, props)
        r = ScanResult(device=info, started=datetime.now().isoformat(timespec="seconds"), deep_scan=deep)
        self._extra_facts(info)
        p.log(f"Device: {info.display} - Android {info.os_version}, patch {info.security_patch}")
        p.pct(5)

        p.step("Loading threat database")
        indicators = ioc_db.load()
        s = ioc_db.summary()
        r.ioc_sets, r.ioc_total = s["sets"], s["total"]
        p.log(f"{s['total']:,} indicators from {s['set_count']} threat feeds")
        p.pct(8)

        p.step("Inspecting installed apps")
        apps, ctx = self._collect_apps()
        third = {k: v for k, v in apps.items() if v["third_party"]}
        r.apps_scanned, r.system_apps = len(third), len(apps) - len(third)
        p.log(f"{len(third)} user-installed apps, {r.system_apps} system apps")
        p.pct(25)

        p.step("Security checks")
        r.checks = self._posture(props, apps, ctx)
        p.pct(30)

        p.step("Matching against spyware & stalkerware indicators")
        r.findings.extend(self._ioc_checks(indicators, apps, props))
        p.pct(40)

        p.step("Behavioural malware analysis")
        flagged = {f.target for f in r.findings}
        for pkg, app in sorted(third.items()):
            if pkg in flagged:
                continue
            score, why = H.score_app(app, ctx)
            sev = H.severity_for(score)
            if sev:
                r.findings.append(Finding(
                    id=f"app:{pkg}", title=pkg, severity=sev,
                    category="malware" if sev == HIGH else "suspicious-app",
                    reasons=why, target=pkg, target_kind="android-app", removable=True,
                    recommended_removal=sev == HIGH,
                    details=self._app_details(app, score)))
        p.log(f"{sum(1 for f in r.findings if f.category in ('malware', 'suspicious-app'))} apps flagged by behaviour")
        p.pct(50)

        if self.settings.get("cloud_lookup", True):
            self._cloud(r, third)
        p.pct(60)

        if deep:
            self._deep(r)
        p.pct(98)
        r.findings.sort(key=lambda f: -{"critical": 4, "high": 3, "medium": 2, "low": 1}.get(f.severity, 0))
        r.finished = datetime.now().isoformat(timespec="seconds")
        return r

    def _extra_facts(self, info: DeviceInfo):
        try:
            df = self.adb.sh("df -h /data").splitlines()[-1].split()
            info.extra["storage"] = f"{df[2]} used of {df[1]}"
        except (IndexError, AdbError):
            pass
        bat = self.adb.sh("dumpsys battery")
        m = re.search(r"level: (\d+)", bat)
        if m:
            info.extra["battery"] = f"{m.group(1)}%"

    def _collect_apps(self):
        sh = self.adb.sh
        apps = {}
        listing = sh("pm list packages -f -i -U --user 0", timeout=120)
        if "Unknown option" in listing or not listing.startswith("package:"):
            listing = sh("pm list packages -f -i", timeout=120)
        for line in listing.splitlines():
            toks = line.split()
            if not toks or not toks[0].startswith("package:"):
                continue
            path, _, pkg = toks[0][len("package:"):].rpartition("=")
            a = {"package": pkg, "path": path, "installer": "null", "uid": ""}
            for t in toks[1:]:
                if t.startswith("installer="):
                    a["installer"] = t.split("=", 1)[1]
                elif t.startswith("uid:"):
                    a["uid"] = t[4:]
            apps[pkg] = a
        third = set(re.findall(r"^package:(\S+)", sh("pm list packages -3"), re.M))
        disabled = set(re.findall(r"^package:(\S+)", sh("pm list packages -d"), re.M))
        launch = sh("cmd package query-activities --brief -a android.intent.action.MAIN "
                    "-c android.intent.category.LAUNCHER", timeout=60)
        launchers = set(re.findall(r"^\s*([A-Za-z0-9_.]+)/", launch, re.M))
        dump = parse_package_dump(sh("dumpsys package packages", timeout=180))
        for pkg, a in apps.items():
            a["third_party"] = pkg in third
            a["disabled"] = pkg in disabled
            a["launcher"] = (pkg in launchers) if launchers else True
            d = dump.get(pkg, {})
            a["granted"], a["requested"] = d.get("granted", set()), d.get("requested", set())
            for k in ("versionName", "firstInstallTime", "lastUpdateTime"):
                a[k] = d.get(k, "")
            if a["installer"] == "null" and d.get("installerPackageName") not in (None, "null"):
                a["installer"] = d["installerPackageName"]

        def op(name):
            out = sh(f"appops query-op {name} allow")
            return set() if "No operations" in out else set(re.findall(r"^\s*([A-Za-z0-9_.]+)\s*$", out, re.M))

        ctx = {
            "accessibility": _set(sh("settings get secure enabled_accessibility_services")),
            "listeners": _set(sh("settings get secure enabled_notification_listeners")),
            "admins": set(re.findall(r"ComponentInfo\{([A-Za-z0-9_.]+)/", sh("dumpsys device_policy"))),
            "overlay": op("SYSTEM_ALERT_WINDOW"),
            "installers": op("REQUEST_INSTALL_PACKAGES"),
            "sms_default": sh("settings get secure sms_default_application"),
        }
        # Hash user-installed APKs on the phone itself (nothing is copied off it).
        paths_ = [(pkg, a["path"]) for pkg, a in apps.items() if a["third_party"] and a["path"]]
        for i in range(0, len(paths_), 25):
            chunk = paths_[i:i + 25]
            out = sh("sha256sum " + " ".join(f"'{pth}'" for _, pth in chunk), timeout=180)
            hashes = {m.group(2): m.group(1) for m in re.finditer(r"^([0-9a-f]{64})\s+(\S+)", out, re.M)}
            for pkg, pth in chunk:
                apps[pkg]["sha256"] = hashes.get(pth, "")
            self.p.log(f"  hashed {min(i + 25, len(paths_))}/{len(paths_)} apps")
        return apps, ctx

    def _app_details(self, app, score=None):
        d = {"package": app["package"], "installer": app.get("installer"),
             "store": H.source_label(app),
             "version": app.get("versionName", ""), "installed": app.get("firstInstallTime", ""),
             "sha256": app.get("sha256", ""), "path": app.get("path", "")}
        if score is not None:
            d["risk_score"] = round(score, 1)
        return d

    def _ioc_checks(self, indicators, apps, props):
        out = []
        for pkg, app in apps.items():
            m = indicators.check_app_id(pkg)
            how = "package name"
            if not m and app.get("sha256"):
                m = indicators.check_file_hash(app["sha256"])
                how = "APK hash"
            if m:
                cat = ioc_db.classify(f"{m.ioc.name} {m.ioc.stix2_file_name}")
                out.append(Finding(
                    id=f"app:{pkg}", title=pkg, severity=CRITICAL, category=cat,
                    reasons=[m.message, f"Matched by {how} against \"{m.ioc.name}\""],
                    target=pkg, target_kind="android-app", removable=True,
                    recommended_removal=True, details={**self._app_details(app), "indicator": m.ioc.value}))
        # Only app-sandbox processes (u0_a123, u0_i45). Spyware process-name indicators
        # are mostly iOS names, several of which (e.g. gatekeeperd) are genuine Android
        # system daemons; system daemons are covered by the deep (MVT) scan instead.
        procs = set()
        for ln in self.adb.sh("ps -A -o USER,NAME", timeout=60).splitlines()[1:]:
            parts = ln.split()
            if len(parts) >= 2 and re.match(r"u\d+_[ai]\d+$", parts[0]):
                procs.add(parts[-1])
        for name in sorted(procs):
            m = indicators.check_process(name)
            if m:
                out.append(Finding(
                    id=f"proc:{name}", title=f"Running process \"{name}\"", severity=CRITICAL,
                    category=ioc_db.classify(m.ioc.name), reasons=[m.message],
                    details={"indicator": m.ioc.value}))
        for key in props:
            m = indicators.check_android_property_name(key)
            if m:
                out.append(Finding(
                    id=f"prop:{key}", title=f"System property \"{key}\"", severity=CRITICAL,
                    category=ioc_db.classify(m.ioc.name), reasons=[m.message]))
        self.p.log(f"Indicator matches: {len(out)}")
        return out

    def _posture(self, props, apps, ctx):
        sh, c = self.adb.sh, []
        g = props.get
        vb = g("ro.boot.verifiedbootstate", "")
        locked = g("ro.boot.flash.locked", "") == "1" or g("ro.boot.vbmeta.device_state", "") == "locked"
        if vb == "green" and (locked or not g("ro.boot.flash.locked")):
            c.append(Check("Bootloader & verified boot", PASS, "Locked, verified (green)"))
        elif vb in ("orange", "yellow") or g("ro.boot.flash.locked") == "0":
            c.append(Check("Bootloader & verified boot", FAIL, f"Unlocked / {vb or 'unverified'}",
                           "An unlocked bootloader lets anyone with the phone install modified software. Re-lock it unless you did this on purpose."))
        else:
            c.append(Check("Bootloader & verified boot", UNKNOWN, vb or "not reported"))

        se = sh("getenforce")
        c.append(Check("SELinux", PASS if se == "Enforcing" else FAIL, se or "unknown",
                       "" if se == "Enforcing" else "SELinux is not enforcing: the system's core sandbox is off."))

        root_pkgs = [f"{n} ({k})" for k, n in H.ROOT_PACKAGES.items() if k in apps]
        su = sh("which su 2>/dev/null; ls /system/xbin/su /system/bin/su /sbin/su 2>/dev/null")
        tags = g("ro.build.tags", "")
        if root_pkgs or su:
            c.append(Check("Root access", FAIL, ", ".join(root_pkgs) or "su binary present",
                           "The phone is rooted: any app granted root can read everything. Remove root unless you need it."))
        else:
            c.append(Check("Root access", PASS, "Not rooted"))
        if g("ro.debuggable") == "1" or "test-keys" in tags:
            c.append(Check("System build", WARN, f"{g('ro.build.type')} / {tags}",
                           "Debuggable or test-signed system image; not a stock retail build."))

        age = _patch_age_days(g("ro.build.version.security_patch", ""))
        patch = g("ro.build.version.security_patch", "unknown")
        if age is None:
            c.append(Check("Security patch level", UNKNOWN, patch))
        elif age <= 95:
            c.append(Check("Security patch level", PASS, f"{patch} ({age} days old)"))
        elif age <= 200:
            c.append(Check("Security patch level", WARN, f"{patch} ({age} days old)",
                           "Install the latest system update (Settings › System update)."))
        else:
            c.append(Check("Security patch level", FAIL, f"{patch} ({age} days old)",
                           "Over 6 months without security fixes. Update now; if no update is offered, the phone is out of support."))
        try:
            sdk = int(g("ro.build.version.sdk", "0"))
        except ValueError:
            sdk = 0
        if sdk and sdk < 33:
            c.append(Check("Android version", WARN, f"Android {g('ro.build.version.release')}",
                           "This Android version no longer gets security fixes from Google."))

        crypto = g("ro.crypto.state", "")
        if crypto:
            c.append(Check("Storage encryption", PASS if crypto == "encrypted" else FAIL, crypto))

        consent = sh("settings get global package_verifier_user_consent")
        verifier = sh("settings get global package_verifier_enable")
        if consent == "-1" or verifier == "0":
            c.append(Check("Google Play Protect", FAIL, "Off", "Turn Play Protect on: Play Store › profile › Play Protect."))
        elif consent == "1":
            c.append(Check("Google Play Protect", PASS, "On"))

        c.append(Check("USB debugging", WARN, "On (needed for this scan)",
                       "Turn it off after the scan: Settings › Developer options › USB debugging."))
        if sh("settings get global adb_wifi_enabled") == "1":
            c.append(Check("Wireless debugging", FAIL, "On", "Anyone on your Wi-Fi who pairs can control the phone. Turn it off."))

        proxy = sh("settings get global http_proxy")
        if proxy and proxy not in ("null", ":0", ""):
            c.append(Check("HTTP proxy", FAIL, proxy,
                           "All web traffic is routed through a proxy. Remove it unless you set it up (Wi-Fi settings › Proxy)."))
        else:
            c.append(Check("HTTP proxy", PASS, "None"))

        dns = sh("settings get global private_dns_mode")
        spec = sh("settings get global private_dns_specifier")
        if dns == "hostname":
            c.append(Check("Private DNS", PASS, spec))
        elif dns == "off":
            c.append(Check("Private DNS", WARN, "Off", "Turn on Private DNS (e.g. dns.google or one.one.one.one) to encrypt DNS lookups."))
        else:
            c.append(Check("Private DNS", PASS, "Automatic"))

        conn = sh("dumpsys connectivity", timeout=60)
        always_vpn = sh("settings get secure always_on_vpn_app")
        if re.search(r"NetworkAgentInfo\{[^\n]*VPN[^\n]*CONNECTED", conn) or always_vpn not in ("", "null"):
            c.append(Check("VPN", WARN, always_vpn if always_vpn not in ("", "null") else "A VPN is active",
                           "A VPN sees all your traffic. Make sure you trust the app providing it."))

        third = {k for k, a in apps.items() if a["third_party"]}
        unknown_src = sorted(p for p in ctx["installers"] if p in third or p in ("com.android.chrome",))
        if unknown_src:
            c.append(Check("Apps allowed to install other apps", WARN, ", ".join(unknown_src),
                           "Revoke 'Install unknown apps' for apps that don't need it (Settings › Apps › Special access)."))
        else:
            c.append(Check("Apps allowed to install other apps", PASS, "None"))
        acc = sorted(ctx["accessibility"])
        c.append(Check("Accessibility services on", WARN if acc else PASS, ", ".join(acc) or "None",
                       "Accessibility services can read everything on screen. Keep only ones you recognise." if acc else ""))
        adm = sorted(ctx["admins"])
        c.append(Check("Device administrator apps", WARN if any(a in third for a in adm) else PASS,
                       ", ".join(adm) or "None",
                       "Review device admin apps (Settings › Security › Device admin apps)." if adm else ""))
        sideloaded = sorted(p for p in third if H.is_sideloaded(apps[p]))
        if sideloaded:
            c.append(Check("Apps not from an app store", WARN, f"{len(sideloaded)}: " + ", ".join(sideloaded[:12]) + (" ..." if len(sideloaded) > 12 else ""),
                           "Sideloaded apps skip store malware screening. Remove the ones you don't need."))
        return c

    def _cloud(self, r: ScanResult, third: dict):
        from .cloud import Reputation
        rep = Reputation(self.settings.get("vt_api_key", ""), self.settings.get("mb_api_key", ""), self.p.log)
        if not rep.enabled:
            r.cloud = {"ran": False, "reason": "No VirusTotal / MalwareBazaar API key set"}
            return
        self.p.step("Cloud reputation lookup")
        flagged = {f.target for f in r.findings}
        # Store apps are screened already; check sideloaded and flagged apps.
        targets = [a for pkg, a in third.items() if a.get("sha256") and
                   (H.is_sideloaded(a) or pkg in flagged)][:40]
        hits = 0
        for i, app in enumerate(targets):
            if self.p.cancelled():
                break
            self.p.log(f"  [{i + 1}/{len(targets)}] {app['package']}")
            res = rep.lookup(app["sha256"])
            if res["verdict"] in ("malicious", "suspicious"):
                hits += 1
                existing = next((f for f in r.findings if f.target == app["package"]), None)
                text = f"{res['source']}: {res['detections']} engines flag this APK" + (f" as {res['name']}" if res["name"] else "")
                sev = HIGH if res["verdict"] == "malicious" else MEDIUM
                if existing:
                    existing.reasons.insert(0, text)
                    if sev == HIGH and existing.severity != CRITICAL:
                        existing.severity, existing.category, existing.recommended_removal = HIGH, "malware", True
                else:
                    r.findings.append(Finding(
                        id=f"app:{app['package']}", title=app["package"], severity=sev,
                        category="malware" if sev == HIGH else "suspicious-app", reasons=[text],
                        target=app["package"], target_kind="android-app", removable=True,
                        recommended_removal=sev == HIGH, details=self._app_details(app)))
        r.cloud = {"ran": True, "checked": len(targets), "hits": hits}

    def _deep(self, r: ScanResult):
        from mvt.android.cmd_check_bugreport import CmdAndroidCheckBugreport
        from . import mvt_runner
        p = self.p
        p.step("Deep forensic scan: collecting bug report (3-10 min)")
        work = paths.WORK_DIR / f"android-{re.sub(r'[^A-Za-z0-9]', '_', self.adb.serial)}"
        work.mkdir(parents=True, exist_ok=True)
        zip_path = work / "bugreport.zip"
        if zip_path.exists():
            zip_path.unlink()
        cmd = [self.adb.exe, "-s", self.adb.serial, "bugreport", str(zip_path)]
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, creationflags=NO_WINDOW)
        buf = b""
        while True:
            ch = proc.stdout.read(64)
            if not ch:
                break
            buf = (buf + ch)[-200:]
            m = re.findall(rb"\[\s*(\d+)%\]", buf)
            if m:
                p.pct(60 + int(m[-1]) * 0.2)
            if p.cancelled():
                proc.kill()
                return
        proc.wait()
        if not zip_path.exists() or zip_path.stat().st_size < 10000:
            r.errors.append("Bug report could not be collected; the deep forensic scan was skipped.")
            r.forensic = {"ran": False}
            return
        p.log(f"Bug report collected ({zip_path.stat().st_size / 1e6:.0f} MB)")
        p.step("Deep forensic scan: analysing with MVT")
        out_dir = work / "mvt"
        if out_dir.exists():
            shutil.rmtree(out_dir, ignore_errors=True)
        r.forensic = mvt_runner.run(CmdAndroidCheckBugreport, str(zip_path), str(out_dir), p)
        r.forensic["source"] = "Android bug report"
        r.forensic["raw_input"] = str(zip_path)
        known = {f.id for f in r.findings}
        r.findings.extend(f for f in mvt_runner.findings_from(r.forensic) if f.id not in known)

    # --------------------------------------------------------------- removal
    def remove(self, finding: Finding) -> None:
        pkg, sh = finding.target, self.adb.sh
        sh(f"am force-stop {pkg}")
        acc = sh("settings get secure enabled_accessibility_services")
        if pkg in acc:
            keep = ":".join(c for c in acc.split(":") if c and not c.startswith(pkg + "/"))
            sh(f"settings put secure enabled_accessibility_services '{keep}'" if keep
               else "settings delete secure enabled_accessibility_services")
        out = self.adb.run("uninstall", pkg, timeout=120)
        if "Success" not in out:
            out2 = sh(f"pm uninstall --user 0 {pkg}")
            out = out2 if "Success" in out2 else out + " " + out2
        still = pkg in re.findall(r"^package:(\S+)$", sh(f"pm list packages {pkg}"), re.M)
        if "Success" in out and not still:
            finding.status, finding.status_note = "removed", "Uninstalled"
        elif "DEVICE_POLICY" in out or "device admin" in out.lower():
            sh("am start -a android.settings.SECURITY_SETTINGS")
            finding.status = "needs-user-action"
            finding.status_note = ("It is a device administrator. On the phone open Settings › Security › "
                                   "Device admin apps, turn it off, then press Remove again.")
        else:
            sh(f"pm disable-user --user 0 {pkg}")
            finding.status = "failed"
            finding.status_note = f"Uninstall refused ({out.strip()[:120]}). Disabled instead where possible."
