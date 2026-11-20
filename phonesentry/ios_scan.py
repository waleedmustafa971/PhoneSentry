"""iPhone scanning over USB through Apple's Mobile Device driver (installed with
the "Apple Devices" app or iTunes). Pairs with the phone, reads device facts,
apps and configuration profiles, and optionally makes a backup that MVT checks
for Pegasus and other mercenary-spyware traces."""
import asyncio
import shutil
from datetime import datetime
from pathlib import Path

import requests

from . import iocs as ioc_db
from . import paths
from .models import CRITICAL, FAIL, MEDIUM, PASS, UNKNOWN, WARN, Check, DeviceInfo, Finding, ScanResult

JAILBREAK_APPS = {
    "com.saurik.Cydia": "Cydia", "org.coolstar.SileoStore": "Sileo", "xyz.willy.Zebra": "Zebra",
    "com.opa334.TrollStore": "TrollStore", "com.opa334.Dopamine": "Dopamine",
    "com.tigisoftware.Filza": "Filza", "science.xnu.undecimus": "unc0ver",
    "org.palera1n.palera1n": "palera1n", "com.electrateam.chimera": "Chimera",
    "com.serena.santanderfm": "Santander", "com.opa334.trollstorepersistencehelper": "TrollStore helper",
}
APPSTORE_SIGNER = "Apple iPhone OS Application Signing"


class IOSError_(RuntimeError):
    pass


def _run(coro):
    return asyncio.run(coro)


def list_devices() -> tuple[str, list[str]]:
    """('ok'|'no-driver', [udid, ...])"""
    from pymobiledevice3.usbmux import list_devices as _ld

    async def go():
        return [d.serial for d in await _ld() if d.is_usb]
    try:
        return "ok", _run(go())
    except Exception:
        return "no-driver", []


def quick_info(udid: str) -> dict:
    """Unpaired lockdown query: enough to show the model before 'Trust'."""
    from pymobiledevice3.lockdown import create_using_usbmux

    async def go():
        ld = await create_using_usbmux(serial=udid, autopair=False)
        try:
            v = ld.all_values
            return {"name": ld.display_name or v.get("ProductType", "iPhone"),
                    "version": v.get("ProductVersion", ""), "paired": ld.paired}
        finally:
            await ld.close()
    try:
        return _run(go())
    except Exception as e:
        return {"name": "iPhone", "version": "", "paired": False, "error": str(e)}


class IOSScanner:
    def __init__(self, udid: str, settings: dict, progress):
        self.udid, self.settings, self.p = udid, settings, progress

    async def _connect(self):
        from pymobiledevice3 import exceptions as X
        from pymobiledevice3.lockdown import create_using_usbmux
        told = False
        for _ in range(60):
            if self.p.cancelled():
                raise IOSError_("Cancelled")
            try:
                return await create_using_usbmux(serial=self.udid, autopair=True, pair_timeout=5)
            except X.PasswordRequiredError:
                if not told:
                    self.p.log("Unlock the iPhone with its passcode...")
            except (X.PairingDialogResponsePendingError, X.NotTrustedError):
                if not told:
                    self.p.log('Tap "Trust" on the iPhone and enter its passcode...')
            except X.UserDeniedPairingError:
                raise IOSError_('"Don\'t Trust" was tapped. Unplug, plug back in and tap "Trust".')
            told = True
            await asyncio.sleep(2)
        raise IOSError_("Timed out waiting for the iPhone to trust this computer.")

    def scan(self, deep: bool) -> ScanResult:
        return _run(self._scan(deep))

    async def _scan(self, deep: bool) -> ScanResult:
        from pymobiledevice3.services.installation_proxy import InstallationProxyService
        from pymobiledevice3.services.mobile_config import MobileConfigService
        p = self.p
        p.step("Pairing with the iPhone")
        ld = await self._connect()
        try:
            v = ld.all_values
            info = DeviceInfo(
                platform="ios", serial=v.get("SerialNumber", ""), brand="Apple", manufacturer="Apple",
                model=ld.display_name or v.get("ProductType", ""), model_code=v.get("ProductType", ""),
                os_name="iPadOS" if v.get("DeviceClass") == "iPad" else "iOS",
                os_version=v.get("ProductVersion", ""), build=v.get("BuildVersion", ""),
                extra={"model_number": f'{v.get("ModelNumber", "")}{v.get("RegionInfo", "")}',
                       "hardware": v.get("HardwareModel", ""), "name": v.get("DeviceName", ""),
                       "udid": self.udid})
            r = ScanResult(device=info, started=datetime.now().isoformat(timespec="seconds"), deep_scan=deep)
            await self._facts(ld, info)
            p.log(f"Device: {info.display} - {info.os_name} {info.os_version} ({info.build})")
            p.pct(8)

            p.step("Loading threat database")
            indicators = ioc_db.load()
            s = ioc_db.summary()
            r.ioc_sets, r.ioc_total = s["sets"], s["total"]
            p.pct(10)

            p.step("Inspecting installed apps")
            async with InstallationProxyService(ld) as ip:
                user_apps = await ip.get_apps(application_type="User")
                try:
                    sys_apps = await ip.get_apps(application_type="System")
                except Exception:
                    sys_apps = {}
            r.apps_scanned, r.system_apps = len(user_apps), len(sys_apps)
            p.log(f"{len(user_apps)} user apps, {len(sys_apps)} system apps")
            for bid, a in sorted(user_apps.items()):
                name = a.get("CFBundleDisplayName") or a.get("CFBundleName") or bid
                det = {"bundle_id": bid, "name": name, "version": a.get("CFBundleShortVersionString", ""),
                       "signer": a.get("SignerIdentity", "")}
                m = indicators.check_app_id(bid)
                if m:
                    r.findings.append(Finding(
                        id=f"app:{bid}", title=f"{name} ({bid})", severity=CRITICAL,
                        category=ioc_db.classify(f"{m.ioc.name} {m.ioc.stix2_file_name}"),
                        reasons=[m.message], target=bid, target_kind="ios-app", removable=True,
                        recommended_removal=True, details=det))
                    continue
                signer = a.get("SignerIdentity", "")
                if bid in JAILBREAK_APPS:
                    r.findings.append(Finding(
                        id=f"app:{bid}", title=f"{name} ({bid})", severity=MEDIUM, category="suspicious-app",
                        reasons=[f"Jailbreak / sideloading tool ({JAILBREAK_APPS[bid]}). It disables core iOS protections."],
                        target=bid, target_kind="ios-app", removable=True, details=det))
                elif (signer and APPSTORE_SIGNER not in signer) or a.get("ProfileValidated"):
                    r.findings.append(Finding(
                        id=f"app:{bid}", title=f"{name} ({bid})", severity=MEDIUM, category="suspicious-app",
                        reasons=[f"Not from the App Store: signed by \"{signer or 'a provisioning profile'}\". "
                                 "Enterprise/developer-signed apps skip Apple review; stalkerware is often installed this way."],
                        target=bid, target_kind="ios-app", removable=True, details=det))
            p.pct(20)

            p.step("Checking configuration profiles")
            try:
                async with MobileConfigService(ld) as mc:
                    prof = await mc.get_profile_list()
                meta = (prof or {}).get("ProfileMetadata", {}) or {}
            except Exception as e:
                meta = {}
                p.log(f"  could not list profiles: {e}")
            for pid, m in meta.items():
                uuid = m.get("PayloadUUID", "")
                hit = indicators.check_profile(uuid) if uuid else None
                name = m.get("PayloadDisplayName") or pid
                r.findings.append(Finding(
                    id=f"profile:{pid}", title=f"Configuration profile \"{name}\"",
                    severity=CRITICAL if hit else MEDIUM,
                    category=ioc_db.classify(hit.ioc.name) if hit else "profile",
                    reasons=[hit.message] if hit else [
                        "Profiles can install root certificates, VPN/proxy settings or device management, "
                        "which can intercept your traffic. Keep it only if your school/employer installed it.",
                        f"Organisation: {m.get('PayloadOrganization', 'not stated')}"],
                    target=pid, target_kind="ios-profile", removable=True, recommended_removal=bool(hit),
                    details={"identifier": pid, "uuid": uuid, "description": m.get("PayloadDescription", "")}))
            r.checks = await self._posture(ld, info, user_apps, meta)
            p.pct(28)

            if deep:
                await self._deep(ld, r)
            r.findings.sort(key=lambda f: -{"critical": 4, "high": 3, "medium": 2, "low": 1}.get(f.severity, 0))
            r.finished = datetime.now().isoformat(timespec="seconds")
            return r
        finally:
            await ld.close()

    async def _facts(self, ld, info):
        try:
            du = await ld.get_value("com.apple.disk_usage")
            tot, avail = du.get("TotalDataCapacity", 0), du.get("TotalDataAvailable", 0)
            if tot:
                info.extra["storage"] = f"{(tot - avail) / 1e9:.0f} GB used of {du.get('TotalDiskCapacity', tot) / 1e9:.0f} GB"
                info.extra["_used_bytes"] = tot - avail
        except Exception:
            pass
        try:
            b = await ld.get_value("com.apple.mobile.battery")
            if b.get("BatteryCurrentCapacity") is not None:
                info.extra["battery"] = f'{b["BatteryCurrentCapacity"]}%'
        except Exception:
            pass

    async def _posture(self, ld, info, apps, profiles):
        c = []
        latest = None
        try:
            j = requests.get(f"https://api.ipsw.me/v4/device/{info.model_code}?type=ipsw", timeout=10).json()
            signed = [f["version"] for f in j.get("firmwares", []) if f.get("signed")]
            if signed:
                latest = max(signed, key=lambda s: [int(x) for x in s.split(".") if x.isdigit()])
        except Exception:
            pass
        cur = info.os_version
        key = lambda s: [int(x) for x in s.split(".") if x.isdigit()]  # noqa: E731
        if latest and key(cur) >= key(latest):
            c.append(Check("iOS version", PASS, f"{cur} (latest)"))
        elif latest:
            c.append(Check("iOS version", FAIL, f"{cur} (latest is {latest})",
                           "Update now: Settings › General › Software Update. Spyware like Pegasus relies on bugs fixed in updates."))
        else:
            c.append(Check("iOS version", UNKNOWN, cur, "Make sure Settings › General › Software Update shows no pending update."))
        try:
            enc = await ld.get_value("com.apple.mobile.backup", "WillEncrypt")
            c.append(Check("Encrypted backups", PASS if enc else WARN, "On" if enc else "Off",
                           "" if enc else "Encrypted backups protect saved passwords and let forensic tools check more."))
        except Exception:
            pass
        try:
            dev = await ld.get_value("com.apple.security.mac.amfi", "DeveloperModeStatus")
            c.append(Check("Developer Mode", WARN if dev else PASS, "On" if dev else "Off",
                           "Turn Developer Mode off unless you build apps (Settings › Privacy & Security)." if dev else ""))
        except Exception:
            pass
        jb = [n for b, n in JAILBREAK_APPS.items() if b in apps]
        c.append(Check("Jailbreak tools", FAIL if jb else PASS, ", ".join(jb) or "None found",
                       "A jailbroken iPhone has its security model disabled. Restore iOS to undo it." if jb else ""))
        c.append(Check("Configuration profiles", WARN if profiles else PASS,
                       f"{len(profiles)} installed" if profiles else "None",
                       "Review in Settings › General › VPN & Device Management." if profiles else ""))
        side = [b for b, a in apps.items() if (a.get("SignerIdentity") and APPSTORE_SIGNER not in a.get("SignerIdentity", "")) or a.get("ProfileValidated")]
        c.append(Check("Apps not from the App Store", WARN if side else PASS,
                       ", ".join(side[:10]) or "None"))
        c.append(Check("Lockdown Mode", UNKNOWN, "Cannot be read over USB",
                       "If you may be targeted (journalist, activist, official), turn on Lockdown Mode: Settings › Privacy & Security."))
        return c

    async def _deep(self, ld, r: ScanResult):
        from mvt.ios.cmd_check_backup import CmdIOSCheckBackup
        from mvt.ios.decrypt import DecryptBackup
        from pymobiledevice3.services.mobilebackup2 import Mobilebackup2Service
        from . import mvt_runner
        p = self.p
        work = paths.WORK_DIR / f"ios-{self.udid[:12]}"
        need = r.device.extra.get("_used_bytes", 0)
        free = shutil.disk_usage(paths.WORK_DIR).free
        async with Mobilebackup2Service(ld) as bk:
            encrypted = await bk.get_will_encrypt()
        factor = 2.2 if encrypted else 1.2
        if need and free < need * factor:
            r.errors.append(f"Deep scan skipped: the backup needs about {need * factor / 1e9:.0f} GB free on "
                            f"{paths.WORK_DIR.drive}, only {free / 1e9:.0f} GB available.")
            r.forensic = {"ran": False}
            return
        password = ""
        if encrypted:
            password = p.ask("encrypted") or ""
            if not password:
                r.errors.append("Deep scan skipped: this iPhone's backups are encrypted and no password was given.")
                r.forensic = {"ran": False}
                return
        else:
            password = p.ask("enable-encryption") or ""
            if password:
                p.log("Turning on encrypted backups (confirm with the passcode on the iPhone if asked)...")
                try:
                    async with Mobilebackup2Service(ld) as bk:
                        await bk.change_password(work, new=password)
                    encrypted = True
                    r.actions.append("Turned on encrypted backups with the password you chose.")
                except Exception as e:
                    p.log(f"  could not enable encryption ({e}); continuing unencrypted")
                    password = ""
        p.step("Deep forensic scan: backing up the iPhone (can take 10-40 min)")
        p.log("Keep the iPhone unlocked and connected. Enter its passcode if it asks.")
        if work.exists():
            shutil.rmtree(work, ignore_errors=True)
        work.mkdir(parents=True)
        async with Mobilebackup2Service(ld) as bk:
            await bk.backup(full=True, backup_directory=work,
                            progress_callback=lambda pc: p.pct(30 + float(pc) * 0.5))
        backup_dir = work / self.udid
        target = backup_dir
        if encrypted:
            p.step("Deep forensic scan: decrypting the backup")
            dest = work / "decrypted"
            dec = DecryptBackup(str(backup_dir), str(dest))
            dec.decrypt_with_password(password)
            if not dec.can_process():
                r.errors.append("Wrong backup password: the deep scan could not decrypt the backup.")
                r.forensic = {"ran": False}
                return
            dec.process_backup()
            target = dest
        p.step("Deep forensic scan: analysing with MVT")
        out_dir = work / "mvt"
        r.forensic = mvt_runner.run(CmdIOSCheckBackup, str(target), str(out_dir), p)
        r.forensic["source"] = "iPhone backup" + (" (encrypted)" if encrypted else " (unencrypted: less data available)")
        r.forensic["raw_input"] = str(work)
        known = {f.id for f in r.findings}
        r.findings.extend(f for f in mvt_runner.findings_from(r.forensic) if f.id not in known)

    # --------------------------------------------------------------- removal
    def remove(self, finding: Finding) -> None:
        _run(self._remove(finding))

    async def _remove(self, finding: Finding):
        from pymobiledevice3.services.installation_proxy import InstallationProxyService
        from pymobiledevice3.services.mobile_config import MobileConfigService
        ld = await self._connect()
        try:
            if finding.target_kind == "ios-app":
                async with InstallationProxyService(ld) as ip:
                    await ip.uninstall(finding.target)
                    left = await ip.get_apps(application_type="User", bundle_identifiers=[finding.target])
                ok = finding.target not in (left or {})
                finding.status = "removed" if ok else "failed"
                finding.status_note = "Uninstalled" if ok else "The iPhone refused to uninstall it; delete it from the home screen."
            elif finding.target_kind == "ios-profile":
                async with MobileConfigService(ld) as mc:
                    await mc.remove_profile(finding.target)
                    left = ((await mc.get_profile_list()) or {}).get("ProfileMetadata", {})
                ok = finding.target not in left
                finding.status = "removed" if ok else "needs-user-action"
                finding.status_note = ("Profile removed" if ok else
                                       "Remove it on the iPhone: Settings › General › VPN & Device Management.")
        except Exception as e:
            finding.status, finding.status_note = "failed", str(e)[:160]
        finally:
            await ld.close()
