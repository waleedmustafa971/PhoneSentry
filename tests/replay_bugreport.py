"""Replays the parsers + malware heuristics on a real bug report's dumpstate.

  .venv\\Scripts\\python.exe tests\\replay_bugreport.py path\\to\\bugreport.zip
"""
import io
import re
import sys
import zipfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from phonesentry import heuristics as H  # noqa: E402
from phonesentry.android_scan import device_info, parse_getprop, parse_package_dump, _set  # noqa: E402


def dumpstate(path):
    z = zipfile.ZipFile(path)
    names = z.namelist()
    if not any(re.match(r"bugreport-.*\.txt$", n) for n in names):
        inner = next(n for n in names if n.lower().endswith(".zip") and "bugreport" in n.lower())
        z = zipfile.ZipFile(io.BytesIO(z.read(inner)))
        names = z.namelist()
    main = next(n for n in names if re.match(r"bugreport-.*\.txt$", n))
    return z.read(main).decode("utf-8", "replace")


def section(text, header):
    i = text.find(header)
    if i < 0:
        return ""
    j = text.find("\n------ ", i + len(header))
    k = text.find("\nDUMP OF SERVICE ", i + len(header))
    ends = [e for e in (j, k) if e > 0]
    return text[i:min(ends) if ends else None]


class FakeAdb:
    serial = "TEST"

    def sh(self, cmd, timeout=0):
        return ""


def main(path):
    t = dumpstate(path)
    props = parse_getprop(section(t, "------ SYSTEM PROPERTIES"))
    info = device_info(FakeAdb(), props)
    print("Device:", info.display, "| brand", info.brand, "| code", info.model_code,
          "| Android", info.os_version, "| patch", info.security_patch, "|", info.extra.get("skin"))

    pkg_dump = section(t, "DUMP OF SERVICE package:")
    pkgs = parse_package_dump(pkg_dump)
    print("Packages parsed:", len(pkgs))
    sec = section(t, "DUMP OF SERVICE settings:") + section(t, "------ SETTINGS")
    acc = re.search(r"enabled_accessibility_services\s+value:([^\s]+)", sec)
    ctx = {"accessibility": _set(acc.group(1)) if acc else set(), "listeners": set(), "admins": set(),
           "overlay": set(), "installers": set(), "sms_default": ""}
    print("Accessibility:", ctx["accessibility"])
    # pkg -> installer via "installerPackageName=" in dump; third-party = codePath under /data/app
    third = {}
    for m in re.finditer(r"^  Package \[([^\]]+)\][^\n]*\n((?:    [^\n]*\n)+)", pkg_dump, re.M):
        if "codePath=/data/app" in m.group(2) and "flags=[ SYSTEM" not in m.group(2):
            third[m.group(1)] = pkgs[m.group(1)]
    print("Third-party apps:", len(third))
    rows = []
    for pkg, d in third.items():
        app = {"package": pkg, "installer": d.get("installerPackageName", "null"),
               "granted": d["granted"], "requested": d["requested"], "launcher": True}
        score, why = H.score_app(app, ctx)
        sev = H.severity_for(score)
        if sev:
            rows.append((score, sev, pkg, app["installer"], why))
    for score, sev, pkg, inst, why in sorted(rows, reverse=True):
        print(f"\n[{sev.upper()} {score:.1f}] {pkg} (installer {inst})")
        for w in why[:6]:
            print("   -", w)
    print(f"\nFlagged {len(rows)} of {len(third)} user apps")


if __name__ == "__main__":
    main(sys.argv[1])
