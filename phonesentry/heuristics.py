"""Behavioural risk scoring for Android apps.

Known-bad detection comes from indicator feeds and hash reputation. This module
catches the rest: commodity trojans (banking malware, SMS stealers, droppers,
stalkerware) share a recognisable shape - sideloaded, abusing accessibility,
device-admin, overlay and SMS access, hiding their icon, posing as system apps.
"""
from .models import HIGH, LOW, MEDIUM

# Installers that are real app stores. Anything else (file manager, browser,
# "package installer", adb) means the APK was sideloaded.
TRUSTED_STORES = {
    "com.android.vending": "Google Play",
    "com.google.android.feedback": "Google Play",
    "com.sec.android.app.samsungapps": "Galaxy Store",
    "com.huawei.appmarket": "Huawei AppGallery",
    "com.xiaomi.market": "Xiaomi GetApps",
    "com.xiaomi.mipicks": "Xiaomi GetApps",
    "com.miui.supermarket": "Xiaomi GetApps",
    "com.heytap.market": "OPPO App Market",
    "com.oppo.market": "OPPO App Market",
    "com.bbk.appstore": "vivo App Store",
    "com.vivo.appstore": "vivo App Store",
    "com.amazon.venezia": "Amazon Appstore",
    "com.hihonor.appmarket": "HONOR App Market",
    "com.transsion.phoenix": "Palm Store",
    "com.oneplus.market": "OnePlus Store",
    "org.fdroid.fdroid": "F-Droid",
    "com.aurora.store": "Aurora Store",
    "com.google.android.packageinstaller.play": "Google Play",
    # OEM preload / partner installers (apps shipped with the phone)
    "com.facebook.system": "Facebook preload (OEM)",
    "com.sec.android.preloadinstaller": "Samsung preload",
    "com.xiaomi.discover": "Xiaomi system updater",
    "com.android.preinstall": "OEM preload",
    "com.miui.global.packageinstaller.preload": "Xiaomi preload",
    "com.huawei.android.hwouc": "Huawei preload",
}

SIDELOAD_INSTALLERS = {
    "com.android.packageinstaller", "com.google.android.packageinstaller",
    "com.miui.packageinstaller", "com.samsung.android.packageinstaller", "null", "",
}

# Package prefixes only the OS vendor ships. A sideloaded app using them is impersonating.
IMPERSONATED_PREFIXES = ("com.android.", "android.", "com.google.", "dev.google.",
                         "com.samsung.", "com.sec.", "com.miui.", "com.xiaomi.",
                         "com.huawei.", "com.oppo.", "com.coloros.", "com.qualcomm.",
                         "com.mediatek.", "com.whatsapp.update")
SYSTEMY_WORDS = ("system", "update", "service", "security", "google", "android",
                 "sysupdate", "settings", "battery", "wifi", "framework")

ROOT_PACKAGES = {
    "com.topjohnwu.magisk": "Magisk", "io.github.huskydg.magisk": "Magisk Delta",
    "io.github.vvb2060.magisk": "Magisk Alpha", "me.weishu.kernelsu": "KernelSU",
    "me.bmax.apatch": "APatch", "eu.chainfire.supersu": "SuperSU",
    "com.koushikdutta.superuser": "Superuser", "com.noshufou.android.su": "Superuser",
    "de.robv.android.xposed.installer": "Xposed", "org.lsposed.manager": "LSPosed",
    "com.kingroot.kinguser": "KingRoot", "com.kingo.root": "KingoRoot",
}

PERM_WEIGHTS = {
    "android.permission.READ_SMS": (2.0, "reads your SMS messages"),
    "android.permission.RECEIVE_SMS": (2.0, "intercepts incoming SMS (2FA codes)"),
    "android.permission.SEND_SMS": (1.5, "can send SMS"),
    "android.permission.READ_CALL_LOG": (1.0, "reads call history"),
    "android.permission.PROCESS_OUTGOING_CALLS": (1.0, "monitors outgoing calls"),
    "android.permission.RECORD_AUDIO": (1.0, "can record audio"),
    "android.permission.CAMERA": (0.5, "can use the camera"),
    "android.permission.ACCESS_BACKGROUND_LOCATION": (1.5, "tracks location in the background"),
    "android.permission.ACCESS_FINE_LOCATION": (0.5, "precise location"),
    "android.permission.READ_CONTACTS": (0.5, "reads contacts"),
    "android.permission.READ_PHONE_STATE": (0.3, "reads phone identity / call state"),
    "android.permission.MANAGE_EXTERNAL_STORAGE": (0.7, "access to all files"),
    "android.permission.QUERY_ALL_PACKAGES": (0.3, "lists every installed app"),
    "android.permission.RECEIVE_BOOT_COMPLETED": (0.3, "starts automatically at boot"),
    "android.permission.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS": (0.3, "keeps itself running"),
    "android.permission.USE_FULL_SCREEN_INTENT": (0.2, "full-screen pop-ups"),
}


def is_preloaded(app: dict) -> bool:
    """APK lives on a read-only firmware partition (/product, /system, /vendor,
    /cust...): it shipped with the phone. Nothing can put it there without root."""
    path = app.get("path", "")
    return bool(path) and not path.startswith(("/data/", "/mnt/"))


def is_webapk(app: dict) -> bool:
    """Home-screen web apps that Chrome mints and installs itself."""
    return app.get("package", "").startswith("org.chromium.webapk.")


def is_sideloaded(app: dict) -> bool:
    return (app.get("installer") or "null") not in TRUSTED_STORES and not is_preloaded(app) \
        and app.get("installer") != "android" and not is_webapk(app)


def source_label(app: dict) -> str:
    if is_webapk(app):
        return "Chrome web app"
    if is_preloaded(app) or app.get("installer") == "android":
        return "Preinstalled by the manufacturer"
    return TRUSTED_STORES.get(app.get("installer"), "Sideloaded")


def score_app(app: dict, ctx: dict) -> tuple[float, list[str]]:
    """Return (score, reasons) for one third-party app.

    app: package, installer, path, granted (set), requested (set), launcher (bool)
    ctx: accessibility (set), admins (set), listeners (set), overlay (set), installers (set),
         sms_default (str)
    """
    pkg = app["package"]
    installer = app.get("installer") or "null"
    granted = app.get("granted", set())
    score, why = 0.0, []

    sideloaded = is_sideloaded(app)
    if sideloaded:
        src = "installed via adb or an unknown source" if installer in ("null", "") else f"installed by {installer}, not an app store"
        score += 2.0
        why.append(f"Sideloaded: {src}")

    if pkg.startswith(IMPERSONATED_PREFIXES) and sideloaded:
        score += 4.5
        why.append("Uses a system/Google-style package name but did not come from the vendor or Play Store (impersonation)")
    elif sideloaded and sum(w in pkg.lower() for w in SYSTEMY_WORDS) >= 2:
        score += 1.5
        why.append("Package name poses as a system component")

    acc = pkg in ctx.get("accessibility", set())
    if acc:
        score += 4.0 if sideloaded else 1.5
        why.append("Accessibility service is ON: it can read the screen, see what you type and tap for you")
    if pkg in ctx.get("admins", set()):
        score += 3.0 if sideloaded else 1.0
        why.append("Registered as a device administrator (blocks uninstall, can lock/wipe)")
    lst = pkg in ctx.get("listeners", set())
    if lst:
        score += 1.5 if sideloaded else 0.5
        why.append("Reads all your notifications (messages, codes)")
    if pkg in ctx.get("overlay", set()):
        score += 1.5 if sideloaded else 0.3
        why.append("Can draw over other apps (fake login screens)")
    if pkg in ctx.get("installers", set()):
        score += 1.0 if sideloaded else 0.3
        why.append("Allowed to install other apps")
    if pkg == ctx.get("sms_default"):
        score += 1.0
        why.append("Set as the default SMS app")

    sms = False
    perm_score = 0.0
    for perm, (w, text) in PERM_WEIGHTS.items():
        if perm in granted:
            perm_score += w
            why.append(f"Permission: {text}")
            sms = sms or "SMS" in perm
    score += perm_score * (1.0 if sideloaded else 0.25)

    if not app.get("launcher", True):
        score += 2.0 if sideloaded else 0.3
        why.append("Has no app icon (hidden from the app drawer)")

    # Combinations typical of banking trojans / stalkerware.
    if sideloaded and acc and (sms or lst):
        score += 3.0
        why.append("Combination typical of banking trojans: accessibility + SMS/notification access")
    if sideloaded and not app.get("launcher", True) and (
            "android.permission.ACCESS_BACKGROUND_LOCATION" in granted
            or "android.permission.RECORD_AUDIO" in granted or sms):
        score += 2.0
        why.append("Hidden app with surveillance permissions: typical of stalkerware")

    return score, why


def severity_for(score: float):
    if score >= 9:
        return HIGH
    if score >= 5.5:
        return MEDIUM
    if score >= 3.5:
        return LOW
    return None
