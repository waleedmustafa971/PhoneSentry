"""PhoneSentry desktop app (customtkinter)."""
import os
import queue
import threading
import time
import tkinter as tk
import traceback
import webbrowser
from tkinter import messagebox

import customtkinter as ctk
from PIL import Image

from . import APP_NAME, APP_TAGLINE, APP_VERSION, paths
from .models import CRITICAL, HIGH, LOW, MEDIUM, Progress

SEV_COLORS = {CRITICAL: "#ef4444", HIGH: "#f97316", MEDIUM: "#eab308", LOW: "#818cf8"}
ACCENT = "#2563eb"

HELP_ANDROID = (
    "Android: turn on USB debugging\n"
    "1. Settings › About phone › tap \"Build number\" (or \"OS version\") 7 times.\n"
    "2. Settings › System / Additional settings › Developer options › USB debugging: ON.\n"
    "   Xiaomi/Redmi: also turn on \"USB debugging (Security settings)\".\n"
    "3. Plug in the cable, unlock the phone and tap \"Allow\" on the pop-up.\n"
)
HELP_IOS = (
    "iPhone / iPad\n"
    "1. Install \"Apple Devices\" from the Microsoft Store (or iTunes).\n"
    "2. Plug in the cable, unlock the iPhone and tap \"Trust\", then enter the passcode.\n"
)


class Dialog(ctk.CTkToplevel):
    """Small modal dialog that returns text (masked for passwords)."""

    def __init__(self, master, title, text, secret=True, button="OK"):
        super().__init__(master)
        self.title(title)
        self.resizable(False, False)
        self.value = None
        ctk.CTkLabel(self, text=text, wraplength=420, justify="left").pack(padx=20, pady=(18, 8), anchor="w")
        self.entry = ctk.CTkEntry(self, width=420, show="•" if secret else "")
        self.entry.pack(padx=20, pady=4)
        row = ctk.CTkFrame(self, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(10, 18))
        ctk.CTkButton(row, text=button, width=110, command=self._ok).pack(side="right")
        ctk.CTkButton(row, text="Skip", width=90, fg_color="gray30", command=self.destroy).pack(side="right", padx=8)
        self.entry.bind("<Return>", lambda e: self._ok())
        self.after(150, self._focus)

    def _focus(self):
        self.grab_set()
        self.entry.focus_set()
        self.lift()

    def _ok(self):
        self.value = self.entry.get()
        self.destroy()

    def get(self):
        self.master.wait_window(self)
        return self.value


class SettingsWindow(ctk.CTkToplevel):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Settings")
        self.resizable(False, False)
        s = app.settings
        f = ctk.CTkFrame(self, fg_color="transparent")
        f.pack(padx=22, pady=18)
        ctk.CTkLabel(f, text="Cloud reputation (optional)", font=ctk.CTkFont(size=15, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(f, text="Free API keys let PhoneSentry check sideloaded apps against 70+ antivirus engines.\n"
                             "Only the app's SHA-256 fingerprint is sent, never the app or your data.",
                     justify="left", text_color="gray70").pack(anchor="w", pady=(2, 10))
        ctk.CTkLabel(f, text="VirusTotal API key (virustotal.com › sign up › API key)").pack(anchor="w")
        self.vt = ctk.CTkEntry(f, width=460, show="•")
        self.vt.insert(0, s.get("vt_api_key", ""))
        self.vt.pack(anchor="w", pady=(2, 10))
        ctk.CTkLabel(f, text="MalwareBazaar Auth-Key (auth.abuse.ch)").pack(anchor="w")
        self.mb = ctk.CTkEntry(f, width=460, show="•")
        self.mb.insert(0, s.get("mb_api_key", ""))
        self.mb.pack(anchor="w", pady=(2, 14))
        self.keep = ctk.CTkCheckBox(f, text="Keep raw bug report / backup after a deep scan (large, contains personal data)")
        if s.get("keep_raw_backup"):
            self.keep.select()
        self.keep.pack(anchor="w", pady=(0, 14))
        ctk.CTkButton(f, text="Save", command=self.save).pack(anchor="e")
        self.after(150, self.grab_set)

    def save(self):
        s = self.app.settings
        s["vt_api_key"], s["mb_api_key"] = self.vt.get().strip(), self.mb.get().strip()
        s["keep_raw_backup"] = bool(self.keep.get())
        paths.save_settings(s)
        self.destroy()


class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        self.title(f"{APP_NAME} {APP_VERSION}")
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w, h = min(1180, sw - 60), min(760, sh - 120)
        self.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}+{max(0, (sh - h - 60) // 2)}")
        self.minsize(min(980, w), min(600, h))
        try:
            self.iconbitmap(str(paths.resource("assets", "logo.ico")))
        except tk.TclError:
            pass
        self.settings = paths.load_settings()
        self.q: queue.Queue = queue.Queue()
        self.devices: dict[str, dict] = {}      # key -> {platform, id, label, state}
        self.info_cache: dict[str, dict] = {}
        self.selected: str = ""
        self.busy = False
        self.cancel_flag = threading.Event()
        self.result = None
        self.scanner = None
        self.check_vars: dict[str, tk.BooleanVar] = {}
        self._build()
        self.after(100, self._pump)
        threading.Thread(target=self._load_db, daemon=True).start()
        if not os.environ.get("PHONESENTRY_DEMO"):
            threading.Thread(target=self._poll_devices, daemon=True).start()
        self.protocol("WM_DELETE_WINDOW", self._close)

    # ----------------------------------------------------------------- layout
    def _build(self):
        top = ctk.CTkFrame(self, height=74, corner_radius=0, fg_color=("#e8edf7", "#0b1226"))
        top.pack(fill="x")
        logo = ctk.CTkImage(Image.open(paths.resource("assets", "logo.png")), size=(50, 50))
        ctk.CTkLabel(top, image=logo, text="").pack(side="left", padx=(18, 10), pady=12)
        t = ctk.CTkFrame(top, fg_color="transparent")
        t.pack(side="left")
        ctk.CTkLabel(t, text=APP_NAME, font=ctk.CTkFont(size=24, weight="bold")).pack(anchor="w")
        ctk.CTkLabel(t, text=APP_TAGLINE + " · Android & iPhone", text_color="gray60").pack(anchor="w")
        ctk.CTkButton(top, text="Settings", width=90, fg_color="gray25", command=lambda: SettingsWindow(self)).pack(side="right", padx=(6, 18))
        self.upd_btn = ctk.CTkButton(top, text="Update threat database", width=170, fg_color="gray25", command=self._update_db)
        self.upd_btn.pack(side="right", padx=6)
        self.db_label = ctk.CTkLabel(top, text="Loading threat database...", text_color="gray60")
        self.db_label.pack(side="right", padx=10)

        body = ctk.CTkFrame(self, fg_color="transparent")
        body.pack(fill="both", expand=True, padx=16, pady=14)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        left = ctk.CTkFrame(body, width=360)
        left.grid(row=0, column=0, sticky="ns", padx=(0, 14))
        left.grid_propagate(False)
        ctk.CTkLabel(left, text="Device", font=ctk.CTkFont(size=16, weight="bold")).pack(anchor="w", padx=16, pady=(14, 4))
        self.dev_menu = ctk.CTkOptionMenu(left, values=["Waiting for a phone..."], command=self._pick, width=328)
        self.dev_menu.pack(padx=16, pady=4)
        self.dev_name = ctk.CTkLabel(left, text="No phone connected", font=ctk.CTkFont(size=18, weight="bold"), wraplength=320, justify="left")
        self.dev_name.pack(anchor="w", padx=16, pady=(10, 0))
        self.dev_state = ctk.CTkLabel(left, text="Plug a phone in with a USB cable.", text_color="gray65", wraplength=320, justify="left")
        self.dev_state.pack(anchor="w", padx=16, pady=(2, 8))
        self.help = ctk.CTkTextbox(left, height=210, wrap="word", fg_color=("#f1f3f8", "#141b2d"))
        self.help.pack(fill="x", padx=16, pady=4)
        self._set_help(HELP_ANDROID + "\n" + HELP_IOS)

        opts = ctk.CTkFrame(left, fg_color="transparent")
        opts.pack(fill="x", padx=16, pady=(10, 0))
        self.deep = ctk.CTkCheckBox(opts, text="Deep forensic scan (Pegasus-grade)")
        if self.settings.get("deep_scan", True):
            self.deep.select()
        self.deep.pack(anchor="w", pady=3)
        ctk.CTkLabel(opts, text="Analyses a full bug report / backup with MVT. Android: +5-10 min. iPhone: +15-40 min and free disk space.",
                     text_color="gray55", wraplength=320, justify="left", font=ctk.CTkFont(size=12)).pack(anchor="w", padx=(28, 0))
        self.cloud = ctk.CTkCheckBox(opts, text="Cloud reputation lookup (needs API key)")
        if self.settings.get("cloud_lookup", True):
            self.cloud.select()
        self.cloud.pack(anchor="w", pady=(8, 3))

        self.scan_btn = ctk.CTkButton(left, text="Start scan", height=46, font=ctk.CTkFont(size=16, weight="bold"),
                                      state="disabled", command=self._start_scan)
        self.scan_btn.pack(fill="x", padx=16, pady=(16, 6), side="bottom")

        right = ctk.CTkFrame(body)
        right.grid(row=0, column=1, sticky="nsew")
        self.tabs = ctk.CTkTabview(right)
        self.tabs.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        scan_tab, res_tab = self.tabs.add("Scan"), self.tabs.add("Results")

        self.step = ctk.CTkLabel(scan_tab, text="Ready", font=ctk.CTkFont(size=17, weight="bold"), anchor="w")
        self.step.pack(fill="x", padx=6, pady=(6, 4))
        self.bar = ctk.CTkProgressBar(scan_tab, height=12)
        self.bar.set(0)
        self.bar.pack(fill="x", padx=6, pady=(0, 10))
        self.log = ctk.CTkTextbox(scan_tab, wrap="word", font=ctk.CTkFont(family="Consolas", size=12))
        self.log.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.log.configure(state="disabled")

        self.verdict = ctk.CTkLabel(res_tab, text="No scan yet", font=ctk.CTkFont(size=22, weight="bold"), anchor="w")
        self.verdict.pack(fill="x", padx=8, pady=(6, 0))
        self.verdict_sub = ctk.CTkLabel(res_tab, text="", anchor="w", text_color="gray65", justify="left", wraplength=700)
        self.verdict_sub.pack(fill="x", padx=8)
        self.res_list = ctk.CTkScrollableFrame(res_tab)
        self.res_list.pack(fill="both", expand=True, padx=6, pady=8)
        row = ctk.CTkFrame(res_tab, fg_color="transparent")
        row.pack(fill="x", padx=6, pady=(0, 6))
        self.rm_btn = ctk.CTkButton(row, text="Remove selected", fg_color="#b91c1c", hover_color="#991b1b",
                                    state="disabled", command=self._remove_selected)
        self.rm_btn.pack(side="left")
        self.open_btn = ctk.CTkButton(row, text="Open report", state="disabled", command=self._open_report)
        self.open_btn.pack(side="right")
        self.dir_btn = ctk.CTkButton(row, text="Report folder", fg_color="gray25", state="disabled",
                                     command=lambda: os.startfile(self.result.report_dir))
        self.dir_btn.pack(side="right", padx=8)

    def _set_help(self, text):
        self.help.configure(state="normal")
        self.help.delete("1.0", "end")
        self.help.insert("1.0", text)
        self.help.configure(state="disabled")

    # ------------------------------------------------------ threading helpers
    def post(self, kind, *data):
        self.q.put((kind, data))

    def _pump(self):
        try:
            while True:
                kind, data = self.q.get_nowait()
                getattr(self, f"_on_{kind}")(*data)
        except queue.Empty:
            pass
        self.after(100, self._pump)

    def _on_log(self, msg):
        self.log.configure(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")

    def _on_step(self, s):
        self.step.configure(text=s)
        self._on_log(f"\n▶ {s}")

    def _on_pct(self, v):
        if v is None:
            self.bar.configure(mode="indeterminate")
            self.bar.start()
        else:
            self.bar.stop()
            self.bar.configure(mode="determinate")
            self.bar.set(max(0, min(1, v / 100)))

    def _on_call(self, fn):
        fn()

    def _ask(self, kind):
        """Called from the worker; blocks until the user answers in the UI."""
        box, ev = {}, threading.Event()

        def show():
            if kind == "encrypted":
                d = Dialog(self, "Backup password", "This iPhone's backups are protected by a password. Enter it so the deep "
                                                    "scan can decrypt the backup (it never leaves this computer).")
            else:
                d = Dialog(self, "Encrypted backup", "Backups on this iPhone are not encrypted. Encrypted backups let PhoneSentry "
                                                     "check much more (e.g. app network records that reveal Pegasus).\n\n"
                                                     "Choose a backup password to turn encryption on - WRITE IT DOWN, you will need it "
                                                     "to restore backups. Or press Skip to scan with less data.",
                           button="Turn on")
            box["v"] = d.get()
            ev.set()
        self.post("call", show)
        ev.wait()
        return box.get("v")

    def _progress(self):
        return Progress(log=lambda m: self.post("log", m), step=lambda s: self.post("step", s),
                        pct=lambda v: self.post("pct", v), cancelled=self.cancel_flag.is_set, ask=self._ask)

    # ---------------------------------------------------------- threat DB
    def _load_db(self):
        try:
            from . import iocs
            s = iocs.summary()
            self.post("call", lambda: self.db_label.configure(
                text=f"{s['total']:,} threat indicators · {s['set_count']} feeds · updated {s['updated']}"))
        except Exception as e:
            self.post("call", lambda: self.db_label.configure(text=f"Threat database error: {e}"))

    def _update_db(self):
        self.upd_btn.configure(state="disabled", text="Updating...")

        def work():
            try:
                from . import iocs
                s = iocs.update()
                msg = f"{s['total']:,} threat indicators · {s['set_count']} feeds · updated {s['updated']}"
            except Exception as e:
                msg = f"Update failed: {e}"
            self.post("call", lambda: (self.db_label.configure(text=msg),
                                       self.upd_btn.configure(state="normal", text="Update threat database")))
        threading.Thread(target=work, daemon=True).start()

    # ------------------------------------------------------- device polling
    def _poll_devices(self):
        from .android_scan import Adb, device_info, parse_getprop
        from .ios_scan import list_devices, quick_info
        try:
            adb = Adb()
            adb.run("start-server", timeout=30)
        except Exception as e:
            adb = None
            self.post("log", f"adb unavailable: {e}")
        ios_driver = True
        while True:
            if not self.busy:
                found = {}
                if adb:
                    try:
                        for d in adb.devices():
                            key = f"a:{d['serial']}"
                            entry = {"platform": "android", "id": d["serial"], "state": d["state"],
                                     "label": d.get("model", d["serial"]).replace("_", " ")}
                            if d["state"] == "device":
                                if key not in self.info_cache:
                                    try:
                                        a = Adb(d["serial"])
                                        info = device_info(a, parse_getprop(a.sh("getprop", timeout=20)))
                                        self.info_cache[key] = {"label": info.display,
                                                                "sub": f"Android {info.os_version} · patch {info.security_patch}"}
                                    except Exception:
                                        pass
                                entry.update(self.info_cache.get(key, {}))
                            found[key] = entry
                    except Exception:
                        pass
                status, udids = list_devices()
                ios_driver = status == "ok"
                for u in udids:
                    key = f"i:{u}"
                    if key not in self.info_cache:
                        q = quick_info(u)
                        self.info_cache[key] = {"label": q["name"], "sub": f"iOS {q['version']}".strip()}
                    found[key] = {"platform": "ios", "id": u, "state": "device", **self.info_cache[key]}
                self.post("devices", found, ios_driver)
            time.sleep(2.5)

    def _on_devices(self, found, ios_driver):
        changed = set(found) != set(self.devices) or any(
            found[k]["state"] != self.devices[k]["state"] for k in found if k in self.devices)
        self.devices = found
        if not changed and self.selected in found:
            return
        if not found:
            self.dev_menu.configure(values=["Waiting for a phone..."])
            self.dev_menu.set("Waiting for a phone...")
            self.selected = ""
        else:
            labels = [self._label(k) for k in found]
            self.dev_menu.configure(values=labels)
            if self.selected not in found:
                self.selected = next(iter(found))
            self.dev_menu.set(self._label(self.selected))
        self._refresh_device(ios_driver)

    def _label(self, key):
        d = self.devices[key]
        return f"{d.get('label', d['id'])} ({'Android' if d['platform'] == 'android' else 'iPhone'})"

    def _pick(self, label):
        for k in self.devices:
            if self._label(k) == label:
                self.selected = k
        self._refresh_device(True)

    def _refresh_device(self, ios_driver=True):
        d = self.devices.get(self.selected)
        ready = False
        if not d:
            self.dev_name.configure(text="No phone connected")
            self.dev_state.configure(text="Plug a phone in with a USB cable." +
                                     ("" if ios_driver else "\niPhone support needs the free \"Apple Devices\" app."))
            self._set_help(HELP_ANDROID + "\n" + HELP_IOS)
        elif d["state"] == "unauthorized":
            self.dev_name.configure(text=d.get("label", "Android phone"))
            self.dev_state.configure(text="Unlock the phone and tap \"Allow\" on the USB debugging prompt.", text_color="#eab308")
            self._set_help(HELP_ANDROID + "\nNo prompt? Unplug and replug the cable, or in Developer options tap "
                                          "\"Revoke USB debugging authorizations\" and try again.")
        elif d["state"] != "device":
            self.dev_name.configure(text=d.get("label", d["id"]))
            self.dev_state.configure(text=f"Phone state: {d['state']}. Reconnect the cable.", text_color="#eab308")
        else:
            ready = True
            self.dev_name.configure(text=d.get("label", d["id"]))
            self.dev_state.configure(text=d.get("sub", "") + "\nReady to scan.", text_color="#22c55e")
            self._set_help(HELP_IOS if d["platform"] == "ios" else
                           "Ready. Keep the phone unlocked and connected during the scan.\n\n"
                           "PhoneSentry reads app and system information through USB debugging. "
                           "Nothing is changed on the phone unless you choose to remove a threat.")
        self.scan_btn.configure(state="normal" if ready and not self.busy else "disabled")

    # ------------------------------------------------------------- scanning
    def _start_scan(self):
        if self.busy:
            self.cancel_flag.set()
            self.scan_btn.configure(text="Cancelling...", state="disabled")
            return
        d = self.devices.get(self.selected)
        if not d:
            return
        deep = bool(self.deep.get())
        consent = (
            "Before scanning, please confirm:\n\n"
            "• This is my phone, or its owner is present and has freely agreed to this scan.\n\n"
            "• I understand PhoneSentry will read the list of installed apps, their permissions and "
            "system settings" + (", and for the deep scan a full bug report / backup (which includes "
            "messages, browsing history and other personal records)" if deep else "") + ".\n\n"
            "• The data stays on this computer. Raw " + ("bug reports / backups are deleted after the scan; "
                                                           if not self.settings.get("keep_raw_backup") else
                                                           "bug reports / backups are KEPT (see Settings); ")
            + "the report and forensic results are saved in Documents\\PhoneSentry Reports.\n\n"
            "• Only app fingerprints (hashes) are sent online, and only if a cloud API key is set.\n\n"
            "Scan this phone?")
        if not messagebox.askyesno(f"{APP_NAME} - consent", consent):
            return
        self.settings["deep_scan"], self.settings["cloud_lookup"] = deep, bool(self.cloud.get())
        paths.save_settings(self.settings)
        self.busy = True
        self.cancel_flag.clear()
        self.scan_btn.configure(text="Cancel scan", fg_color="gray30")
        self.log.configure(state="normal")
        self.log.delete("1.0", "end")
        self.log.configure(state="disabled")
        self.tabs.set("Scan")
        self._on_pct(0)
        threading.Thread(target=self._scan_worker, args=(d,), daemon=True).start()

    def _scan_worker(self, d):
        from . import report
        from .cli import cleanup_raw
        p = self._progress()
        try:
            if d["platform"] == "android":
                from .android_scan import AndroidScanner
                self.scanner = AndroidScanner(d["id"], self.settings, p)
            else:
                from .ios_scan import IOSScanner
                self.scanner = IOSScanner(d["id"], self.settings, p)
            r = self.scanner.scan(bool(self.settings["deep_scan"]))
            if self.cancel_flag.is_set():
                r.errors.append("The scan was cancelled before it finished.")
            p.step("Writing report")
            report.build(r)
            cleanup_raw(r, self.settings.get("keep_raw_backup", False))
            p.pct(100)
            p.log(f"Report saved: {r.report_html}")
            self.post("done", r)
        except Exception as e:
            p.log(traceback.format_exc())
            self.post("failed", str(e))

    def _on_failed(self, msg):
        self.busy = False
        self.scan_btn.configure(text="Start scan", fg_color=ACCENT)
        self._refresh_device()
        self.step.configure(text="Scan failed")
        messagebox.showerror(APP_NAME, f"The scan stopped:\n\n{msg}")

    def _on_done(self, r):
        self.busy = False
        self.result = r
        self.scan_btn.configure(text="Start scan", fg_color=ACCENT)
        self._refresh_device()
        self.step.configure(text="Scan complete")
        self._show_results()
        self.tabs.set("Results")
        webbrowser.open(r.report_html)

    def _show_results(self):
        from .report import CAT_LABEL, STATUS_LABEL, verdict
        r = self.result
        cls, title, sub = verdict(r)
        color = {"ok": "#22c55e", "warn": "#eab308", "danger": "#ef4444"}[cls]
        self.verdict.configure(text=f"{title} · {r.device.display}", text_color=color)
        fails = sum(1 for c in r.checks if c.status == "fail")
        self.verdict_sub.configure(text=f"{sub}  {r.apps_scanned} apps scanned against {r.ioc_total:,} indicators. "
                                        f"{fails} security check(s) failed. See the report for recommendations.")
        for w in self.res_list.winfo_children():
            w.destroy()
        self.check_vars.clear()
        if not r.findings:
            ctk.CTkLabel(self.res_list, text="Nothing to remove. ✔", text_color="#22c55e",
                         font=ctk.CTkFont(size=16)).pack(pady=30)
        for f in r.findings:
            card = ctk.CTkFrame(self.res_list, fg_color=("#f1f3f8", "#141b2d"))
            card.pack(fill="x", pady=4, padx=2)
            head = ctk.CTkFrame(card, fg_color="transparent")
            head.pack(fill="x", padx=10, pady=(8, 0))
            if f.removable and f.status not in ("removed",):
                v = tk.BooleanVar(value=f.recommended_removal and f.status == "found")
                self.check_vars[f.id] = v
                ctk.CTkCheckBox(head, text="", variable=v, width=24).pack(side="left")
            ctk.CTkLabel(head, text=f" {f.severity.upper()} ", fg_color=SEV_COLORS.get(f.severity, "gray40"),
                         corner_radius=6, text_color="white", font=ctk.CTkFont(size=11, weight="bold")).pack(side="left", padx=(0, 8))
            ctk.CTkLabel(head, text=f.title, font=ctk.CTkFont(size=14, weight="bold")).pack(side="left")
            ctk.CTkLabel(head, text=CAT_LABEL.get(f.category, f.category), text_color="gray60").pack(side="left", padx=10)
            if f.status != "found":
                ok = f.status == "removed"
                ctk.CTkLabel(head, text=STATUS_LABEL.get(f.status, f.status),
                             text_color="#22c55e" if ok else "#ef4444").pack(side="right")
            text = "\n".join("• " + x for x in f.reasons[:5])
            if f.status_note and f.status != "removed":
                text += f"\n→ {f.status_note}"
            ctk.CTkLabel(card, text=text, justify="left", anchor="w", wraplength=720,
                         text_color="gray75").pack(fill="x", padx=(44, 10), pady=(2, 8))
        self.rm_btn.configure(state="normal" if self.check_vars else "disabled")
        self.open_btn.configure(state="normal")
        self.dir_btn.configure(state="normal")

    def _open_report(self):
        if self.result:
            webbrowser.open(self.result.report_html)

    # -------------------------------------------------------------- removal
    def _remove_selected(self):
        r = self.result
        chosen = [f for f in r.findings if self.check_vars.get(f.id) and self.check_vars[f.id].get()]
        if not chosen:
            messagebox.showinfo(APP_NAME, "Tick the items you want to remove first.")
            return
        warn = ""
        if any(f.category == "stalkerware" for f in chosen):
            warn += ("\n\nSTALKERWARE: whoever installed it may be notified when it disappears. "
                     "If that could put you at risk, cancel and get advice first (stopstalkerware.org).")
        if any(f.category == "spyware" for f in chosen):
            warn += ("\n\nSPYWARE: removing it destroys evidence experts could use. Consider contacting "
                     "Amnesty Security Lab or Access Now before removing.")
        names = "\n".join(f"• {f.title}" for f in chosen[:12])
        if not messagebox.askyesno(APP_NAME, f"Remove these {len(chosen)} item(s) from the phone?\n\n{names}{warn}",
                                   icon="warning"):
            return
        for f in r.findings:
            if f.removable and f.status == "found" and f not in chosen and f.id in self.check_vars:
                f.status = "kept"
        self.rm_btn.configure(state="disabled", text="Removing...")
        self.busy = True

        def work():
            from . import report
            p = self._progress()
            p.step("Removing threats")
            for f in chosen:
                p.log(f"Removing {f.title}...")
                try:
                    self.scanner.remove(f)
                except Exception as e:
                    f.status, f.status_note = "failed", str(e)[:160]
                p.log(f"  → {f.status}: {f.status_note}")
            from pathlib import Path
            report.build(r, Path(r.report_dir))
            self.post("removed")
        threading.Thread(target=work, daemon=True).start()

    def _on_removed(self):
        self.busy = False
        self.rm_btn.configure(text="Remove selected")
        self._show_results()
        r = self.result
        ok = sum(1 for f in r.findings if f.status == "removed")
        bad = [f for f in r.findings if f.status in ("failed", "needs-user-action")]
        msg = f"{ok} item(s) removed. The report has been updated."
        if bad:
            msg += "\n\nNeeds your attention:\n" + "\n".join(f"• {f.title}: {f.status_note}" for f in bad)
        messagebox.showinfo(APP_NAME, msg)

    def report_callback_exception(self, exc, val, tb):
        text = "".join(traceback.format_exception(exc, val, tb))
        try:
            with open(paths.LOCAL / "error.log", "a", encoding="utf-8") as fh:
                fh.write(f"\n--- {time.ctime()}\n{text}")
        except OSError:
            pass
        self._on_log(text)

    def _close(self):
        if self.busy and not messagebox.askyesno(APP_NAME, "A scan is running. Quit anyway?"):
            return
        try:
            from .android_scan import Adb
            Adb().kill_server()
        except Exception:
            pass
        self.destroy()
        os._exit(0)


def _demo(app, mode):
    """Fills the window with fictional data for screenshots (PHONESENTRY_DEMO=scan|results)."""
    from .demo import threats_sample
    app._on_devices({"a:demo": {"platform": "android", "id": "demo", "state": "device",
                                "label": "Samsung Galaxy A-Series (demo)",
                                "sub": "Android 14 · patch 2024-03-01"}}, True)
    if mode == "results":
        app.result = threats_sample()
        app._show_results()
        app.tabs.set("Results")
        return
    for line in ["", "▶ Reading device information", "Device: Samsung Galaxy A-Series (demo) - Android 14, patch 2024-03-01",
                 "", "▶ Loading threat database", "11,494 indicators from 19 threat feeds", "",
                 "▶ Inspecting installed apps", "  hashed 25/96 apps", "  hashed 50/96 apps", "  hashed 96/96 apps",
                 "96 user-installed apps, 341 system apps", "", "▶ Security checks", "",
                 "▶ Matching against spyware & stalkerware indicators",
                 'Found a known suspicious app with ID "com.demo.syncservice" matching indicators from "DemoSpy"',
                 "Indicator matches: 1", "", "▶ Behavioural malware analysis", "3 apps flagged by behaviour", "",
                 "▶ Deep forensic scan: analysing with MVT", "  Running module DumpsysAccessibility...",
                 "  Found accessibility service: com.android.systemupdate.demo/.A11y (enabled)",
                 "  Running module DumpsysAppops...", "  Extracted 6160 running process threads"]:
        app._on_log(line)
    app.tabs.set("Scan")
    app.dev_state.configure(text="Android 14 · patch 2024-03-01\nScanning...", text_color="#60a5fa")
    app.step.configure(text="Deep forensic scan: analysing with MVT")
    app.bar.set(0.82)
    app.scan_btn.configure(text="Cancel scan", fg_color="gray30", state="normal")


def run():
    app = App()
    demo = os.environ.get("PHONESENTRY_DEMO")
    if demo:
        app.after(1500, lambda: _demo(app, demo))
    shot = os.environ.get("PHONESENTRY_SELFTEST")
    if shot:  # build check: screenshot the window, then quit
        def grab():
            from PIL import ImageGrab
            app.attributes("-topmost", True)
            app.update()
            time.sleep(0.5)
            x, y = app.winfo_rootx(), app.winfo_rooty()
            ImageGrab.grab((x, y, x + app.winfo_width(), y + app.winfo_height())).save(shot)
            app.destroy()
            os._exit(0)
        app.after(int(os.environ.get("PHONESENTRY_SELFTEST_DELAY", "7000")), grab)
    app.mainloop()
