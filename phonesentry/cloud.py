"""Optional hash-reputation lookups (VirusTotal, MalwareBazaar). Both need a
free API key the user enters in Settings; without keys this module does nothing."""
import time

import requests

UA = {"User-Agent": "PhoneSentry/1.0"}


class Reputation:
    def __init__(self, vt_key: str = "", mb_key: str = "", log=print):
        self.vt_key, self.mb_key, self.log = vt_key.strip(), mb_key.strip(), log
        self._last_vt = 0.0

    @property
    def enabled(self) -> bool:
        return bool(self.vt_key or self.mb_key)

    def lookup(self, sha256: str) -> dict:
        """Return {"verdict": malicious|suspicious|clean|unknown, "source", "name", "detections"}."""
        res = {"verdict": "unknown", "source": "", "name": "", "detections": 0}
        if self.mb_key:
            try:
                r = requests.post("https://mb-api.abuse.ch/api/v1/",
                                  data={"query": "get_info", "hash": sha256},
                                  headers={**UA, "Auth-Key": self.mb_key}, timeout=20)
                j = r.json()
                if j.get("query_status") == "ok" and j.get("data"):
                    d = j["data"][0]
                    return {"verdict": "malicious", "source": "MalwareBazaar",
                            "name": d.get("signature") or ", ".join(d.get("tags") or []) or "known malware",
                            "detections": 1}
            except (requests.RequestException, ValueError) as e:
                self.log(f"MalwareBazaar lookup failed: {e}")
        if self.vt_key:
            # Free tier: 4 requests/minute.
            wait = 15.5 - (time.time() - self._last_vt)
            if wait > 0:
                time.sleep(wait)
            self._last_vt = time.time()
            try:
                r = requests.get(f"https://www.virustotal.com/api/v3/files/{sha256}",
                                 headers={**UA, "x-apikey": self.vt_key}, timeout=20)
                if r.status_code == 404:
                    return res
                if r.status_code == 401:
                    self.log("VirusTotal rejected the API key")
                    self.vt_key = ""
                    return res
                if r.status_code == 429:
                    self.log("VirusTotal quota reached; skipping further lookups")
                    self.vt_key = ""
                    return res
                a = r.json()["data"]["attributes"]
                stats = a.get("last_analysis_stats", {})
                mal = int(stats.get("malicious", 0))
                name = (a.get("popular_threat_classification") or {}).get("suggested_threat_label", "")
                verdict = "malicious" if mal >= 4 else "suspicious" if mal >= 1 else "clean"
                return {"verdict": verdict, "source": "VirusTotal", "name": name, "detections": mal}
            except (requests.RequestException, ValueError, KeyError) as e:
                self.log(f"VirusTotal lookup failed: {e}")
        return res
