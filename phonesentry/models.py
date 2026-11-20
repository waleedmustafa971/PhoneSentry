from dataclasses import asdict, dataclass, field
from typing import Any, Callable, Optional

# Severity order, most severe first.
CRITICAL, HIGH, MEDIUM, LOW, INFO = "critical", "high", "medium", "low", "info"
SEVERITY_RANK = {CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1, INFO: 0}

# Posture check status.
PASS, WARN, FAIL, UNKNOWN = "pass", "warn", "fail", "unknown"


@dataclass
class Finding:
    """One threat or suspicious item on the device."""
    id: str                    # stable key, e.g. "app:com.foo"
    title: str
    severity: str
    category: str              # spyware | stalkerware | malware | suspicious-app | profile | forensic
    reasons: list = field(default_factory=list)
    target: str = ""           # package name / bundle id / profile id the removal acts on
    target_kind: str = ""      # android-app | ios-app | ios-profile | ""
    removable: bool = False
    recommended_removal: bool = False
    details: dict = field(default_factory=dict)
    status: str = "found"      # found | removed | kept | failed | needs-user-action
    status_note: str = ""


@dataclass
class Check:
    """One security-posture check (bootloader, patch level, ...)."""
    name: str
    status: str
    value: str = ""
    advice: str = ""


@dataclass
class DeviceInfo:
    platform: str = ""         # android | ios
    serial: str = ""
    brand: str = ""
    manufacturer: str = ""
    model: str = ""            # marketing name
    model_code: str = ""
    os_name: str = ""
    os_version: str = ""
    build: str = ""
    security_patch: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def display(self) -> str:
        name = self.model or self.model_code or "Unknown device"
        if self.brand and not name.lower().startswith(self.brand.lower()):
            name = f"{self.brand} {name}"
        return name


@dataclass
class ScanResult:
    device: DeviceInfo
    started: str = ""
    finished: str = ""
    deep_scan: bool = False
    findings: list = field(default_factory=list)
    checks: list = field(default_factory=list)
    apps_scanned: int = 0
    system_apps: int = 0
    ioc_sets: list = field(default_factory=list)
    ioc_total: int = 0
    forensic: dict = field(default_factory=dict)   # MVT summary
    cloud: dict = field(default_factory=dict)
    actions: list = field(default_factory=list)
    errors: list = field(default_factory=list)
    report_dir: str = ""
    report_html: str = ""
    sample: bool = False       # demo data (website / screenshots), shown with a banner

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def threats(self):
        return [f for f in self.findings if f.severity in (CRITICAL, HIGH)]

    @property
    def suspicious(self):
        return [f for f in self.findings if f.severity in (MEDIUM, LOW)]


class Progress:
    """Thread-safe-ish callback bundle the scanners report through."""

    def __init__(self, log: Callable[[str], None] = print,
                 step: Callable[[str], None] = lambda s: None,
                 pct: Callable[[Optional[float]], None] = lambda p: None,
                 cancelled: Callable[[], bool] = lambda: False,
                 ask: Callable[[str], Optional[str]] = lambda kind: None):
        self.log, self.step, self.pct, self.cancelled, self.ask = log, step, pct, cancelled, ask
