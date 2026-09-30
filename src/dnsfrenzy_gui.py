"""DNSFrenzy - Windows GUI (PyQt5).

Pings DNS servers in parallel, applies the fastest one, verifies it.
"""
from __future__ import annotations

import ctypes
import json
import queue
import subprocess
import sys
import threading
import time
import traceback
import zipfile
from concurrent.futures import ThreadPoolExecutor, as_completed
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Optional

from PyQt5.QtCore import (
    Qt, QTimer, QPropertyAnimation, QEasingCurve, QEvent,
)
from PyQt5.QtGui import QColor, QFont, QIcon, QPainter, QPixmap, QBrush, QPen
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QFrame, QLabel, QPushButton,
    QVBoxLayout, QHBoxLayout, QGridLayout, QTableWidget, QTableWidgetItem,
    QHeaderView, QAbstractItemView, QMenu, QFileDialog, QSystemTrayIcon,
    QProgressBar,
)

try:
    import winreg
    HAS_WINREG = True
except Exception:
    HAS_WINREG = False


def _find_root() -> Optional[Path]:
    cands = []
    try:
        here = Path(__file__).resolve().parent
        cands.extend([here, here.parent])
    except Exception:
        pass
    if getattr(sys, "frozen", False):
        try:
            exe_dir = Path(sys.executable).resolve().parent
            cands.extend([exe_dir, exe_dir.parent])
        except Exception:
            pass
    cands.extend([Path("C:/DNSFrenzyWindows"), Path("C:/DNSFrenzy")])
    for cand in cands:
        try:
            if (cand / "config" / "servers.txt").is_file():
                return cand
        except OSError:
            continue
    return None


ROOT = _find_root()
if ROOT is None:
    print("DNSFrenzy: config/servers.txt not found.")
    sys.exit(1)

CONFIG_DIR = ROOT / "config"
DATA_DIR = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

SERVER_FILE = CONFIG_DIR / "servers.txt"
SETTINGS_FILE = DATA_DIR / "settings.json"
STATE_FILE = DATA_DIR / "state.json"
HISTORY_FILE = DATA_DIR / "history.json"
BLACKLIST_FILE = DATA_DIR / "blacklist.json"
LOG_FILE = DATA_DIR / "dnsfrenzy.log"


P = {
    "bg":         "#0a1220",
    "bg_alt":     "#0d1626",
    "surface":    "#111c30",
    "surface2":   "#172540",
    "surface3":   "#20324f",
    "border":     "#2a3f5c",
    "border_hi":  "#3d567a",
    "fg":         "#e8eef7",
    "fg_dim":     "#a3b4cc",
    "fg_sub":     "#7c8da8",
    "accent":     "#4a9eff",
    "accent_hi":  "#6bb3ff",
    "accent_dn":  "#2d7ce0",
    "accent_fg":  "#081428",
    "good":       "#2ecc71",
    "good_bg":    "#0e3424",
    "good_bg_hi": "#175132",
    "warn":       "#f0b429",
    "warn_dark":  "#a37a1a",
    "warn_bg":    "#3a2a0c",
    "bad":        "#ff5c5c",
    "bad_bg":     "#3a1015",
    "purple":     "#a78bfa",
    "purple_bg":  "#1e2952",
    "purple_hi":  "#2b3a75",
    "row_2nd":    "#172547",
    "row_2nd_hi": "#22356b",
    "auto_bg":    "#0e3424",
}

DEFAULT_SETTINGS = {
    "smart_mix": True,
    "fallback_chain": True,
    "blacklist_threshold": 3,
    "blacklist_duration": 300,
    "fallback_primary": "1.1.1.1",
    "fallback_secondary": "1.0.0.1",
    "auto_interval_sec": 60,
}

FAIL = 99999
SPOOF_MS = 5
FALLBACK_NAME = "Fallback"

_log_lock = threading.Lock()


def log(tag: str, msg: str) -> None:
    try:
        with _log_lock:
            line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {tag:<8} {msg}\n"
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line)
            try:
                lines = LOG_FILE.read_text(encoding="utf-8").splitlines()
                if len(lines) > 500:
                    LOG_FILE.write_text("\n".join(lines[-500:]) + "\n", encoding="utf-8")
            except OSError:
                pass
    except OSError:
        pass


def load_json(path: Path, default):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path: Path, obj) -> None:
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(obj, f, indent=2)
    except OSError:
        pass


@dataclass
class Server:
    name: str
    primary: str
    secondary: str


def read_servers() -> list[Server]:
    if not SERVER_FILE.is_file():
        return []
    out: list[Server] = []
    for raw in SERVER_FILE.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = [p.strip() for p in line.split("|")]
        if len(parts) >= 3 and parts[0] and parts[1]:
            out.append(Server(parts[0], parts[1], parts[2]))
    return out


_iphlpapi = ctypes.WinDLL("iphlpapi")
_ws2_32 = ctypes.WinDLL("ws2_32")


class _IP_OPTION_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Ttl", ctypes.c_ubyte),
        ("Tos", ctypes.c_ubyte),
        ("Flags", ctypes.c_ubyte),
        ("OptionsSize", ctypes.c_ubyte),
        ("OptionsData", ctypes.c_void_p),
    ]


class _ICMP_ECHO_REPLY(ctypes.Structure):
    _fields_ = [
        ("Address", wintypes.DWORD),
        ("Status", wintypes.ULONG),
        ("RoundTripTime", wintypes.ULONG),
        ("DataSize", wintypes.USHORT),
        ("Reserved", wintypes.USHORT),
        ("Data", ctypes.c_void_p),
        ("Options", _IP_OPTION_INFORMATION),
    ]


_iphlpapi.IcmpCreateFile.restype = wintypes.HANDLE
_iphlpapi.IcmpCreateFile.argtypes = []
_iphlpapi.IcmpCloseHandle.restype = wintypes.BOOL
_iphlpapi.IcmpCloseHandle.argtypes = [wintypes.HANDLE]
_iphlpapi.IcmpSendEcho.restype = wintypes.DWORD
_iphlpapi.IcmpSendEcho.argtypes = [
    wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.WORD,
    ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
]
_ws2_32.inet_addr.restype = wintypes.ULONG
_ws2_32.inet_addr.argtypes = [ctypes.c_char_p]

_INVALID_HANDLE = ctypes.c_void_p(-1).value
_INADDR_NONE = 0xFFFFFFFF


def ping_once(ip: str, timeout_ms: int = 700) -> Optional[int]:
    handle = _iphlpapi.IcmpCreateFile()
    if not handle or handle == _INVALID_HANDLE:
        return None
    try:
        addr = _ws2_32.inet_addr(ip.encode("ascii", "ignore"))
        if addr == _INADDR_NONE:
            return None
        payload = b"dnsfrenzy-ping-payload" * 2
        reply_size = ctypes.sizeof(_ICMP_ECHO_REPLY) + len(payload) + 32
        reply_buf = ctypes.create_string_buffer(reply_size)
        ret = _iphlpapi.IcmpSendEcho(
            handle, addr, payload, len(payload), None,
            reply_buf, reply_size, timeout_ms,
        )
        if ret == 0:
            return None
        reply = ctypes.cast(reply_buf, ctypes.POINTER(_ICMP_ECHO_REPLY)).contents
        if reply.Status != 0:
            return None
        return int(reply.RoundTripTime)
    except Exception:
        return None
    finally:
        try:
            _iphlpapi.IcmpCloseHandle(handle)
        except Exception:
            pass


def measure(server: Server, samples: int = 2, timeout_ms: int = 700) -> int:
    times: list[int] = []
    for _ in range(samples):
        t = ping_once(server.primary, timeout_ms)
        if t is not None:
            times.append(t)
        time.sleep(0.03)
    if not times:
        return FAIL
    times.sort()
    return times[len(times) // 2]


CREATE_NO_WINDOW = 0x08000000


def _ps(command: str, timeout: int = 15) -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
            capture_output=True, text=True, timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )
        return r.stdout or ""
    except Exception:
        return ""


def get_current_dns() -> list[str]:
    out = _ps(
        "Get-DnsClientServerAddress -AddressFamily IPv4 | "
        "Where-Object { $_.ServerAddresses } | "
        "Select-Object -First 1 -ExpandProperty ServerAddresses"
    )
    return [l.strip() for l in out.splitlines() if l.strip()]


def apply_dns(primary: str, secondary: str) -> None:
    ps = (
        "Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object { "
        "Set-DnsClientServerAddress -InterfaceAlias $_.Name "
        f"-ServerAddresses @('{primary}','{secondary}') "
        "-ErrorAction SilentlyContinue }; "
        "ipconfig /flushdns | Out-Null"
    )
    _ps(ps, timeout=20)


def verify_dns() -> bool:
    ip = _ps(
        "(Resolve-DnsName digikala.com -Type A -DnsOnly "
        "-ErrorAction SilentlyContinue -QuickTimeout | "
        "Where-Object { $_.IPAddress } | "
        "Select-Object -First 1).IPAddress"
    ).strip()
    return bool(ip) and not ip.startswith("198.20.")


RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_NAME = "DNSFrenzy"


def get_autostart() -> bool:
    if not HAS_WINREG:
        return False
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            v, _ = winreg.QueryValueEx(k, RUN_NAME)
            return bool(v)
    except OSError:
        return False


def set_autostart(on: bool) -> None:
    if not HAS_WINREG:
        return
    try:
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, RUN_KEY) as k:
            if on:
                if getattr(sys, "frozen", False):
                    cmd = f'"{sys.executable}"'
                else:
                    cmd = f'"{sys.executable}" "{Path(__file__).resolve()}"'
                winreg.SetValueEx(k, RUN_NAME, 0, winreg.REG_SZ, cmd)
            else:
                try:
                    winreg.DeleteValue(k, RUN_NAME)
                except OSError:
                    pass
    except OSError:
        pass


class _PROCESS_MEMORY_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("PageFaultCount", wintypes.DWORD),
        ("PeakWorkingSetSize", ctypes.c_size_t),
        ("WorkingSetSize", ctypes.c_size_t),
        ("QuotaPeakPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPagedPoolUsage", ctypes.c_size_t),
        ("QuotaPeakNonPagedPoolUsage", ctypes.c_size_t),
        ("QuotaNonPagedPoolUsage", ctypes.c_size_t),
        ("PagefileUsage", ctypes.c_size_t),
        ("PeakPagefileUsage", ctypes.c_size_t),
    ]


def get_process_mem_mb() -> float:
    try:
        psapi = ctypes.WinDLL("psapi")
        kernel32 = ctypes.WinDLL("kernel32")
        h = kernel32.GetCurrentProcess()
        counters = _PROCESS_MEMORY_COUNTERS()
        counters.cb = ctypes.sizeof(counters)
        if psapi.GetProcessMemoryInfo(h, ctypes.byref(counters), counters.cb):
            return counters.WorkingSetSize / (1024.0 * 1024.0)
    except Exception:
        pass
    return -1.0


def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> None:
    params = " ".join(f'"{a}"' for a in sys.argv)
    ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, params, None, 1)


PUMP_INTERVAL_MS = 40


def _excepthook(exc_type, exc_val, exc_tb):
    text = "".join(traceback.format_exception(exc_type, exc_val, exc_tb))
    log("EXC", text.replace("\n", " | "))


class App(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self._post: queue.Queue = queue.Queue()
        self._pump_running = True

        self.setWindowTitle("DNSFrenzy")
        self.setMinimumSize(540, 620)
        self.resize(680, 800)
        self._center_window(680, 800)
        self.setWindowOpacity(0.0)

        self.settings = {**DEFAULT_SETTINGS, **(load_json(SETTINGS_FILE, {}) or {})}
        self.persisted = load_json(STATE_FILE, {}) or {}
        self.history: dict[str, list[int]] = {}
        for k, v in (load_json(HISTORY_FILE, {}) or {}).items():
            if isinstance(v, list):
                self.history[k] = [int(x) for x in v][-20:]
        self.blacklist: dict[str, int] = {}
        now = int(time.time())
        for k, v in (load_json(BLACKLIST_FILE, {}) or {}).items():
            try:
                iv = int(v)
                if iv > now:
                    self.blacklist[str(k)] = iv
            except (TypeError, ValueError):
                pass

        self.servers: list[Server] = []
        self.fastest: Optional[Server] = None
        self.second: Optional[Server] = None
        self.busy = False
        self.mix_on = bool(self.persisted.get("mix_on", True))
        self.auto_on = bool(self.persisted.get("auto_on", False))
        self.exiting = False

        self._pump_timer: Optional[QTimer] = None
        self._mem_timer: Optional[QTimer] = None
        self._pulse_timer: Optional[QTimer] = None
        self._flash_timer: Optional[QTimer] = None
        self._scan_timer: Optional[QTimer] = None
        self._auto_timer: Optional[QTimer] = None
        self._fade_anim: Optional[QPropertyAnimation] = None
        self._pulse_on = False
        self._pulse_phase = 0
        self._pulse_color = P["warn"]
        self._flash_row = -1
        self._flash_count = 0
        self._scan_phase = 0.0
        self._row_by_name: dict[str, int] = {}
        self._row_tag: dict[str, str] = {}
        self.tray_icon: Optional[QSystemTrayIcon] = None
        self._tray_auto = None
        self._tray_startup = None

        self._build_ui()
        self._apply_window_icon()
        self._reload_servers()
        self._refresh_active()
        self._update_mix_visual()
        self._update_auto_visual()
        self._set_status("ready", P["fg_dim"])

        self._pump_timer = QTimer(self)
        self._pump_timer.timeout.connect(self._pump)
        self._pump_timer.start(PUMP_INTERVAL_MS)

        self._mem_timer = QTimer(self)
        self._mem_timer.timeout.connect(self._update_mem)
        self._mem_timer.start(2000)

        QTimer.singleShot(120, self._start_tray)
        QTimer.singleShot(160, self._post_startup)
        QTimer.singleShot(200, self._start_fade_in)

        log("START", f"launch mix={self.mix_on} auto={self.auto_on} admin={is_admin()} tray=Qt")

    def _center_window(self, w: int, h: int) -> None:
        scr = QApplication.primaryScreen()
        if scr is None:
            return
        geo = scr.availableGeometry()
        w = min(w, max(400, geo.width() - 80))
        h = min(h, max(400, geo.height() - 120))
        self.resize(w, h)
        x = max(geo.x(), geo.x() + (geo.width() - w) // 2)
        y = max(geo.y(), geo.y() + (geo.height() - h) // 2 - 30)
        self.move(x, y)

    def _make_icon_pixmap(self, size: int) -> QPixmap:
        pix = QPixmap(size, size)
        pix.fill(Qt.transparent)
        p = QPainter(pix)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        p.setBrush(QBrush(QColor(88, 166, 255)))
        p.drawEllipse(1, 1, size - 2, size - 2)
        p.setBrush(Qt.NoBrush)
        p.setPen(QPen(QColor(13, 17, 23), max(1, size // 10)))
        inset = int(size * 0.34)
        p.drawEllipse(inset, inset, size - inset * 2, size - inset * 2)
        p.end()
        return pix

    def _apply_window_icon(self) -> None:
        try:
            self.setWindowIcon(QIcon(self._make_icon_pixmap(64)))
        except Exception as e:
            log("ICON", str(e))

    # ------------------------------------------------------- animation

    def _start_fade_in(self) -> None:
        try:
            self._fade_anim = QPropertyAnimation(self, b"windowOpacity", self)
            self._fade_anim.setDuration(280)
            self._fade_anim.setStartValue(0.0)
            self._fade_anim.setEndValue(1.0)
            self._fade_anim.setEasingCurve(QEasingCurve.OutCubic)
            self._fade_anim.start()
        except Exception as e:
            log("FADE", str(e))
            self.setWindowOpacity(1.0)

    def _pulse_start(self) -> None:
        if self._pulse_on:
            return
        self._pulse_on = True
        self._pulse_phase = 0
        if self._pulse_timer is None:
            self._pulse_timer = QTimer(self)
            self._pulse_timer.timeout.connect(self._pulse_tick)
        self._pulse_timer.start(400)

    def _pulse_stop(self) -> None:
        self._pulse_on = False
        if self._pulse_timer is not None:
            self._pulse_timer.stop()

    def _pulse_tick(self) -> None:
        if not self._pulse_on or self.exiting:
            return
        phase = self._pulse_phase % 2
        color = self._pulse_color if phase == 0 else P["warn_dark"]
        self.status_chip.setStyleSheet(self._chip_qss(color))
        self._pulse_phase += 1

    def _flash_winner(self) -> None:
        if self.fastest is None or self.fastest.name == FALLBACK_NAME:
            return
        row = self._row_by_name.get(self.fastest.name)
        if row is None:
            return
        self._flash_row = row
        self._flash_count = 0
        if self._flash_timer is None:
            self._flash_timer = QTimer(self)
            self._flash_timer.timeout.connect(self._flash_step)
        self._flash_timer.start(160)
        self._flash_step()

    def _flash_step(self) -> None:
        if self.exiting or self._flash_row < 0:
            if self._flash_timer is not None:
                self._flash_timer.stop()
            return
        hi = self._flash_count % 2 == 0
        bg = P["good_bg_hi"] if hi else P["good_bg"]
        self._set_row_bg(self._flash_row, bg)
        self._flash_count += 1
        if self._flash_count >= 6:
            if self._flash_timer is not None:
                self._flash_timer.stop()
            self._set_row_bg(self._flash_row, P["good_bg"])

    def _scan_bar_start(self) -> None:
        self._scan_phase = 0.0
        if self._scan_timer is None:
            self._scan_timer = QTimer(self)
            self._scan_timer.timeout.connect(self._scan_tick)
        self._scan_timer.start(30)

    def _scan_stop(self) -> None:
        if self._scan_timer is not None:
            self._scan_timer.stop()
        self._set_progress(0.0)

    def _scan_tick(self) -> None:
        if self.exiting or not self.busy:
            return
        self._scan_phase = (self._scan_phase + 0.04) % 1.0
        self._set_progress(self._scan_phase)

    # ------------------------------------------------------- pump

    def _post_call(self, fn: Callable[[], None]) -> None:
        self._post.put(fn)

    def _pump(self) -> None:
        if not self._pump_running:
            return
        for _ in range(200):
            try:
                fn = self._post.get_nowait()
            except queue.Empty:
                break
            try:
                fn()
            except Exception as e:
                log("PUMP", f"{type(e).__name__}: {e}")

    def _update_mem(self) -> None:
        if self.exiting:
            return
        mb = get_process_mem_mb()
        self.val_mem.setText(f"{mb:.0f} MB" if mb >= 0 else "-")

    def _post_startup(self) -> None:
        try:
            self.raise_()
            self.activateWindow()
        except Exception:
            pass
        if self.auto_on:
            QTimer.singleShot(500, self._auto_cycle)

    # ------------------------------------------------------- styling

    def _chip_qss(self, color: str) -> str:
        return (
            "QLabel {"
            f"background: {P['surface2']};"
            f"color: {color};"
            f"border: 1px solid {P['border']};"
            "border-radius: 10px;"
            "padding: 5px 14px;"
            "font-family: 'Segoe UI Semibold';"
            "font-size: 10px;"
            "letter-spacing: 1px;"
            "}"
        )

    def _kv_qss(self, color: str) -> str:
        return f"QLabel {{ color: {color}; background: transparent; }}"

    def _btn_qss(self, role: str, align: str = "center") -> str:
        palette = {
            "primary":   (P['accent'],    P['accent_fg'], P['accent_dn'],   P['accent_hi'],  P['accent_dn'],   P['accent_dn']),
            "secondary": (P['surface2'],  P['fg'],        P['border'],      P['surface3'],   P['border_hi'],   P['surface3']),
            "auto_on":   (P['auto_bg'],   P['good'],      P['good_bg_hi'],  P['good_bg_hi'], P['good_bg_hi'],  P['good_bg']),
            "auto_off":  (P['surface2'],  P['fg'],        P['border'],      P['surface3'],   P['border_hi'],   P['surface3']),
            "mix_on":    (P['purple_bg'], P['purple'],    P['purple_hi'],   P['purple_hi'],  P['purple_hi'],   P['purple_bg']),
            "mix_off":   (P['surface2'],  P['fg_dim'],    P['border'],      P['surface3'],   P['border_hi'],   P['surface3']),
        }
        bg, fg, bd, hov, hov_bd, pressed = palette[role]
        return (
            "QPushButton {"
            f"background: {bg};"
            f"color: {fg};"
            f"border: 1px solid {bd};"
            "border-radius: 10px;"
            "padding: 0 16px;"
            "font-family: 'Segoe UI Semibold';"
            "font-size: 12px;"
            f"text-align: {align};"
            "}"
            "QPushButton:hover {"
            f"background: {hov};"
            f"border: 1px solid {hov_bd};"
            "}"
            "QPushButton:pressed {"
            f"background: {pressed};"
            f"border: 1px solid {P['border_hi']};"
            "}"
            "QPushButton:disabled {"
            f"background: {P['surface']};"
            f"color: {P['fg_sub']};"
            f"border: 1px solid {P['border']};"
            "}"
        )


    def _menu_qss(self) -> str:
        return (
            "QMenu {"
            f"background: {P['surface']};"
            f"color: {P['fg']};"
            f"border: 1px solid {P['border']};"
            "font-family: 'Segoe UI';"
            "font-size: 11px;"
            "padding: 6px;"
            "}"
            "QMenu::item {"
            "padding: 7px 26px 7px 14px;"
            "border-radius: 5px;"
            "}"
            "QMenu::item:selected {"
            f"background: {P['accent']};"
            f"color: {P['accent_fg']};"
            "}"
            "QMenu::separator {"
            f"background: {P['border']};"
            "height: 1px;"
            "margin: 5px 10px;"
            "}"
        )


    def _table_qss(self) -> str:
        return (
            "QTableWidget {"
            f"background: {P['surface']};"
            f"color: {P['fg']};"
            f"border: 1px solid {P['border']};"
            "gridline-color: transparent;"
            "font-family: 'Segoe UI';"
            "font-size: 12px;"
            "outline: none;"
            "}"
            "QTableWidget::item {"
            f"background: {P['surface']};"
            f"color: {P['fg']};"
            "padding: 8px 12px;"
            "border: none;"
            "}"
            "QTableWidget::item:selected {"
            f"background: {P['surface3']};"
            f"color: {P['fg']};"
            "}"
            "QHeaderView::section {"
            f"background: {P['bg']};"
            f"color: {P['fg_sub']};"
            "border: none;"
            f"border-bottom: 1px solid {P['border']};"
            "padding: 10px 12px;"
            "font-family: 'Segoe UI Semibold';"
            "font-size: 10px;"
            "letter-spacing: 1px;"
            "}"
            "QTableCornerButton::section {"
            f"background: {P['bg']};"
            "border: none;"
            "}"
            "QScrollBar:vertical {"
            f"background: {P['surface']};"
            "width: 12px;"
            "margin: 0;"
            "border: none;"
            f"border-left: 1px solid {P['surface2']};"
            "}"
            "QScrollBar::handle:vertical {"
            f"background: {P['border']};"
            "min-height: 28px;"
            "border-radius: 4px;"
            "margin: 3px;"
            "}"
            "QScrollBar::handle:vertical:hover {"
            f"background: {P['accent']};"
            "}"
            "QScrollBar::handle:vertical:pressed {"
            f"background: {P['accent_hi']};"
            "}"
            "QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {"
            "height: 0;"
            "background: none;"
            "border: none;"
            "}"
            "QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {"
            "background: none;"
            "}"
            "QScrollBar:horizontal {"
            f"background: {P['surface']};"
            "height: 12px;"
            "margin: 0;"
            "border: none;"
            f"border-top: 1px solid {P['surface2']};"
            "}"
            "QScrollBar::handle:horizontal {"
            f"background: {P['border']};"
            "min-width: 28px;"
            "border-radius: 4px;"
            "margin: 3px;"
            "}"
            "QScrollBar::handle:horizontal:hover {"
            f"background: {P['accent']};"
            "}"
            "QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {"
            "width: 0;"
            "background: none;"
            "border: none;"
            "}"
            "QScrollBar::add-page:horizontal, QScrollBar::sub-page:horizontal {"
            "background: none;"
            "}"
        )



    def _kv(self, grid: QGridLayout, row: int, key: str, default: str, small: bool) -> QLabel:
        k = QLabel(key)
        k.setFont(QFont("Segoe UI Semibold", 9))
        k.setStyleSheet(f"QLabel {{ color: {P['fg_sub']}; background: transparent; letter-spacing: 1px; }}")
        v = QLabel(default)
        v.setFont(QFont("Consolas", 10 if small else 11))
        v.setStyleSheet(self._kv_qss(P['fg']))
        grid.addWidget(k, row, 0, Qt.AlignLeft | Qt.AlignVCenter)
        grid.addWidget(v, row, 1, Qt.AlignLeft | Qt.AlignVCenter)
        return v


    def _build_ui(self) -> None:
        central = QWidget(self)
        central.setStyleSheet(f"QWidget {{ background: {P['bg']}; }}")
        self.setCentralWidget(central)
        outer = QVBoxLayout(central)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        accent = QFrame()
        accent.setFixedHeight(3)
        accent.setStyleSheet(f"QFrame {{ background: {P['accent']}; }}")
        outer.addWidget(accent)

        header = QFrame()
        header.setFixedHeight(96)
        header.setStyleSheet(
            f"QFrame {{ background: {P['surface']}; border-bottom: 1px solid {P['border']}; }}")
        hl = QHBoxLayout(header)
        hl.setContentsMargins(22, 0, 22, 0)
        hl.setSpacing(0)

        diamond = QLabel("\u25C6")
        diamond.setFont(QFont("Segoe UI", 28))
        diamond.setStyleSheet(f"QLabel {{ color: {P['accent']}; background: transparent; }}")
        hl.addWidget(diamond, 0, Qt.AlignVCenter)

        title_col = QVBoxLayout()
        title_col.setContentsMargins(14, 22, 0, 20)
        title_col.setSpacing(0)
        title = QLabel("DNSFrenzy")
        title.setFont(QFont("Segoe UI Semibold", 20))
        title.setStyleSheet(f"QLabel {{ color: {P['fg']}; background: transparent; }}")
        subtitle = QLabel("Fastest DNS auto-switcher")
        subtitle.setFont(QFont("Segoe UI", 11))
        subtitle.setStyleSheet(f"QLabel {{ color: {P['fg_dim']}; background: transparent; }}")
        title_col.addWidget(title)
        title_col.addWidget(subtitle)
        hl.addLayout(title_col)
        hl.addStretch(1)

        self.status_chip = QLabel("  READY  ")
        self.status_chip.setAlignment(Qt.AlignCenter)
        self.status_chip.setStyleSheet(self._chip_qss(P["fg_dim"]))
        hl.addWidget(self.status_chip, 0, Qt.AlignVCenter)
        outer.addWidget(header)

        body = QWidget()
        body.setStyleSheet(f"QWidget {{ background: {P['bg']}; }}")
        body_l = QVBoxLayout(body)
        body_l.setContentsMargins(18, 14, 18, 8)
        body_l.setSpacing(8)

        tb = QHBoxLayout()
        tb.setSpacing(0)
        lbl_sec = QLabel("SERVERS")
        lbl_sec.setFont(QFont("Segoe UI Semibold", 10))
        lbl_sec.setStyleSheet(
            f"QLabel {{ color: {P['fg_dim']}; background: transparent; letter-spacing: 2px; }}")
        tb.addWidget(lbl_sec)
        tb.addStretch(1)
        self.lbl_count = QLabel("")
        self.lbl_count.setFont(QFont("Segoe UI", 10))
        self.lbl_count.setStyleSheet(f"QLabel {{ color: {P['fg_sub']}; background: transparent; }}")
        tb.addWidget(self.lbl_count)
        body_l.addLayout(tb)

        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["SERVER", "LATENCY", "AVG", "STATUS", "IP"])
        self.table.verticalHeader().setVisible(False)
        self.table.verticalHeader().setDefaultSectionSize(30)
        self.table.setShowGrid(False)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setFocusPolicy(Qt.NoFocus)
        self.table.setStyleSheet(self._table_qss())
        self.table.setWordWrap(False)
        hh = self.table.horizontalHeader()
        hh.setHighlightSections(False)
        hh.setStretchLastSection(False)
        hh.setSectionResizeMode(0, QHeaderView.Stretch)
        hh.setSectionResizeMode(1, QHeaderView.Fixed)
        hh.setSectionResizeMode(2, QHeaderView.Fixed)
        hh.setSectionResizeMode(3, QHeaderView.Fixed)
        hh.setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.setColumnWidth(1, 100)
        self.table.setColumnWidth(2, 80)
        self.table.setColumnWidth(3, 80)
        self.table.setContextMenuPolicy(Qt.CustomContextMenu)
        self.table.customContextMenuRequested.connect(self._on_table_context_menu)
        self.table.doubleClicked.connect(self._on_table_double)
        self.table.setMinimumHeight(260)
        body_l.addWidget(self.table, 1)

        self.progress = QProgressBar()
        self.progress.setFixedHeight(3)
        self.progress.setTextVisible(False)
        self.progress.setRange(0, 1000)
        self.progress.setValue(0)
        self.progress.setStyleSheet(
            "QProgressBar {"
            f"background: {P['surface2']};"
            "border: none;"
            "border-radius: 1px;"
            "}"
            "QProgressBar::chunk {"
            f"background: {P['accent']};"
            "border-radius: 1px;"
            "}"
        )
        body_l.addWidget(self.progress)

        outer.addWidget(body, 1)

        bottom = QWidget()
        bottom.setStyleSheet(f"QWidget {{ background: {P['bg']}; }}")
        bl = QVBoxLayout(bottom)
        bl.setContentsMargins(18, 6, 18, 14)
        bl.setSpacing(8)

        self.btn_mix = QPushButton("")
        self.btn_mix.setFixedHeight(38)
        self.btn_mix.setCursor(Qt.PointingHandCursor)
        self.btn_mix.clicked.connect(self._toggle_mix)
        bl.addWidget(self.btn_mix)

        info = QFrame()
        info.setFixedHeight(112)
        info.setStyleSheet(
            f"QFrame {{ background: {P['surface']}; "
            f"border: 1px solid {P['border']}; border-radius: 10px; }}")
        il = QHBoxLayout(info)
        il.setContentsMargins(18, 14, 18, 14)
        il.setSpacing(28)

        left_col = QGridLayout()
        left_col.setHorizontalSpacing(14)
        left_col.setVerticalSpacing(6)
        self.val_active = self._kv(left_col, 0, "ACTIVE", "-", small=False)
        self.val_fastest = self._kv(left_col, 1, "FASTEST", "-", small=False)
        self.val_second = self._kv(left_col, 2, "RUNNER-UP", "-", small=False)
        left_col.setColumnStretch(1, 1)

        right_col = QGridLayout()
        right_col.setHorizontalSpacing(14)
        right_col.setVerticalSpacing(6)
        self.val_last = self._kv(right_col, 0, "LAST", "never", small=True)
        self.val_verify = self._kv(right_col, 1, "VERIFY", "-", small=True)
        self.val_mem = self._kv(right_col, 2, "MEM", "-", small=True)
        right_col.setColumnStretch(1, 1)

        il.addLayout(left_col, 1)
        il.addLayout(right_col, 1)
        bl.addWidget(info)

        actions = QHBoxLayout()
        actions.setSpacing(12)

        self.btn_test = QPushButton("Run test")
        self.btn_test.setFixedHeight(44)
        self.btn_test.setCursor(Qt.PointingHandCursor)
        self.btn_test.setStyleSheet(self._btn_qss("primary"))
        self.btn_test.clicked.connect(lambda: self._run_test())

        self.btn_apply = QPushButton("Apply fastest")
        self.btn_apply.setFixedHeight(44)
        self.btn_apply.setCursor(Qt.PointingHandCursor)
        self.btn_apply.setStyleSheet(self._btn_qss("secondary"))
        self.btn_apply.clicked.connect(lambda: self._run_apply())

        self.btn_auto = QPushButton("Auto: OFF")
        self.btn_auto.setFixedHeight(44)
        self.btn_auto.setCursor(Qt.PointingHandCursor)
        self.btn_auto.clicked.connect(self._toggle_auto)

        actions.addWidget(self.btn_test, 1)
        actions.addWidget(self.btn_apply, 1)
        actions.addWidget(self.btn_auto, 1)
        bl.addLayout(actions)

        outer.addWidget(bottom)

        self._set_busy(False)


    def _reload_servers(self) -> None:
        self.servers = read_servers()
        self._rebuild_table()

    def _new_cell(self, text: str) -> QTableWidgetItem:
        item = QTableWidgetItem(text)
        item.setFlags(Qt.ItemIsEnabled | Qt.ItemIsSelectable)
        item.setForeground(QColor(P["fg"]))
        item.setBackground(QColor(P["surface"]))
        return item

    def _rebuild_table(self) -> None:
        self.table.setRowCount(0)
        self._row_by_name.clear()
        self._row_tag.clear()

        for s in self.servers:
            row = self.table.rowCount()
            self.table.insertRow(row)
            self.table.setRowHeight(row, 34)
            self._row_by_name[s.name] = row
            self._row_tag[s.name] = ""
            self.table.setItem(row, 0, self._new_cell(s.name))
            self.table.setItem(row, 1, self._new_cell("-"))
            self.table.setItem(row, 2, self._new_cell(self._avg_text(s.name)))
            self.table.setItem(row, 3, self._new_cell(""))
            self.table.setItem(row, 4, self._new_cell(s.primary))

        self.lbl_count.setText(f"{len(self.servers)} servers")
        self._highlight_top2()

    def _avg_text(self, name: str) -> str:
        h = self.history.get(name)
        if not h:
            return "-"
        return f"{int(sum(h) / len(h))} ms"

    def _set_row_values(self, name: str, lat: Optional[str] = None,
                        avg: Optional[str] = None, st: Optional[str] = None,
                        ip: Optional[str] = None) -> None:
        row = self._row_by_name.get(name)
        if row is None:
            return
        if lat is not None:
            it = self.table.item(row, 1)
            if it: it.setText(lat)
        if avg is not None:
            it = self.table.item(row, 2)
            if it: it.setText(avg)
        if st is not None:
            it = self.table.item(row, 3)
            if it: it.setText(st)
        if ip is not None:
            it = self.table.item(row, 4)
            if it: it.setText(ip)

    def _set_row_bg(self, row: int, hex_color: str) -> None:
        c = QColor(hex_color)
        for col in range(self.table.columnCount()):
            it = self.table.item(row, col)
            if it is not None:
                it.setBackground(c)

    def _set_row_fg(self, row: int, hex_color: str) -> None:
        c = QColor(hex_color)
        for col in range(self.table.columnCount()):
            it = self.table.item(row, col)
            if it is not None:
                it.setForeground(c)

    def _set_row_tag(self, name: str, tag: str) -> None:
        row = self._row_by_name.get(name)
        if row is None:
            return
        self._row_tag[name] = tag
        if tag == "winner":
            self._set_row_bg(row, P["good_bg"]); self._set_row_fg(row, P["fg"])
        elif tag == "second":
            self._set_row_bg(row, P["row_2nd"]); self._set_row_fg(row, P["fg"])
        elif tag == "spoof":
            self._set_row_bg(row, P["surface"]); self._set_row_fg(row, P["purple"])
        elif tag == "fail":
            self._set_row_bg(row, P["surface"]); self._set_row_fg(row, P["fg_sub"])
        elif tag == "slow":
            self._set_row_bg(row, P["surface"]); self._set_row_fg(row, P["bad"])
        else:
            self._set_row_bg(row, P["surface"]); self._set_row_fg(row, P["fg"])

    def _highlight_top2(self) -> None:
        fast = self.fastest.name if self.fastest else None
        sec = self.second.name if self.second else None
        for name in list(self._row_by_name.keys()):
            if name == fast:
                self._set_row_tag(name, "winner")
            elif name == sec:
                self._set_row_tag(name, "second")
            elif self._row_tag.get(name) in ("winner", "second"):
                self._set_row_tag(name, "")

    def _name_at_row(self, row: int) -> Optional[str]:
        for n, r in self._row_by_name.items():
            if r == row:
                return n
        return None

    def _on_table_context_menu(self, pos) -> None:
        idx = self.table.indexAt(pos)
        if not idx.isValid():
            return
        row = idx.row()
        name = self._name_at_row(row)
        if name is None:
            return
        server = next((s for s in self.servers if s.name == name), None)
        if server is None:
            return
        self.table.selectRow(row)
        m = QMenu(self)
        m.setStyleSheet(self._menu_qss())
        a1 = m.addAction("Test this server only")
        a2 = m.addAction("Apply this server")
        a3 = m.addAction("Copy IP")
        m.addSeparator()
        a4 = m.addAction("Remove from blacklist")
        a1.triggered.connect(lambda: self._run_test(single=server))
        a2.triggered.connect(lambda: self._run_apply(force=server))
        a3.triggered.connect(lambda: self._copy_ip(server.primary))
        a4.triggered.connect(lambda: self._unblacklist(server.primary))
        m.exec_(self.table.viewport().mapToGlobal(pos))

    def _on_table_double(self, idx) -> None:
        if not idx.isValid():
            return
        name = self._name_at_row(idx.row())
        if name is None:
            return
        server = next((s for s in self.servers if s.name == name), None)
        if server is not None:
            self._run_test(single=server)

    def _copy_ip(self, ip: str) -> None:
        try:
            QApplication.clipboard().setText(ip)
        except Exception:
            pass

    def _unblacklist(self, ip: str) -> None:
        if ip in self.blacklist:
            del self.blacklist[ip]
            save_json(BLACKLIST_FILE, {k: int(v) for k, v in self.blacklist.items()})
            self._set_status(f"unblacklisted {ip}", P["good"])

    # ------------------------------------------------------- status / visuals

    def _set_status(self, text: str, color: str, pulse: bool = False) -> None:
        self.status_chip.setText(f"  {text.upper()}  ")
        self.status_chip.setStyleSheet(self._chip_qss(color))
        if pulse:
            self._pulse_color = color
            self._pulse_start()
        else:
            self._pulse_stop()

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        for b in (self.btn_test, self.btn_auto, self.btn_mix):
            b.setEnabled(not busy)
        self.btn_apply.setEnabled((not busy) and self.fastest is not None)
        if busy:
            self._scan_bar_start()
        else:
            self._scan_stop()

    def _set_progress(self, frac: float) -> None:
        frac = max(0.0, min(1.0, frac))
        self.progress.setValue(int(frac * 1000))

    def _update_mix_visual(self) -> None:
        if self.mix_on:
            self.btn_mix.setText("  MIX TOP 2     primary from #1  ·  secondary from #2")
            self.btn_mix.setStyleSheet(self._btn_qss("mix_on", align="left"))
        else:
            self.btn_mix.setText("  MIX TOP 2     same provider for both slots")
            self.btn_mix.setStyleSheet(self._btn_qss("mix_off", align="left"))


    def _update_auto_visual(self) -> None:
        if self.auto_on:
            self.btn_auto.setText("Auto: ON")
            self.btn_auto.setStyleSheet(self._btn_qss("auto_on"))
        else:
            self.btn_auto.setText("Auto: OFF")
            self.btn_auto.setStyleSheet(self._btn_qss("auto_off"))


    def _refresh_active(self) -> None:
        addrs = get_current_dns()
        self.val_active.setText(", ".join(addrs) if addrs else "-")

    # ------------------------------------------------------- test flow

    def _run_test(self, single: Optional[Server] = None,
                  then: Optional[Callable[[], None]] = None) -> None:
        if self.busy:
            if then is not None:
                self._post_call(then)
            return
        self._set_busy(True)
        threading.Thread(target=self._test_worker, args=(single, then), daemon=True).start()

    def _test_worker(self, single: Optional[Server],
                     then: Optional[Callable[[], None]]) -> None:
        try:
            if single is not None:
                self._post_call(lambda: self._set_status(f"testing {single.name}", P["warn"], pulse=True))
                ms = measure(single)
                self._post_call(lambda: self._finish_single(single, ms))
                return

            servers = list(self.servers)
            if not servers:
                self._post_call(lambda: self._set_status("no servers", P["bad"]))
                return

            self._post_call(self._prepare_rows_for_test)
            self._post_call(lambda: self._set_status(f"pinging {len(servers)} servers", P["warn"], pulse=True))

            total = len(servers)
            done = 0
            results: dict[str, int] = {}

            with ThreadPoolExecutor(max_workers=20) as ex:
                futures = {ex.submit(measure, s): s for s in servers}
                for fut in as_completed(futures):
                    srv = futures[fut]
                    try:
                        ms = int(fut.result())
                    except Exception:
                        ms = FAIL
                    results[srv.name] = ms
                    done += 1
                    self._post_call(lambda srv=srv, ms=ms, d=done, t=total:
                                    self._on_row_result(srv, ms, d, t))

            self._post_call(lambda: self._finish_test(results))
        except Exception as e:
            log("CRASH", f"{type(e).__name__}: {e}")
            self._post_call(lambda: self._set_status("error (see log)", P["bad"]))
        finally:
            self._post_call(lambda: self._set_busy(False))
            if then is not None:
                self._post_call(then)

    def _prepare_rows_for_test(self) -> None:
        self.val_second.setText("-")
        for name in list(self._row_by_name.keys()):
            self._set_row_values(name, lat="...", st="")
            self._set_row_tag(name, "")

    def _on_row_result(self, server: Server, ms: int, done: int, total: int) -> None:
        self._apply_row_latency(server, ms)

    def _apply_row_latency(self, server: Server, ms: int) -> None:
        if server.name not in self._row_by_name:
            return
        if ms == FAIL:
            self._set_row_values(server.name, lat="FAIL",
                                 st="blk" if self._is_blacklisted(server.primary) else "")
            self._set_row_tag(server.name, "fail")
        elif ms <= SPOOF_MS:
            self._set_row_values(server.name, lat="spoof", st="spoof")
            self._set_row_tag(server.name, "spoof")
        else:
            self._set_row_values(server.name, lat=f"{ms} ms",
                                 st="slow" if ms >= 150 else "")
            self._set_row_tag(server.name, "slow" if ms >= 150 else "")

    def _is_blacklisted(self, ip: str) -> bool:
        exp = self.blacklist.get(ip)
        if exp is None:
            return False
        if exp > int(time.time()):
            return True
        del self.blacklist[ip]
        return False

    def _add_blacklist(self, ip: str) -> None:
        self.blacklist[ip] = int(time.time()) + int(self.settings.get("blacklist_duration", 300))
        save_json(BLACKLIST_FILE, {k: int(v) for k, v in self.blacklist.items()})
        log("BLKLST", f"blacklisted {ip}")

    def _finish_single(self, server: Server, ms: int) -> None:
        self._apply_row_latency(server, ms)
        if ms == FAIL or ms <= SPOOF_MS:
            self._set_status(f"{server.name}: unreachable", P["bad"])
            log("TEST1", f"{server.name} FAIL")
            return
        self._push_history(server.name, ms)
        self._set_row_values(server.name, avg=self._avg_text(server.name))
        self._set_status(f"{server.name}: {ms} ms", P["good"])
        log("TEST1", f"{server.name} {ms} ms")

    def _push_history(self, name: str, ms: int) -> None:
        arr = self.history.get(name, []) + [ms]
        if len(arr) > 20:
            arr = arr[-20:]
        self.history[name] = arr

    def _finish_test(self, results: dict[str, int]) -> None:
        fail_counts: dict[str, int] = {}
        successes: list[tuple[Server, int]] = []

        for server in self.servers:
            ms = int(results.get(server.name, FAIL))
            if ms != FAIL and ms > SPOOF_MS:
                self._push_history(server.name, ms)
                self._set_row_values(server.name, avg=self._avg_text(server.name))
                successes.append((server, ms))
                fail_counts[server.primary] = 0
            else:
                cur = fail_counts.get(server.primary, 0) + 1
                fail_counts[server.primary] = cur
                if cur >= int(self.settings.get("blacklist_threshold", 3)):
                    self._add_blacklist(server.primary)

        save_json(HISTORY_FILE, self.history)
        self.val_last.setText(datetime.now().strftime("%H:%M:%S"))

        successes.sort(key=lambda t: t[1])

        if successes:
            self.fastest = successes[0][0]
            self.val_fastest.setText(f"{self.fastest.name}  ({successes[0][1]} ms)")
        elif self.settings.get("fallback_chain", True):
            self.fastest = Server(
                FALLBACK_NAME,
                str(self.settings.get("fallback_primary", "1.1.1.1")),
                str(self.settings.get("fallback_secondary", "1.0.0.1")),
            )
            self.val_fastest.setText(f"Fallback  ({self.fastest.primary})")
        else:
            self.fastest = None
            self.val_fastest.setText("none reachable")

        if len(successes) >= 2:
            self.second = successes[1][0]
            self.val_second.setText(f"{self.second.name}  ({successes[1][1]} ms)")
        else:
            self.second = None
            self.val_second.setText("-")

        self._highlight_top2()
        self._flash_winner()

        if self.fastest is not None:
            self._set_status(f"winner: {self.fastest.name}", P["good"])
            first = successes[0][1] if successes else 0
            log("TEST", f"winner={self.fastest.name} ({first}ms) tested={len(self.servers)}")
        else:
            self._set_status("all failed", P["bad"])
            log("TEST", "all failed")

        self._set_busy(False)

    # ------------------------------------------------------- apply flow

    def _resolve_pair(self, server: Server) -> tuple[str, str]:
        primary = server.primary
        secondary = server.secondary
        if self.mix_on and self.second is not None:
            cand = self.second.secondary or self.second.primary
            if cand and cand != primary:
                secondary = cand
        if not secondary or secondary == primary:
            secondary = str(self.settings.get("fallback_secondary", "1.0.0.1"))
        if not secondary or secondary == primary:
            secondary = "1.1.1.1"
        return primary, secondary

    def _run_apply(self, force: Optional[Server] = None,
                   then: Optional[Callable[[], None]] = None) -> None:
        if self.busy:
            if then is not None:
                self._post_call(then)
            return
        target = force if force is not None else self.fastest
        if target is None:
            if then is not None:
                self._post_call(then)
            return
        if force is not None:
            self.fastest = force
            self.second = None
            self._highlight_top2()
        self._set_busy(True)
        self.val_verify.setText("...")
        self.val_verify.setStyleSheet(self._kv_qss(P['warn']))
        self._set_status("applying", P["warn"], pulse=True)
        threading.Thread(target=self._apply_worker, args=(target, then), daemon=True).start()

    def _apply_worker(self, server: Server,
                      then: Optional[Callable[[], None]]) -> None:
        try:
            previous = get_current_dns()
            primary, secondary = self._resolve_pair(server)
            apply_dns(primary, secondary)
            time.sleep(0.4)
            ok = verify_dns()
            if ok:
                mode = "mixed" if (self.mix_on and self.second is not None) else "single"
                log("APPLY", f"{server.name} {primary}+{secondary} [{mode}] ok")
                self._post_call(lambda: self._apply_success(server, primary, secondary, mode))
            else:
                log("APPLY", f"{server.name} verify=failed, reverted")
                if previous:
                    fb = previous[1] if (len(previous) > 1 and previous[1] and previous[1] != previous[0]) else str(self.settings.get("fallback_secondary", "1.0.0.1"))
                    apply_dns(previous[0], fb)
                self._post_call(lambda: self._apply_failed(server))
        except Exception as e:
            log("ERROR", f"apply: {type(e).__name__}: {e}")
            self._post_call(lambda: self._set_status("apply error", P["bad"]))
            self._post_call(lambda: self.val_verify.setText("error"))
            self._post_call(lambda: self.val_verify.setStyleSheet(
                f"QLabel {{ color: {P['bad']}; background: transparent; }}"))
        finally:
            self._post_call(lambda: self._set_busy(False))
            if then is not None:
                self._post_call(then)

    def _apply_success(self, server: Server, primary: str,
                       secondary: str, mode: str) -> None:
        self.val_verify.setText("ok")
        self.val_verify.setStyleSheet(self._kv_qss(P['good']))
        self._refresh_active()
        self._set_status(f"applied ({mode})", P["good"])
        self.persisted["last_apply"] = {
            "name": server.name, "primary": primary,
            "secondary": secondary, "mode": mode,
            "time": datetime.now().isoformat(),
        }
        save_json(STATE_FILE, self.persisted)

    def _apply_failed(self, server: Server) -> None:
        self.val_verify.setText("failed")
        self.val_verify.setStyleSheet(self._kv_qss(P['bad']))
        self._refresh_active()
        self._set_status("reverted (verify failed)", P["bad"])

    # ------------------------------------------------------- toggles

    def _toggle_mix(self) -> None:
        if self.busy:
            return
        self.mix_on = not self.mix_on
        self._update_mix_visual()
        self.persisted["mix_on"] = self.mix_on
        save_json(STATE_FILE, self.persisted)

    def _toggle_auto(self) -> None:
        if self.busy:
            return
        self.auto_on = not self.auto_on
        self._update_auto_visual()
        if self._tray_auto is not None:
            self._tray_auto.setChecked(self.auto_on)
        self.persisted["auto_on"] = self.auto_on
        save_json(STATE_FILE, self.persisted)
        log("AUTO", f"toggled {'on' if self.auto_on else 'off'}")

        if self.auto_on:
            interval = int(self.settings.get("auto_interval_sec", 60))
            self._set_status(f"auto \u00b7 {interval}s", P["good"])
            self._auto_cycle()
        else:
            if self._auto_timer is not None:
                self._auto_timer.stop()
            self._set_status("idle", P["fg_dim"])

    def _auto_cycle(self) -> None:
        if not self.auto_on:
            return
        if self.busy:
            log("AUTO", "cycle deferred (busy)")
            self._schedule_next_auto(5)
            return
        log("AUTO", "cycle start")
        self._run_test(then=self._auto_after_test)

    def _auto_after_test(self) -> None:
        if not self.auto_on:
            return
        if self.fastest is None:
            log("AUTO", "no winner, next cycle")
            self._schedule_next_auto()
            return
        if self.fastest.name == FALLBACK_NAME:
            log("AUTO", "winner is fallback, skipping apply")
            self._schedule_next_auto()
            return
        self._run_apply(then=self._schedule_next_auto)

    def _schedule_next_auto(self, seconds: Optional[int] = None) -> None:
        if not self.auto_on:
            return
        if seconds is None:
            seconds = int(self.settings.get("auto_interval_sec", 60))
        if self._auto_timer is not None:
            self._auto_timer.stop()
        self._auto_timer = QTimer(self)
        self._auto_timer.setSingleShot(True)
        self._auto_timer.timeout.connect(self._auto_cycle)
        self._auto_timer.start(max(1, seconds) * 1000)
        log("AUTO", f"next cycle in {seconds}s")

    # ------------------------------------------------------- tray

    def _start_tray(self) -> None:
        if not QSystemTrayIcon.isSystemTrayAvailable():
            log("TRAY", "system tray not available")
            return
        try:
            icon = QIcon(self._make_icon_pixmap(64))
            self.tray_icon = QSystemTrayIcon(icon, self)
            self.tray_icon.setToolTip("DNSFrenzy")

            m = QMenu()
            m.setStyleSheet(self._menu_qss())

            a_show = m.addAction("Show")
            m.addSeparator()
            a_test = m.addAction("Run test now")
            a_apply = m.addAction("Apply fastest")
            self._tray_auto = m.addAction("Auto refresh")
            self._tray_auto.setCheckable(True)
            self._tray_auto.setChecked(self.auto_on)
            self._tray_startup = m.addAction("Start with Windows")
            self._tray_startup.setCheckable(True)
            self._tray_startup.setChecked(get_autostart())
            m.addSeparator()
            a_exp = m.addAction("Export config...")
            a_imp = m.addAction("Import config...")
            a_log = m.addAction("Open log file")
            m.addSeparator()
            a_exit = m.addAction("Exit")

            a_show.triggered.connect(self._restore)
            a_test.triggered.connect(lambda: self._run_test())
            a_apply.triggered.connect(lambda: self._run_apply())
            self._tray_auto.triggered.connect(self._toggle_auto)
            self._tray_startup.triggered.connect(self._toggle_startup)
            a_exp.triggered.connect(self._export_config)
            a_imp.triggered.connect(self._import_config)
            a_log.triggered.connect(self._open_log)
            a_exit.triggered.connect(self._exit_app)

            self.tray_icon.setContextMenu(m)
            self.tray_icon.activated.connect(self._on_tray_activate)
            self.tray_icon.show()
            log("TRAY", "started")
        except Exception as e:
            log("TRAY", f"failed: {type(e).__name__}: {e}")
            self.tray_icon = None

    def _on_tray_activate(self, reason) -> None:
        if reason in (QSystemTrayIcon.Trigger, QSystemTrayIcon.DoubleClick):
            self._restore()

    def _toggle_startup(self) -> None:
        set_autostart(not get_autostart())
        if self._tray_startup is not None:
            self._tray_startup.setChecked(get_autostart())

    # ------------------------------------------------------- file ops

    def _export_config(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Export DNSFrenzy config",
            f"dnsfrenzy-config-{datetime.now():%Y%m%d}.zip",
            "DNSFrenzy config (*.zip)",
        )
        if not path:
            return
        try:
            with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
                if SERVER_FILE.is_file():
                    z.write(SERVER_FILE, "config/servers.txt")
                if SETTINGS_FILE.is_file():
                    z.write(SETTINGS_FILE, "settings.json")
                if STATE_FILE.is_file():
                    z.write(STATE_FILE, "state.json")
            log("EXPORT", path)
            self._set_status("exported", P["good"])
        except Exception as e:
            self._set_status(f"export failed: {e}", P["bad"])

    def _import_config(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Import DNSFrenzy config", "", "DNSFrenzy config (*.zip)",
        )
        if not path:
            return
        try:
            with zipfile.ZipFile(path, "r") as z:
                if "config/servers.txt" in z.namelist():
                    with z.open("config/servers.txt") as src, open(SERVER_FILE, "wb") as dst:
                        dst.write(src.read())
            self._reload_servers()
            log("IMPORT", path)
            self._set_status("imported", P["good"])
        except Exception as e:
            self._set_status(f"import failed: {e}", P["bad"])

    def _open_log(self) -> None:
        if LOG_FILE.is_file():
            try:
                subprocess.Popen(["notepad.exe", str(LOG_FILE)],
                                 creationflags=CREATE_NO_WINDOW)
            except Exception:
                pass

    # ------------------------------------------------------- lifecycle

    def _restore(self) -> None:
        self.showNormal()
        self.raise_()
        self.activateWindow()

    def changeEvent(self, e) -> None:
        if e.type() == QEvent.WindowStateChange:
            if self.isMinimized() and self.tray_icon is not None:
                QTimer.singleShot(10, self.hide)
        super().changeEvent(e)

    def closeEvent(self, e) -> None:
        if self.exiting:
            e.accept()
            return
        if self.tray_icon is None:
            e.ignore()
            self._exit_app()
            return
        e.ignore()
        self.hide()

    def _exit_app(self) -> None:
        self.exiting = True
        self._pump_running = False
        for t in (self._pump_timer, self._mem_timer, self._pulse_timer,
                  self._flash_timer, self._scan_timer, self._auto_timer):
            if t is not None:
                try:
                    t.stop()
                except Exception:
                    pass
        if self.tray_icon is not None:
            try:
                self.tray_icon.hide()
            except Exception:
                pass
        self.persisted["auto_on"] = self.auto_on
        self.persisted["mix_on"] = self.mix_on
        save_json(STATE_FILE, self.persisted)
        save_json(HISTORY_FILE, self.history)
        save_json(SETTINGS_FILE, self.settings)
        log("EXIT", "user exit")
        QApplication.quit()


def main() -> None:
    if not is_admin():
        log("START", "not admin, relaunching with UAC")
        relaunch_as_admin()
        sys.exit(0)
    sys.excepthook = _excepthook
    app = QApplication(sys.argv)
    app.setApplicationName("DNSFrenzy")
    app.setQuitOnLastWindowClosed(False)
    win = App()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
