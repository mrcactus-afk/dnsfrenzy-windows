"""DNSFrenzy - Windows GUI.

Pings DNS servers in parallel, applies the fastest one, verifies it.
CustomTkinter + ttk.Treeview. Animated.
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

import customtkinter as ctk
import tkinter as tk
from tkinter import Menu, filedialog, ttk

try:
    from PIL import Image, ImageDraw, ImageTk
    HAS_PIL = True
except Exception:
    HAS_PIL = False

try:
    import pystray
    HAS_TRAY = HAS_PIL
except Exception:
    HAS_TRAY = False

try:
    import winreg
    HAS_WINREG = True
except Exception:
    HAS_WINREG = False


def _find_root() -> Optional[Path]:
    here = Path(__file__).resolve().parent
    for cand in (here, here.parent, Path("C:/DNSFrenzyWindows"), Path("C:/DNSFrenzy")):
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
    "bg":         "#071426",
    "surface":    "#0e2038",
    "surface2":   "#16304e",
    "surface3":   "#1e3f63",
    "border":     "#234568",
    "fg":         "#e6f0ff",
    "fg_dim":     "#8ba3c7",
    "fg_sub":     "#5b7291",
    "accent":     "#4a9eff",
    "accent_hi":  "#6bb3ff",
    "accent_dn":  "#2d7ce0",
    "good":       "#2ecc71",
    "good_bg":    "#0e3424",
    "good_bg_hi": "#175132",
    "warn":       "#f0b429",
    "warn_dark":  "#a37a1a",
    "bad":        "#ff5c5c",
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

FONT = {
    "title":   ("Segoe UI Semibold", 20),
    "tag":     ("Segoe UI", 11),
    "chip":    ("Segoe UI Semibold", 10),
    "section": ("Segoe UI Semibold", 10),
    "count":   ("Segoe UI", 10),
    "cell":    ("Segoe UI", 11),
    "head":    ("Segoe UI Semibold", 10),
    "key":     ("Segoe UI Semibold", 9),
    "val":     ("Consolas", 11),
    "val_sm":  ("Consolas", 10),
    "btn":     ("Segoe UI Semibold", 13),
    "btn_sm":  ("Segoe UI Semibold", 11),
}

ROW_HEIGHT = 34

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


class App(ctk.CTk):
    def __init__(self) -> None:
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("dark-blue")
        super().__init__(fg_color=P["bg"])

        self._post: queue.Queue[Callable[[], None]] = queue.Queue()
        self._pump_running = True

        self.title("DNSFrenzy")
        self.minsize(540, 620)
        self._center_window(680, 800)
        self.configure(fg_color=P["bg"])
        self.protocol("WM_DELETE_WINDOW", self._on_close_request)
        self.bind("<Unmap>", self._on_unmap)

        self.settings: dict = {**DEFAULT_SETTINGS, **(load_json(SETTINGS_FILE, {}) or {})}
        self.persisted: dict = load_json(STATE_FILE, {}) or {}
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
        self._auto_job: Optional[str] = None
        self._pulse_job: Optional[str] = None
        self._pulse_on = False
        self._flash_job: Optional[str] = None
        self._fade_job: Optional[str] = None
        self._scan_job: Optional[str] = None
        self._mem_job: Optional[str] = None
        self.tray_icon = None
        self._icon_photo = None
        self._row_tags: dict[str, str] = {}

        self.report_callback_exception = self._on_tk_exception

        self._setup_tree_style()
        self._build_ui()
        self._reload_servers()
        self._refresh_active()
        self._update_mix_visual()
        self._update_auto_visual()
        self._set_status("ready", P["fg_dim"])

        try:
            self.attributes("-alpha", 0.0)
        except tk.TclError:
            pass

        self.after(60, self._apply_icon)
        self.after(60, self._pump)
        self.after(120, self._start_tray)
        self.after(160, self._post_startup)
        self.after(200, lambda: self._fade_in(0.0))
        self.after(1000, self._update_mem)

        log("START", f"launch mix={self.mix_on} auto={self.auto_on} admin={is_admin()} tray={HAS_TRAY}")

    def _center_window(self, w: int, h: int) -> None:
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        w = min(w, sw - 80)
        h = min(h, sh - 120)
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2 - 30)
        self.geometry(f"{w}x{h}+{x}+{y}")

    # ---------------------------------------------------------- runtime

    def _update_mem(self) -> None:
        if self.exiting:
            return
        try:
            mb = get_process_mem_mb()
            self.val_mem.configure(text=f"{mb:.0f} MB" if mb >= 0 else "-")
        except tk.TclError:
            return
        self._mem_job = self.after(2000, self._update_mem)
    def _on_tk_exception(self, exc, val, tb) -> None:
        text = "".join(traceback.format_exception(exc, val, tb))
        log("TK-EXC", text.replace("\n", " | "))
        try:
            self._set_status("ui error (see log)", P["bad"])
        except Exception:
            pass

    def _post_call(self, fn: Callable[[], None]) -> None:
        self._post.put(fn)

    def _pump(self) -> None:
        if not self._pump_running:
            return
        try:
            for _ in range(200):
                try:
                    fn = self._post.get_nowait()
                except queue.Empty:
                    break
                try:
                    fn()
                except Exception as e:
                    log("PUMP", f"{type(e).__name__}: {e}")
        finally:
            try:
                self.after(PUMP_INTERVAL_MS, self._pump)
            except tk.TclError:
                pass

    def _apply_icon(self) -> None:
        if not HAS_PIL:
            return
        try:
            img = Image.new("RGBA", (32, 32), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.ellipse((2, 2, 29, 29), fill=(88, 166, 255, 255))
            d.ellipse((11, 11, 20, 20), outline=(13, 17, 23, 255), width=3)
            self._icon_photo = ImageTk.PhotoImage(img)
            self.iconphoto(True, self._icon_photo)
        except Exception as e:
            log("ICON", str(e))

    def _post_startup(self) -> None:
        try:
            self.deiconify()
            self.lift()
            self.focus_force()
        except tk.TclError:
            pass
        if self.auto_on:
            self.after(500, self._auto_cycle)

    # -------------------------------------------------------- animations

    def _fade_in(self, a: float) -> None:
        try:
            a = min(1.0, a + 0.10)
            self.attributes("-alpha", a)
            if a < 1.0 and not self.exiting:
                self._fade_job = self.after(16, lambda: self._fade_in(a))
        except tk.TclError:
            pass

    def _pulse_start(self) -> None:
        if self._pulse_on:
            return
        self._pulse_on = True
        self._pulse_phase = 0
        self._pulse_tick()

    def _pulse_stop(self) -> None:
        self._pulse_on = False
        if self._pulse_job:
            try:
                self.after_cancel(self._pulse_job)
            except tk.TclError:
                pass
            self._pulse_job = None

    def _pulse_tick(self) -> None:
        if not self._pulse_on or self.exiting:
            return
        try:
            cur = self.status_chip.cget("fg")
        except tk.TclError:
            return
        phase = self._pulse_phase % 2
        on_color = getattr(self, "_pulse_color", P["warn"])
        color = on_color if phase == 0 else P["warn_dark"]
        try:
            self.status_chip.configure(fg=color)
        except tk.TclError:
            pass
        self._pulse_phase += 1
        self._pulse_job = self.after(400, self._pulse_tick)

    def _flash_winner(self) -> None:
        if self.fastest is None or self.fastest.name == FALLBACK_NAME:
            return
        iid = self.fastest.name
        if not self.tree.exists(iid):
            return
        if self._flash_job:
            try:
                self.after_cancel(self._flash_job)
            except tk.TclError:
                pass
            self._flash_job = None
        self._flash_step(iid, 0)

    def _flash_step(self, iid: str, count: int) -> None:
        if self.exiting or not self.tree.exists(iid):
            return
        hi = count % 2 == 0
        bg = P["good_bg_hi"] if hi else P["good_bg"]
        try:
            self.tree.tag_configure("winner", background=bg, foreground=P["fg"])
            self.tree.item(iid, tags=("winner",))
        except tk.TclError:
            return
        if count < 5:
            self._flash_job = self.after(160, lambda: self._flash_step(iid, count + 1))
        else:
            try:
                self.tree.tag_configure("winner", background=P["good_bg"], foreground=P["fg"])
            except tk.TclError:
                pass
            self._flash_job = None

    def _scan_bar_start(self) -> None:
        self._scan_phase = 0
        self._scan_tick()

    def _scan_stop(self) -> None:
        if self._scan_job:
            try:
                self.after_cancel(self._scan_job)
            except tk.TclError:
                pass
            self._scan_job = None
        self._set_progress(0.0)

    def _scan_tick(self) -> None:
        if self.exiting or not self.busy:
            return
        self._scan_phase = (getattr(self, "_scan_phase", 0) + 0.04) % 1.0
        try:
            self.progress_fill.place_configure(relwidth=self._scan_phase)
        except tk.TclError:
            return
        self._scan_job = self.after(30, self._scan_tick)

    # ------------------------------------------------------------ style

    def _setup_tree_style(self) -> None:
        try:
            style = ttk.Style(self)
            style.theme_use("clam")
        except Exception:
            style = ttk.Style(self)

        style.configure(
            "DF.Treeview",
            background=P["surface"],
            fieldbackground=P["surface"],
            foreground=P["fg"],
            borderwidth=0,
            relief="flat",
            rowheight=ROW_HEIGHT,
            font=FONT["cell"],
        )
        style.configure(
            "DF.Treeview.Heading",
            background=P["bg"],
            foreground=P["fg_dim"],
            borderwidth=0,
            relief="flat",
            padding=(10, 8),
            font=FONT["head"],
        )
        style.map(
            "DF.Treeview",
            background=[("selected", P["surface3"])],
            foreground=[("selected", P["fg"])],
        )
        style.map(
            "DF.Treeview.Heading",
            background=[("active", P["bg"])],
            foreground=[("active", P["fg"])],
        )
        style.layout("DF.Treeview", [("Treeview.treearea", {"sticky": "nswe"})])

        style.configure(
            "DF.Vertical.TScrollbar",
            background=P["surface2"],
            troughcolor=P["surface"],
            bordercolor=P["surface"],
            arrowcolor=P["fg_dim"],
            darkcolor=P["surface2"],
            lightcolor=P["surface2"],
            gripcount=0,
            relief="flat",
        )
        style.map(
            "DF.Vertical.TScrollbar",
            background=[("active", P["accent"])],
        )

    # ------------------------------------------------------------ layout

    def _build_ui(self) -> None:
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        tk.Frame(self, bg=P["accent"], height=3).grid(row=0, column=0, sticky="ew")

        body = tk.Frame(self, bg=P["bg"])
        body.grid(row=1, column=0, sticky="nsew")
        body.grid_rowconfigure(1, weight=1)
        body.grid_columnconfigure(0, weight=1)

        header = tk.Frame(body, bg=P["surface"], height=96)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_propagate(False)
        header.grid_columnconfigure(1, weight=1)

        diamond = tk.Label(header, text="\u25C6", font=("Segoe UI", 28),
                           bg=P["surface"], fg=P["accent"])
        diamond.grid(row=0, column=0, rowspan=2, padx=(22, 14), pady=(0, 6), sticky="w")

        tk.Label(header, text="DNSFrenzy", font=FONT["title"],
                 bg=P["surface"], fg=P["fg"], anchor="w").grid(
            row=0, column=1, sticky="sw", pady=(22, 0))

        tk.Label(header, text="Fastest DNS auto-switcher", font=FONT["tag"],
                 bg=P["surface"], fg=P["fg_dim"], anchor="w").grid(
            row=1, column=1, sticky="nw", pady=(0, 20))

        self.status_chip = tk.Label(
            header, text="  READY  ", font=FONT["chip"],
            bg=P["surface2"], fg=P["fg_dim"], padx=12, pady=6,
        )
        self.status_chip.grid(row=0, column=2, rowspan=2, padx=(8, 22), sticky="e")

        body_inner = tk.Frame(body, bg=P["bg"])
        body_inner.grid(row=1, column=0, sticky="nsew", padx=18, pady=(14, 8))
        body_inner.grid_rowconfigure(2, weight=1)
        body_inner.grid_columnconfigure(0, weight=1)

        toolbar = tk.Frame(body_inner, bg=P["bg"])
        toolbar.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        toolbar.grid_columnconfigure(1, weight=1)
        tk.Label(toolbar, text="SERVERS", font=FONT["section"],
                 bg=P["bg"], fg=P["fg_dim"]).grid(row=0, column=0, sticky="w")
        self.lbl_count = tk.Label(toolbar, text="", font=FONT["count"],
                                  bg=P["bg"], fg=P["fg_sub"])
        self.lbl_count.grid(row=0, column=2, sticky="e")

        self.progress_bg = tk.Frame(body_inner, bg=P["surface2"], height=3)
        self.progress_bg.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        self.progress_bg.grid_propagate(False)
        self.progress_fill = tk.Frame(self.progress_bg, bg=P["accent"], height=3)
        self.progress_fill.place(x=0, y=0, relwidth=0.0, relheight=1.0)

        tree_wrap = tk.Frame(body_inner, bg=P["border"], bd=0, highlightthickness=0)
        tree_wrap.grid(row=2, column=0, sticky="nsew")
        tree_wrap.grid_rowconfigure(0, weight=1)
        tree_wrap.grid_columnconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            tree_wrap,
            style="DF.Treeview",
            columns=("name", "lat", "avg", "st", "ip"),
            show="headings",
            selectmode="browse",
        )
        self.tree.heading("name", text="SERVER", anchor="w")
        self.tree.heading("lat", text="LATENCY", anchor="w")
        self.tree.heading("avg", text="AVG", anchor="w")
        self.tree.heading("st", text="STATUS", anchor="w")
        self.tree.heading("ip", text="IP", anchor="w")

        self.tree.column("name", width=180, minwidth=120, stretch=True, anchor="w")
        self.tree.column("lat", width=100, minwidth=85, stretch=False, anchor="w")
        self.tree.column("avg", width=80, minwidth=70, stretch=False, anchor="w")
        self.tree.column("st", width=80, minwidth=70, stretch=False, anchor="w")
        self.tree.column("ip", width=140, minwidth=100, stretch=True, anchor="w")

        vsb = ttk.Scrollbar(tree_wrap, orient="vertical",
                            command=self.tree.yview, style="DF.Vertical.TScrollbar")
        self.tree.configure(yscrollcommand=vsb.set)

        self.tree.grid(row=0, column=0, sticky="nsew", padx=(1, 0), pady=(1, 1))
        vsb.grid(row=0, column=1, sticky="ns", pady=(1, 1), padx=(0, 1))

        self.tree.tag_configure("winner", background=P["good_bg"], foreground=P["fg"])
        self.tree.tag_configure("second", background=P["row_2nd"], foreground=P["fg"])
        self.tree.tag_configure("spoof", foreground=P["purple"])
        self.tree.tag_configure("fail", foreground=P["fg_sub"])
        self.tree.tag_configure("slow", foreground=P["bad"])

        self.tree.bind("<Button-3>", self._on_tree_right_click)
        self.tree.bind("<Double-1>", self._on_tree_double)

        bottom = tk.Frame(self, bg=P["bg"])
        bottom.grid(row=2, column=0, sticky="ew", padx=18, pady=(6, 14))
        bottom.grid_columnconfigure(0, weight=1)

        self.btn_mix = ctk.CTkButton(
            bottom, text="", height=38,
            font=FONT["btn_sm"],
            fg_color=P["surface2"], hover_color=P["surface3"],
            text_color=P["fg_dim"], corner_radius=8, anchor="w",
            command=self._toggle_mix,
        )
        self.btn_mix.grid(row=0, column=0, sticky="ew", pady=(0, 8))

        info = tk.Frame(bottom, bg=P["surface"], height=112)
        info.grid(row=1, column=0, sticky="ew", pady=(0, 10))
        info.grid_propagate(False)
        info.grid_rowconfigure(0, weight=1)
        info.grid_columnconfigure(0, weight=1, minsize=280)
        info.grid_columnconfigure(1, weight=1)

        left = tk.Frame(info, bg=P["surface"])
        left.grid(row=0, column=0, sticky="nsew", padx=(16, 8), pady=14)
        left.grid_columnconfigure(1, weight=1)

        def kv(parent, row, key, value_default, val_font):
            tk.Label(parent, text=key, font=FONT["key"],
                     bg=P["surface"], fg=P["fg_dim"], anchor="w").grid(
                row=row, column=0, sticky="w", pady=(0, 6))
            v = tk.Label(parent, text=value_default, font=val_font,
                         bg=P["surface"], fg=P["fg"], anchor="w")
            v.grid(row=row, column=1, sticky="w", padx=(14, 0), pady=(0, 6))
            return v

        self.val_active = kv(left, 0, "ACTIVE", "-", FONT["val"])
        self.val_fastest = kv(left, 1, "FASTEST", "-", FONT["val"])
        self.val_second = kv(left, 2, "RUNNER-UP", "-", FONT["val"])

        right = tk.Frame(info, bg=P["surface"])
        right.grid(row=0, column=1, sticky="nsew", padx=(8, 16), pady=14)
        right.grid_columnconfigure(1, weight=1)

        self.val_last = kv(right, 0, "LAST", "never", FONT["val_sm"])
        self.val_verify = kv(right, 1, "VERIFY", "-", FONT["val_sm"])
        self.val_mem = kv(right, 2, "MEM", "-", FONT["val_sm"])

        actions = tk.Frame(bottom, bg=P["bg"])
        actions.grid(row=2, column=0, sticky="ew")
        for i in range(3):
            actions.grid_columnconfigure(i, weight=1, uniform="act")

        self.btn_test = ctk.CTkButton(
            actions, text="Run test", height=44,
            font=FONT["btn"],
            fg_color=P["accent"], hover_color=P["accent_hi"],
            text_color="#071426", corner_radius=10,
            command=lambda: self._run_test(),
        )
        self.btn_test.grid(row=0, column=0, sticky="ew", padx=(0, 6))

        self.btn_apply = ctk.CTkButton(
            actions, text="Apply fastest", height=44,
            font=FONT["btn"],
            fg_color=P["surface2"], hover_color=P["surface3"],
            text_color=P["fg"], corner_radius=10,
            command=lambda: self._run_apply(),
        )
        self.btn_apply.grid(row=0, column=1, sticky="ew", padx=6)

        self.btn_auto = ctk.CTkButton(
            actions, text="Auto: OFF", height=44,
            font=FONT["btn"],
            fg_color=P["surface2"], hover_color=P["surface3"],
            text_color=P["fg"], corner_radius=10,
            command=self._toggle_auto,
        )
        self.btn_auto.grid(row=0, column=2, sticky="ew", padx=(6, 0))

        self._set_busy(False)

    # ---------------------------------------------------------- rows

    def _reload_servers(self) -> None:
        self.servers = read_servers()
        self._rebuild_tree()

    def _rebuild_tree(self) -> None:
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self._row_tags.clear()

        for s in self.servers:
            avg = self._avg_text(s.name)
            iid = self.tree.insert(
                "", "end", iid=s.name,
                values=(s.name, "-", avg, "", s.primary),
            )
            self._row_tags[iid] = ""

        self.lbl_count.configure(text=f"{len(self.servers)} servers")
        self._highlight_top2()

    def _avg_text(self, name: str) -> str:
        h = self.history.get(name)
        if not h:
            return "-"
        return f"{int(sum(h) / len(h))} ms"

    def _set_tree_values(self, iid: str, lat: str = None, avg: str = None,
                         st: str = None, ip: str = None) -> None:
        if not self.tree.exists(iid):
            return
        cur = list(self.tree.item(iid, "values"))
        if len(cur) < 5:
            cur = (iid, "-", "-", "", "")[:5]
        if lat is not None: cur[1] = lat
        if avg is not None: cur[2] = avg
        if st is not None: cur[3] = st
        if ip is not None: cur[4] = ip
        self.tree.item(iid, values=tuple(cur))

    def _set_row_tag(self, iid: str, tag: str) -> None:
        if not self.tree.exists(iid):
            return
        self._row_tags[iid] = tag
        self.tree.item(iid, tags=(tag,) if tag else ())

    def _highlight_top2(self) -> None:
        fast = self.fastest.name if self.fastest else None
        sec = self.second.name if self.second else None
        for iid in self.tree.get_children():
            if iid == fast:
                self._set_row_tag(iid, "winner")
            elif iid == sec:
                self._set_row_tag(iid, "second")
            elif self._row_tags.get(iid) in ("winner", "second"):
                self._set_row_tag(iid, "")

    def _on_tree_right_click(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        self.tree.selection_set(iid)
        server = next((s for s in self.servers if s.name == iid), None)
        if server is None:
            return

        m = Menu(self, tearoff=0, bg=P["surface"], fg=P["fg"],
                 activebackground=P["accent"], activeforeground="#ffffff",
                 borderwidth=0, font=FONT["cell"])
        m.add_command(label="Test this server only",
                      command=lambda: self._run_test(single=server))
        m.add_command(label="Apply this server",
                      command=lambda: self._run_apply(force=server))
        m.add_command(label="Copy IP",
                      command=lambda: self._copy_ip(server.primary))
        m.add_separator()
        m.add_command(label="Remove from blacklist",
                      command=lambda: self._unblacklist(server.primary))
        try:
            m.tk_popup(event.x_root, event.y_root)
        finally:
            m.grab_release()

    def _on_tree_double(self, event) -> None:
        iid = self.tree.identify_row(event.y)
        if not iid:
            return
        server = next((s for s in self.servers if s.name == iid), None)
        if server is not None:
            self._run_test(single=server)

    def _copy_ip(self, ip: str) -> None:
        try:
            self.clipboard_clear()
            self.clipboard_append(ip)
        except tk.TclError:
            pass

    def _unblacklist(self, ip: str) -> None:
        if ip in self.blacklist:
            del self.blacklist[ip]
            save_json(BLACKLIST_FILE, {k: int(v) for k, v in self.blacklist.items()})
            self._set_status(f"unblacklisted {ip}", P["good"])

    # -------------------------------------------------------- status

    def _set_status(self, text: str, color: str, pulse: bool = False) -> None:
        try:
            self.status_chip.configure(text=f"  {text.upper()}  ", fg=color)
        except tk.TclError:
            return
        if pulse:
            self._pulse_color = color
            self._pulse_start()
        else:
            self._pulse_stop()

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        state = "normal" if not busy else "disabled"
        for b in (self.btn_test, self.btn_auto, self.btn_mix):
            try:
                b.configure(state=state)
            except tk.TclError:
                pass
        try:
            if busy:
                self.btn_apply.configure(state="disabled")
            else:
                self.btn_apply.configure(state="normal" if self.fastest else "disabled")
        except tk.TclError:
            pass
        if busy:
            self._scan_bar_start()
        else:
            self._scan_stop()
        if self.tray_icon is not None:
            try:
                self.tray_icon.update_menu()
            except Exception:
                pass

    def _set_progress(self, frac: float) -> None:
        frac = max(0.0, min(1.0, frac))
        try:
            self.progress_fill.place_configure(relwidth=frac)
        except tk.TclError:
            pass

    def _update_mix_visual(self) -> None:
        try:
            if self.mix_on:
                self.btn_mix.configure(
                    text="  MIX TOP 2     primary from #1  \u00b7  secondary from #2",
                    fg_color=P["purple_bg"], hover_color=P["purple_hi"],
                    text_color=P["purple"], anchor="w",
                )
            else:
                self.btn_mix.configure(
                    text="  MIX TOP 2     same provider for both slots",
                    fg_color=P["surface2"], hover_color=P["surface3"],
                    text_color=P["fg_dim"], anchor="w",
                )
        except tk.TclError:
            pass

    def _update_auto_visual(self) -> None:
        try:
            if self.auto_on:
                self.btn_auto.configure(text="Auto: ON", fg_color=P["auto_bg"],
                                        hover_color=P["surface3"], text_color=P["good"])
            else:
                self.btn_auto.configure(text="Auto: OFF", fg_color=P["surface2"],
                                        hover_color=P["surface3"], text_color=P["fg"])
        except tk.TclError:
            pass

    def _refresh_active(self) -> None:
        addrs = get_current_dns()
        try:
            self.val_active.configure(text=", ".join(addrs) if addrs else "-")
        except tk.TclError:
            pass

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
        try:
            self.val_second.configure(text="-")
        except tk.TclError:
            pass
        for iid in self.tree.get_children():
            self._set_tree_values(iid, lat="...", st="")
            self._set_row_tag(iid, "")

    def _on_row_result(self, server: Server, ms: int, done: int, total: int) -> None:
        self._apply_row_latency(server, ms)

    def _apply_row_latency(self, server: Server, ms: int) -> None:
        iid = server.name
        if not self.tree.exists(iid):
            return
        if ms == FAIL:
            self._set_tree_values(iid, lat="FAIL", st="blk" if self._is_blacklisted(server.primary) else "")
            self._set_row_tag(iid, "fail")
        elif ms <= SPOOF_MS:
            self._set_tree_values(iid, lat="spoof", st="spoof")
            self._set_row_tag(iid, "spoof")
        else:
            self._set_tree_values(iid, lat=f"{ms} ms", st="slow" if ms >= 150 else "")
            self._set_row_tag(iid, "slow" if ms >= 150 else "")

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
        self._set_tree_values(server.name, avg=self._avg_text(server.name))
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
                self._set_tree_values(server.name, avg=self._avg_text(server.name))
                successes.append((server, ms))
                fail_counts[server.primary] = 0
            else:
                cur = fail_counts.get(server.primary, 0) + 1
                fail_counts[server.primary] = cur
                if cur >= int(self.settings.get("blacklist_threshold", 3)):
                    self._add_blacklist(server.primary)

        save_json(HISTORY_FILE, self.history)
        try:
            self.val_last.configure(text=datetime.now().strftime("%H:%M:%S"))
        except tk.TclError:
            pass

        successes.sort(key=lambda t: t[1])

        if successes:
            self.fastest = successes[0][0]
            try:
                self.val_fastest.configure(text=f"{self.fastest.name}  ({successes[0][1]} ms)")
            except tk.TclError:
                pass
        elif self.settings.get("fallback_chain", True):
            self.fastest = Server(
                FALLBACK_NAME,
                str(self.settings.get("fallback_primary", "1.1.1.1")),
                str(self.settings.get("fallback_secondary", "1.0.0.1")),
            )
            try:
                self.val_fastest.configure(text=f"Fallback  ({self.fastest.primary})")
            except tk.TclError:
                pass
        else:
            self.fastest = None
            try:
                self.val_fastest.configure(text="none reachable")
            except tk.TclError:
                pass

        if len(successes) >= 2:
            self.second = successes[1][0]
            try:
                self.val_second.configure(text=f"{self.second.name}  ({successes[1][1]} ms)")
            except tk.TclError:
                pass
        else:
            self.second = None
            try:
                self.val_second.configure(text="-")
            except tk.TclError:
                pass

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
        try:
            self.val_verify.configure(text="...", fg=P["warn"])
        except tk.TclError:
            pass
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
                    apply_dns(previous[0], (previous[1] if (len(previous) > 1 and previous[1] and previous[1] != previous[0]) else str(self.settings.get("fallback_secondary", "1.0.0.1"))))
                self._post_call(lambda: self._apply_failed(server))
        except Exception as e:
            log("ERROR", f"apply: {type(e).__name__}: {e}")
            self._post_call(lambda: self._set_status("apply error", P["bad"]))
            self._post_call(lambda: self.val_verify.configure(text="error", fg=P["bad"]))
        finally:
            self._post_call(lambda: self._set_busy(False))
            if then is not None:
                self._post_call(then)

    def _apply_success(self, server: Server, primary: str,
                       secondary: str, mode: str) -> None:
        try:
            self.val_verify.configure(text="ok", fg=P["good"])
        except tk.TclError:
            pass
        self._refresh_active()
        self._set_status(f"applied ({mode})", P["good"])
        self.persisted["last_apply"] = {
            "name": server.name, "primary": primary,
            "secondary": secondary, "mode": mode,
            "time": datetime.now().isoformat(),
        }
        save_json(STATE_FILE, self.persisted)

    def _apply_failed(self, server: Server) -> None:
        try:
            self.val_verify.configure(text="failed", fg=P["bad"])
        except tk.TclError:
            pass
        self._refresh_active()
        self._set_status("reverted (verify failed)", P["bad"])

    # --------------------------------------------------------- toggles

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
        self.persisted["auto_on"] = self.auto_on
        save_json(STATE_FILE, self.persisted)
        log("AUTO", f"toggled {'on' if self.auto_on else 'off'}")

        if self.auto_on:
            interval = int(self.settings.get("auto_interval_sec", 60))
            self._set_status(f"auto \u00b7 {interval}s", P["good"])
            self._auto_cycle()
        else:
            if self._auto_job:
                try:
                    self.after_cancel(self._auto_job)
                except tk.TclError:
                    pass
                self._auto_job = None
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
        if self._auto_job:
            try:
                self.after_cancel(self._auto_job)
            except tk.TclError:
                pass
        self._auto_job = self.after(max(1, seconds) * 1000, self._auto_cycle)
        log("AUTO", f"next cycle in {seconds}s")

    # ----------------------------------------------------------- tray

    def _start_tray(self) -> None:
        if not HAS_TRAY:
            log("TRAY", "pystray unavailable, tray disabled")
            return
        try:
            img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
            d = ImageDraw.Draw(img)
            d.ellipse((0, 0, 63, 63), fill=(88, 166, 255, 255))
            d.ellipse((18, 18, 46, 46), outline=(13, 17, 23, 255), width=6)

            def wrap(fn):
                return lambda icon, item: self._post_call(fn)

            def auto_checked(item):
                return self.auto_on

            def startup_checked(item):
                return get_autostart()

            menu = pystray.Menu(
                pystray.MenuItem("Show", wrap(self._restore), default=True),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Run test now", wrap(lambda: self._run_test())),
                pystray.MenuItem("Apply fastest", wrap(lambda: self._run_apply())),
                pystray.MenuItem("Auto refresh", wrap(self._toggle_auto), checked=auto_checked),
                pystray.MenuItem("Start with Windows",
                                 wrap(self._toggle_startup), checked=startup_checked),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Export config...", wrap(self._export_config)),
                pystray.MenuItem("Import config...", wrap(self._import_config)),
                pystray.MenuItem("Open log file", wrap(self._open_log)),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Exit", wrap(self._exit_app)),
            )
            self.tray_icon = pystray.Icon("DNSFrenzy", img, "DNSFrenzy", menu)
            threading.Thread(target=self.tray_icon.run, daemon=True).start()
            log("TRAY", "started")
        except Exception as e:
            log("TRAY", f"failed: {type(e).__name__}: {e}")
            self.tray_icon = None

    def _toggle_startup(self) -> None:
        set_autostart(not get_autostart())
        if self.tray_icon is not None:
            try:
                self.tray_icon.update_menu()
            except Exception:
                pass

    # ------------------------------------------------------- file ops

    def _export_config(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Export DNSFrenzy config",
            defaultextension=".zip",
            filetypes=[("DNSFrenzy config", "*.zip")],
            initialfile=f"dnsfrenzy-config-{datetime.now():%Y%m%d}.zip",
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
        path = filedialog.askopenfilename(
            title="Import DNSFrenzy config",
            filetypes=[("DNSFrenzy config", "*.zip")],
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

    # ------------------------------------------------------ lifecycle

    def _restore(self) -> None:
        try:
            self.deiconify()
            self.state("normal")
            self.lift()
            self.focus_force()
        except tk.TclError:
            pass

    def _on_unmap(self, event) -> None:
        if self.exiting:
            return
        self.after(30, self._check_minimized)

    def _check_minimized(self) -> None:
        try:
            if self.state() == "iconic" and self.tray_icon is not None:
                self.withdraw()
        except tk.TclError:
            pass

    def _on_close_request(self) -> None:
        if self.exiting:
            self.destroy()
            return
        if self.tray_icon is None:
            self._exit_app()
            return
        try:
            self.withdraw()
        except tk.TclError:
            self._exit_app()

    def _exit_app(self) -> None:
        self.exiting = True
        self._pump_running = False
        for job in (self._auto_job, self._pulse_job, self._flash_job, self._mem_job,
                    self._fade_job, self._scan_job):
            if job:
                try:
                    self.after_cancel(job)
                except tk.TclError:
                    pass
        if self.tray_icon is not None:
            try:
                self.tray_icon.stop()
            except Exception:
                pass
        self.persisted["auto_on"] = self.auto_on
        self.persisted["mix_on"] = self.mix_on
        save_json(STATE_FILE, self.persisted)
        save_json(HISTORY_FILE, self.history)
        save_json(SETTINGS_FILE, self.settings)
        log("EXIT", "user exit")
        try:
            self.destroy()
        except tk.TclError:
            pass


def main() -> None:
    if not is_admin():
        log("START", "not admin, relaunching with UAC")
        relaunch_as_admin()
        sys.exit(0)
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()