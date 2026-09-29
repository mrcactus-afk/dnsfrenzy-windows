# DNSFrenzy

Fastest DNS auto-switcher for Windows. Pings a list of servers, applies the fastest one. Tray app, portable.

Windows version of my [dnsfrenzy-linux](https://github.com/mrcactus-afk/dnsfrenzy-linux).

## Requirements

- Windows 10 / 11
- Python 3.10+ (3.12 recommended)

## Setup

    pip install customtkinter pillow pystray

## Usage

    python src/dnsfrenzy_gui.py

The app self-elevates via UAC on launch (needed to change DNS settings).

Click **Run test**, then **Apply fastest**. Close minimizes to tray.

## Features

- Parallel ICMP ping, sorted by latency
- Spoof filter (<=5ms treated as fake)
- Verify + auto-revert on apply
- Smart mix (primary from winner, secondary from runner-up)
- Blacklist (3 fails -> skip 300s)
- Fallback chain (1.1.1.1 / 1.0.0.1)
- 20-sample rolling latency history
- Tray icon, autostart toggle
- Export / import config
- Auto refresh loop
- Live memory readout

## Editing servers

`config/servers.txt`, one per line:

    Name | Primary | Secondary

Lines starting with `#` are ignored.

## Legacy

`src/dnsfrenzy.ps1` is the original single-file PowerShell implementation. Build with `.\make-exe.ps1` (requires the ps2exe module). The Python GUI supersedes it.