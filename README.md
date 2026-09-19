# DNSFrenzy

Fastest DNS auto-switcher for Windows. Pings a list of servers, applies the fastest one. Tray app, portable, no install.

Windows version of my [dnsfrenzy-linux](https://github.com/mrcactus-afk/dnsfrenzy-linux).

## Usage

Grab the zip from [Releases](../../releases), extract anywhere, right-click `DNSFrenzy.exe` and pick "Run as administrator". Click Run test, then Apply fastest. The window minimizes to the tray when closed.

## Editing servers

`config/servers.txt`, one per line:

    Name | Primary | Secondary

Lines starting with # are ignored.

## Building

    .\make-exe.ps1

Needs PowerShell 5.1 and the ps2exe module (`Install-Module ps2exe -Scope CurrentUser -Force`).
