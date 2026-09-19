Add-Type -AssemblyName System.Windows.Forms, System.Drawing

Add-Type -TypeDefinition @"
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;
public class DFColorTable : ProfessionalColorTable {
    public override Color MenuItemSelected { get { return Color.FromArgb(33, 38, 45); } }
    public override Color MenuItemSelectedGradientBegin { get { return Color.FromArgb(33, 38, 45); } }
    public override Color MenuItemSelectedGradientEnd { get { return Color.FromArgb(33, 38, 45); } }
    public override Color MenuItemPressedGradientBegin { get { return Color.FromArgb(28, 33, 40); } }
    public override Color MenuItemPressedGradientMiddle { get { return Color.FromArgb(28, 33, 40); } }
    public override Color MenuItemPressedGradientEnd { get { return Color.FromArgb(28, 33, 40); } }
    public override Color MenuItemBorder { get { return Color.FromArgb(48, 54, 61); } }
    public override Color MenuBorder { get { return Color.FromArgb(48, 54, 61); } }
    public override Color ToolStripDropDownBackground { get { return Color.FromArgb(22, 27, 34); } }
    public override Color ImageMarginGradientBegin { get { return Color.FromArgb(22, 27, 34); } }
    public override Color ImageMarginGradientMiddle { get { return Color.FromArgb(22, 27, 34); } }
    public override Color ImageMarginGradientEnd { get { return Color.FromArgb(22, 27, 34); } }
    public override Color SeparatorDark { get { return Color.FromArgb(48, 54, 61); } }
    public override Color SeparatorLight { get { return Color.FromArgb(48, 54, 61); } }
}
public class DFRenderer : ToolStripProfessionalRenderer {
    public DFRenderer() : base(new DFColorTable()) { }
    protected override void OnRenderItemText(ToolStripItemTextRenderEventArgs e) {
        e.TextColor = e.Item.Enabled ? Color.FromArgb(240, 246, 252) : Color.FromArgb(90, 96, 104);
        base.OnRenderItemText(e);
    }
    protected override void OnRenderItemCheck(ToolStripItemImageRenderEventArgs e) {
        Graphics g = e.Graphics; g.SmoothingMode = SmoothingMode.AntiAlias;
        Rectangle r = e.ImageRectangle;
        int cx = r.Left + r.Width / 2, cy = r.Top + r.Height / 2;
        using (Pen pen = new Pen(Color.FromArgb(88, 166, 255), 2)) {
            g.DrawLines(pen, new Point[] { new Point(cx-5,cy), new Point(cx-2,cy+4), new Point(cx+6,cy-5) });
        }
    }
    protected override void OnRenderSeparator(ToolStripSeparatorRenderEventArgs e) {
        Graphics g = e.Graphics; Rectangle r = e.Item.Bounds;
        using (Pen pen = new Pen(Color.FromArgb(48, 54, 61)))
            g.DrawLine(pen, r.Left + 8, r.Height / 2, r.Right - 8, r.Height / 2);
    }
    protected override void OnRenderArrow(ToolStripArrowRenderEventArgs e) {
        e.ArrowColor = Color.FromArgb(139, 148, 158);
        base.OnRenderArrow(e);
    }
}
"@ -ReferencedAssemblies 'System.Windows.Forms','System.Drawing'

$T = @{
    BG=[Drawing.Color]::FromArgb(13,17,23); SURFACE=[Drawing.Color]::FromArgb(22,27,34); SURFACE2=[Drawing.Color]::FromArgb(33,38,45)
    FG=[Drawing.Color]::FromArgb(240,246,252); FG_DIM=[Drawing.Color]::FromArgb(139,148,158)
    ACCENT=[Drawing.Color]::FromArgb(88,166,255); ACCENT_HI=[Drawing.Color]::FromArgb(120,190,255); ACCENT_DN=[Drawing.Color]::FromArgb(70,140,220)
    GOOD=[Drawing.Color]::FromArgb(63,185,80); GOOD_BG=[Drawing.Color]::FromArgb(20,45,28)
    WARN=[Drawing.Color]::FromArgb(210,153,34); BAD=[Drawing.Color]::FromArgb(248,81,73)
    PURPLE=[Drawing.Color]::FromArgb(163,113,247); PURPLE_BG=[Drawing.Color]::FromArgb(42,32,68)
    PURPLE_HI=[Drawing.Color]::FromArgb(58,44,92); PURPLE_DN=[Drawing.Color]::FromArgb(34,24,54)
    ROW_2ND=[Drawing.Color]::FromArgb(38,28,58); AUTO_BG=[Drawing.Color]::FromArgb(22,48,32)
}

$candidates = @()
if ($PSScriptRoot) { $candidates += $PSScriptRoot }
try { $candidates += Split-Path ([System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName) -Parent } catch {}
$candidates += 'C:\DNSFrenzy'
$ExeDir = $null
foreach ($c in $candidates) { if ($c -and (Test-Path (Join-Path $c 'config\servers.txt'))) { $ExeDir = $c; break } }
if (-not $ExeDir) { [System.Windows.Forms.MessageBox]::Show("Config not found.", 'DNSFrenzy') | Out-Null; exit 1 }

$script:LaunchPath = $null
try {
    $mm = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if ($mm -and $mm -notlike '*powershell*' -and $mm -like '*.exe') { $script:LaunchPath = $mm }
} catch {}
if (-not $script:LaunchPath) { $script:LaunchPath = Join-Path $ExeDir 'dnsfrenzy.ps1' }

$ConfigDir = Join-Path $ExeDir 'config'
$DataDir   = Join-Path $ExeDir 'data'
if (-not (Test-Path $DataDir)) { New-Item -ItemType Directory -Path $DataDir -Force | Out-Null }

$ServerFile = Join-Path $ConfigDir 'servers.txt'
$SettingsFile = Join-Path $DataDir 'settings.json'
$StatePath = Join-Path $DataDir 'state.json'
$HistoryPath = Join-Path $DataDir 'history.json'
$BlacklistPath = Join-Path $DataDir 'blacklist.json'
$LogPath = Join-Path $DataDir 'dnsfrenzy.log'

$script:Settings = @{
    interval=30; http_test=$false; http_timeout=3; http_url=''
    smart_mix=$true; fallback_chain=$true; blacklist_threshold=3; blacklist_duration=300
    fallback_primary='1.1.1.1'; fallback_secondary='1.0.0.1'
}

function Write-Log($tag, $msg) {
    try {
        Add-Content -Path $LogPath -Value ("[{0}] {1,-8} {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $tag, $msg) -Encoding UTF8
        $all = @(Get-Content $LogPath -EA SilentlyContinue)
        if ($all.Count -gt 500) { $all[-500..-1] | Set-Content -Path $LogPath -Encoding UTF8 }
    } catch {}
}
function Invoke-Safe($label, $block) { try { & $block } catch { Write-Log 'ERROR' ("{0} : {1}" -f $label, $_.Exception.Message) } }
function Load-Json($path, $default) {
    if (-not (Test-Path $path)) { return $default }
    try { return Get-Content $path -Raw | ConvertFrom-Json } catch { return $default }
}
function Save-Json($path, $obj) { Invoke-Safe "save:$path" { $obj | ConvertTo-Json -Depth 4 | Set-Content $path -Encoding UTF8 } }

function Load-Settings {
    $s = Load-Json $SettingsFile $null
    if ($s) { foreach ($k in $script:Settings.Keys.Clone()) { if ($null -ne $s.$k) { $script:Settings[$k] = $s.$k } } }
}
function Save-Settings { Save-Json $SettingsFile $script:Settings }

function Load-State {
    $s = Load-Json $StatePath ([pscustomobject]@{ MixOn = $true; LastApply = $null })
    if ($null -eq $s.MixOn) { $s.MixOn = $true }
    return $s
}
function Save-State($s) { Save-Json $StatePath $s }

function Load-History {
    $raw = Load-Json $HistoryPath @{}
    $out = @{}
    foreach ($p in $raw.PSObject.Properties) { $out[$p.Name] = @($p.Value) }
    return $out
}
function Save-History($h) { Save-Json $HistoryPath $h }
function Add-History($name, $ms) {
    $h = $script:History
    if (-not $h.ContainsKey($name)) { $h[$name] = @() }
    $arr = @($h[$name]) + @($ms)
    if ($arr.Count -gt 20) { $arr = $arr[-20..-1] }
    $h[$name] = $arr
    $script:History = $h
}
function Get-AvgMs($name) {
    $h = $script:History
    if (-not $h.ContainsKey($name) -or $h[$name].Count -eq 0) { return $null }
    return [int]((@($h[$name]) | Measure-Object -Average).Average)
}

function Load-Blacklist {
    $raw = Load-Json $BlacklistPath @{}
    $out = @{}
    $now = [int][double]::Parse((Get-Date -UFormat %s))
    if ($null -ne $raw) {
        foreach ($p in $raw.PSObject.Properties) {
            try {
                $val = $p.Value
                if ($val -is [array]) { if ($val.Count -gt 0) { $val = $val[0] } else { continue } }
                if ($null -eq $val) { continue }
                [int]$iVal = [int]$val
                if ($iVal -gt $now) { $out[[string]$p.Name] = $iVal }
            } catch {}
        }
    }
    return $out
}
function Save-Blacklist {
    $clean = @{}
    foreach ($k in $script:Blacklist.Keys) { try { $clean[[string]$k] = [int]$script:Blacklist[$k] } catch {} }
    Save-Json $BlacklistPath $clean
}
function Test-Blacklisted([string]$ip) {
    [bool]$result = $false
    if ($script:Blacklist.ContainsKey($ip)) {
        $now = [int][double]::Parse((Get-Date -UFormat %s))
        if ([int]$script:Blacklist[$ip] -gt $now) { $result = $true }
        else { $null = $script:Blacklist.Remove($ip) }
    }
    return $result
}
function Add-Blacklist($ip) {
    $now = [int][double]::Parse((Get-Date -UFormat %s))
    $script:Blacklist[$ip] = $now + $script:Settings.blacklist_duration
    Save-Blacklist
}

function Read-Servers {
    if (-not (Test-Path $ServerFile)) { return @() }
    Get-Content $ServerFile | Where-Object { $_ -and $_ -notmatch '^\s*#' } | ForEach-Object {
        $p = $_ -split '\|'
        if ($p.Count -ge 3) { [pscustomobject]@{ Name=$p[0].Trim(); Primary=$p[1].Trim(); Secondary=$p[2].Trim() } }
    }
}

function Test-Ping([string]$ip) {
    [int]$result = 99999
    $p = $null
    try {
        $p = New-Object System.Net.NetworkInformation.Ping
        $times = New-Object 'System.Collections.Generic.List[int]'
        for ($i=0; $i -lt 3; $i++) {
            $r = $p.Send($ip, 700)
            if ($r.Status -eq 'Success') { [void]$times.Add([int]$r.RoundtripTime) }
            Start-Sleep -Milliseconds 30
        }
        if ($times.Count -ge 2) {
            $sorted = $times.ToArray() | Sort-Object
            $result = [int]$sorted[[int]($sorted.Count / 2)]
        }
    } catch { $result = 99999 }
    finally { if ($p) { $null = $p.Dispose() } }
    return $result
}

function Test-ServersBatched {
    param([array]$Servers, [int]$Samples = 2, [int]$Timeout = 700, [int]$BatchSize = 10)

    $batch = @()
    foreach ($s in $Servers) {
        $batch += [pscustomobject]@{
            Server = $s
            Samples = New-Object 'System.Collections.Generic.List[int]'
            Pinger = $null
            Task = $null
        }
    }

    for ($round = 1; $round -le $Samples; $round++) {
        $alive = New-Object 'System.Collections.Generic.List[object]'
        foreach ($b in $batch) {
            if ($round -eq 1 -or $b.Samples.Count -gt 0) { $alive.Add($b) | Out-Null }
        }
        if ($alive.Count -eq 0) { break }

        $i = 0
        while ($i -lt $alive.Count) {
            $end = [math]::Min($i + $BatchSize - 1, $alive.Count - 1)
            $group = @()
            for ($j = $i; $j -le $end; $j++) { $group += $alive[$j] }

            foreach ($b in $group) {
                try {
                    $b.Pinger = New-Object System.Net.NetworkInformation.Ping
                    $b.Task = $b.Pinger.SendPingAsync($b.Server.Primary, $Timeout)
                } catch { $b.Task = $null }
            }

            $deadline = [DateTime]::UtcNow.AddMilliseconds($Timeout + 1500)
            while ([DateTime]::UtcNow -lt $deadline) {
                $pending = 0
                foreach ($b in $group) {
                    if ($b.Task -ne $null -and -not $b.Task.IsCompleted) { $pending++ }
                }
                if ($pending -eq 0) { break }
                [System.Windows.Forms.Application]::DoEvents()
                Start-Sleep -Milliseconds 20
            }

            foreach ($b in $group) {
                if ($b.Task -ne $null -and $b.Task.IsCompleted) {
                    try {
                        $r = $b.Task.Result
                        if ($r.Status -eq 'Success') { [void]$b.Samples.Add([int]$r.RoundtripTime) }
                    } catch {}
                }
                if ($b.Pinger) { try { $b.Pinger.Dispose() } catch {} }
                $b.Pinger = $null
                $b.Task = $null
            }
            [System.Windows.Forms.Application]::DoEvents()
            $i += $BatchSize
        }
    }

    $results = @{}
    foreach ($b in $batch) {
        if ($b.Samples.Count -ge 1) {
            $sorted = $b.Samples.ToArray() | Sort-Object
            $median = [int]$sorted[[int]($sorted.Count / 2)]
            $results[$b.Server.Name] = $median
        } else {
            $results[$b.Server.Name] = 99999
        }
    }
    return $results
}

function Get-CurrentDns {
    try { return @((Get-DnsClientServerAddress -AddressFamily IPv4 | Where-Object { $_.ServerAddresses } | Select-Object -First 1).ServerAddresses) } catch { return @() }
}

function Apply-Dns($srv, $mix) {
    $primary = [string]$srv.Primary
    $secondary = [string]$srv.Secondary

    if ($mix -and $script:Second -and $script:Second.PSObject.Properties['Primary']) {
        $cand = [string]$script:Second.Secondary
        if (-not $cand) { $cand = [string]$script:Second.Primary }
        if ($cand -and $cand -ne $primary) { $secondary = $cand }
    }

    if (-not $secondary -or $secondary -eq $primary) {
        $secondary = $script:Settings.fallback_secondary
    }
    if (-not $secondary -or $secondary -eq $primary) {
        $secondary = '1.1.1.1'
    }

    Write-Log 'DNS' ("primary={0} secondary={1}" -f $primary, $secondary)

    Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
        try { Set-DnsClientServerAddress -InterfaceAlias $_.Name -ServerAddresses @($primary,$secondary) -EA Stop } catch {}
    }
    try { ipconfig /flushdns | Out-Null } catch {}
    return @($primary,$secondary)
}

function Verify-Dns {
    try {
        $ip = ((Resolve-DnsName digikala.com -Type A -DnsOnly -EA Stop -QuickTimeout) | Where-Object { $_.IPAddress } | Select-Object -First 1).IPAddress
        return ($ip -and $ip -notmatch '^198\.20\.')
    } catch { return $false }
}

function Get-Autostart {
    try { return [bool](Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run' -Name DNSFrenzy -EA SilentlyContinue).DNSFrenzy } catch { return $false }
}
function Set-Autostart($on) {
    $reg = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
    if ($on -and $script:LaunchPath) {
        $cmd = if ($script:LaunchPath -like '*.exe') { "`"$($script:LaunchPath)`"" }
               else { "powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$($script:LaunchPath)`"" }
        Set-ItemProperty -Path $reg -Name 'DNSFrenzy' -Value $cmd -Force
    } else { Remove-ItemProperty -Path $reg -Name 'DNSFrenzy' -EA SilentlyContinue }
}

function New-CtrlLabel($text, $x, $y, $font, $color, $bg) {
    $l = New-Object Windows.Forms.Label
    $l.Text = $text; $l.Font = $font; $l.ForeColor = $color
    if ($bg) { $l.BackColor = $bg }
    $l.Location = New-Object Drawing.Point($x, $y); $l.AutoSize = $true
    return $l
}
function New-FullLabel($text, $y, $h, $font, $color, $bg) {
    $l = New-Object Windows.Forms.Label
    $l.Text = $text; $l.Font = $font; $l.ForeColor = $color
    if ($bg) { $l.BackColor = $bg }
    $l.AutoSize = $false; $l.Size = New-Object Drawing.Size(520, $h)
    $l.Location = New-Object Drawing.Point(0, $y); $l.TextAlign = 'MiddleCenter'
    return $l
}
function New-Panel($x, $y, $w, $h, $bg) {
    $p = New-Object Windows.Forms.Panel
    $p.Location = New-Object Drawing.Point($x, $y)
    $p.Size = New-Object Drawing.Size($w, $h); $p.BackColor = $bg
    return $p
}
function New-Btn($text, $x, $y, $w, $h, $primary, $align) {
    $b = New-Object Windows.Forms.Button
    $b.Text = $text; $b.Location = New-Object Drawing.Point($x, $y)
    $b.Size = New-Object Drawing.Size($w, $h)
    $b.FlatStyle = 'Flat'; $b.FlatAppearance.BorderSize = 0
    $b.Font = 'Segoe UI Semibold,9'; $b.Cursor = 'Hand'
    if ($align) { $b.TextAlign = $align }
    if ($primary) {
        $b.BackColor = $T.ACCENT; $b.ForeColor = $T.BG
        $b.FlatAppearance.MouseOverBackColor = $T.ACCENT_HI
        $b.FlatAppearance.MouseDownBackColor = $T.ACCENT_DN
    } else {
        $b.BackColor = $T.SURFACE2; $b.ForeColor = $T.FG
    }
    return $b
}
function New-MenuItem($text) {
    $i = New-Object System.Windows.Forms.ToolStripMenuItem $text
    $i.BackColor = $T.SURFACE; $i.ForeColor = $T.FG
    $i.Padding = New-Object System.Windows.Forms.Padding(2,5,12,5)
    $i.Margin = New-Object System.Windows.Forms.Padding(0)
    return $i
}
function New-MenuStrip {
    $m = New-Object System.Windows.Forms.ContextMenuStrip
    $m.BackColor = $T.SURFACE; $m.ForeColor = $T.FG; $m.Font = 'Segoe UI,9'
    $m.Renderer = New-Object DFRenderer
    $m.ShowImageMargin = $true; $m.Padding = New-Object System.Windows.Forms.Padding(0,4,0,4)
    return $m
}
function New-InfoRow($label, $y) {
    return @((New-CtrlLabel $label 14 $y 'Segoe UI,8' $T.FG_DIM $null),
             (New-CtrlLabel '-' 100 $y 'Consolas,9' $T.FG $null))
}

Load-Settings
$script:State = Load-State
$script:History = Load-History
$script:Blacklist = Load-Blacklist

$form = New-Object Windows.Forms.Form
$form.Text = 'DNSFrenzy'
$form.ClientSize = New-Object Drawing.Size(520,650)
$form.StartPosition = 'CenterScreen'
$form.FormBorderStyle = 'FixedSingle'
$form.MaximizeBox = $false
$form.AutoScaleMode = 'None'
$form.BackColor = $T.BG; $form.ForeColor = $T.FG; $form.Font = 'Segoe UI,9'

$accentBar = New-Panel 0 0 520 3 $T.ACCENT
$header = New-Panel 0 3 520 105 $T.SURFACE
$logo = New-FullLabel ([char]0x25C6) 8 26 'Segoe UI,18' $T.ACCENT $null
$title = New-FullLabel 'DNSFrenzy' 32 26 'Segoe UI Semibold,15' $T.FG $null
$subtitle = New-FullLabel 'Fastest DNS auto-switcher' 60 16 'Segoe UI,8' $T.FG_DIM $null
$statusChip = New-FullLabel 'READY' 80 18 'Segoe UI Semibold,7' $T.FG_DIM $T.SURFACE2
$header.Controls.AddRange(@($logo,$title,$subtitle,$statusChip))

$lblServers = New-CtrlLabel 'SERVERS      (right-click a row for options)' 20 118 'Segoe UI Semibold,7' $T.FG_DIM $null

$list = New-Object Windows.Forms.ListView
$list.Location = New-Object Drawing.Point(20,136)
$list.Size = New-Object Drawing.Size(480,290)
$list.View = 'Details'
$list.FullRowSelect = $true; $list.GridLines = $false
$list.HeaderStyle = 'Nonclickable'; $list.MultiSelect = $false
$list.HideSelection = $false; $list.BorderStyle = 'FixedSingle'
$list.BackColor = $T.SURFACE; $list.ForeColor = $T.FG; $list.Font = 'Segoe UI,9'
$list.Columns.Add('SERVER', 160) | Out-Null
$list.Columns.Add('LATENCY', 110) | Out-Null
$list.Columns.Add('AVG (20)', 90) | Out-Null
$list.Columns.Add('STATUS', 70) | Out-Null
$list.Columns.Add('IP', 50) | Out-Null

$rowMenu = New-MenuStrip
$rmTest = New-MenuItem 'Test this server only'
$rmApply = New-MenuItem 'Apply this server'
$rmCopy = New-MenuItem 'Copy IP'
$rmUnbl = New-MenuItem 'Remove from blacklist'
$rowMenu.Items.AddRange(@($rmTest,$rmApply,$rmCopy,$rmUnbl)) | Out-Null
$list.ContextMenuStrip = $rowMenu

$progress = New-Object Windows.Forms.ProgressBar
$progress.Location = New-Object Drawing.Point(20,432)
$progress.Size = New-Object Drawing.Size(480,3)
$progress.Style = 'Continuous'; $progress.Minimum = 0; $progress.Maximum = 100; $progress.Value = 0

$panel = New-Panel 20 444 480 92 $T.SURFACE
$r1 = New-InfoRow 'Active DNS' 12
$r2 = New-InfoRow 'Fastest' 36
$r3 = New-InfoRow 'Runner-up' 60
$lblLastMini = New-CtrlLabel 'LAST CHECK' 380 12 'Segoe UI Semibold,7' $T.FG_DIM $null
$valLast = New-CtrlLabel 'never' 380 28 'Consolas,8' $T.FG_DIM $null
$lblVerify = New-CtrlLabel 'VERIFY' 380 50 'Segoe UI Semibold,7' $T.FG_DIM $null
$valVerify = New-CtrlLabel '-' 380 66 'Consolas,8' $T.FG_DIM $null
$panel.Controls.AddRange(@($r1[0],$r1[1],$r2[0],$r2[1],$r3[0],$r3[1],$lblLastMini,$valLast,$lblVerify,$valVerify))

$btnMix = New-Btn '   MIX TOP 2' 20 546 480 30 $false 'MiddleLeft'
$btnMix.Padding = New-Object Windows.Forms.Padding(14,0,0,0)
$btnMix.Font = 'Segoe UI Semibold,8'

$btnGo = New-Btn 'Run test' 20 586 155 34 $true $null
$btnSet = New-Btn 'Apply fastest' 182 586 155 34 $false $null
$btnAuto = New-Btn 'Auto: OFF' 344 586 156 34 $false $null
$btnSet.Enabled = $false

$form.Controls.AddRange(@($accentBar,$header,$lblServers,$list,$progress,$panel,$btnMix,$btnGo,$btnSet,$btnAuto))

$script:Fastest = $null; $script:Second = $null; $script:Servers = @()
$script:Busy = $false; $script:MixOn = $script:State.MixOn; $script:Exiting = $false

function New-TrayIcon {
    $bmp = New-Object System.Drawing.Bitmap 16,16
    $g = [System.Drawing.Graphics]::FromImage($bmp)
    $g.SmoothingMode = 'AntiAlias'; $g.Clear([System.Drawing.Color]::Transparent)
    $brush = New-Object System.Drawing.SolidBrush $T.ACCENT
    $g.FillEllipse($brush, 0, 0, 15, 15)
    $pen = New-Object System.Drawing.Pen $T.FG, 2
    $g.DrawEllipse($pen, 4, 4, 7, 7)
    $g.Dispose(); $brush.Dispose(); $pen.Dispose()
    return [System.Drawing.Icon]::FromHandle($bmp.GetHicon())
}

$tray = New-Object System.Windows.Forms.NotifyIcon
$tray.Icon = New-TrayIcon; $tray.Text = 'DNSFrenzy'; $tray.Visible = $true

$trayMenu = New-MenuStrip
$miShow = New-MenuItem 'Show'
$miTest = New-MenuItem 'Run test now'
$miApply = New-MenuItem 'Apply fastest'
$miAuto = New-MenuItem 'Auto refresh  (60s)'
$miStartup = New-MenuItem 'Start with Windows'
$miExport = New-MenuItem 'Export config...'
$miImport = New-MenuItem 'Import config...'
$miLog = New-MenuItem 'Open log file'
$miExit = New-MenuItem 'Exit'
$miAuto.Checked = $false
$miStartup.Checked = (Get-Autostart)
$sep1 = New-Object System.Windows.Forms.ToolStripSeparator
$sep2 = New-Object System.Windows.Forms.ToolStripSeparator
$trayMenu.Items.AddRange(@($miShow,$sep1,$miTest,$miApply,$miAuto,$miStartup,$sep2,$miExport,$miImport,$miLog,$sep2,$miExit)) | Out-Null
$tray.ContextMenuStrip = $trayMenu

function Set-Status($text, $color) {
    $statusChip.Text = "  $($text.ToUpper())  "
    $statusChip.ForeColor = if ($color -is [System.Drawing.Color]) { $color } else { $T.FG_DIM }
    $tray.Text = "DNSFrenzy - $text"
}
function Set-Busy($b) {
    $script:Busy = $b
    $btnGo.Enabled = -not $b
    $btnSet.Enabled = (-not $b) -and ($null -ne $script:Fastest)
    $btnAuto.Enabled = -not $b
    $btnMix.Enabled = -not $b
    $miTest.Enabled = -not $b
    $miApply.Enabled = -not $b
}
function Update-MixVisual {
    if ($script:MixOn) {
        $btnMix.Text = '   MIX TOP 2     primary from #1  ·  secondary from #2'
        $btnMix.BackColor = $T.PURPLE_BG; $btnMix.ForeColor = $T.PURPLE
        $btnMix.FlatAppearance.MouseOverBackColor = $T.PURPLE_HI
        $btnMix.FlatAppearance.MouseDownBackColor = $T.PURPLE_DN
    } else {
        $btnMix.Text = '   MIX TOP 2     same provider for both slots'
        $btnMix.BackColor = $T.SURFACE2; $btnMix.ForeColor = $T.FG_DIM
    }
}
function Update-StartupVisual { $miStartup.Checked = Get-Autostart }
function Refresh-Active {
    $addrs = Get-CurrentDns
    $r1[1].Text = if ($addrs.Count) { ($addrs -join ', ') } else { '-' }
}
function Populate-List {
    $list.Items.Clear()
    $script:Servers = @(Read-Servers)
    foreach ($s in $script:Servers) {
        $avg = Get-AvgMs $s.Name
        $avgText = if ($avg) { "$avg ms" } else { '-' }
        $item = New-Object Windows.Forms.ListViewItem($s.Name)
        $item.SubItems.Add('-') | Out-Null
        $item.SubItems.Add($avgText) | Out-Null
        $item.SubItems.Add('') | Out-Null
        $item.SubItems.Add($s.Primary) | Out-Null
        $item.UseItemStyleForSubItems = $false
        $item.ForeColor = $T.FG
        $item.SubItems[1].ForeColor = $T.FG_DIM
        $item.SubItems[2].ForeColor = $T.FG_DIM
        $item.SubItems[3].ForeColor = $T.FG_DIM
        $item.SubItems[4].ForeColor = $T.FG_DIM
        $list.Items.Add($item) | Out-Null
    }
}
function Highlight-Top2 {
    for ($i=0; $i -lt $list.Items.Count; $i++) { $list.Items[$i].BackColor = $T.SURFACE }
    $fastName = $null; $secName = $null
    if ($script:Fastest -and $script:Fastest.PSObject.Properties['Name']) { $fastName = [string]$script:Fastest.Name }
    if ($script:Second -and $script:Second.PSObject.Properties['Name']) { $secName = [string]$script:Second.Name }
    for ($i=0; $i -lt $list.Items.Count; $i++) {
        $itemName = [string]$list.Items[$i].Text
        if ($fastName -and $itemName -eq $fastName) { $list.Items[$i].BackColor = $T.GOOD_BG }
        elseif ($secName -and $itemName -eq $secName) { $list.Items[$i].BackColor = $T.ROW_2ND }
    }
}
function Set-RowLatency($item, $ms) {
    if (-not $item) { return }
    if ($ms -eq 99999) {
        $item.SubItems[1].Text = 'FAIL'
        $item.SubItems[1].ForeColor = $T.FG_DIM
        $item.SubItems[3].Text = if (Test-Blacklisted $item.SubItems[4].Text) { 'blk' } else { '' }
        $item.SubItems[3].ForeColor = $T.BAD
    } elseif ($ms -le 5) {
        $item.SubItems[1].Text = 'spoof'
        $item.SubItems[1].ForeColor = $T.PURPLE
        $item.SubItems[3].Text = 'spoof'
        $item.SubItems[3].ForeColor = $T.PURPLE
    } else {
        $item.SubItems[1].Text = "$ms ms"
        if ($ms -lt 50) { $item.SubItems[1].ForeColor = $T.GOOD; $item.SubItems[3].Text = '' }
        elseif ($ms -lt 150) { $item.SubItems[1].ForeColor = $T.WARN; $item.SubItems[3].Text = '' }
        else { $item.SubItems[1].ForeColor = $T.BAD; $item.SubItems[3].Text = 'slow'; $item.SubItems[3].ForeColor = $T.BAD }
    }
}

function Invoke-Test {
    param([object]$Single = $null)
    if ($script:Busy) { return }
    Set-Busy $true
    try {
        if ($Single) {
            Set-Status "Testing $($Single.Name)" $T.WARN
            $form.Refresh()
            $ms = [int](Test-Ping $Single.Primary)
            $item = $list.Items | Where-Object { $_.Text -eq $Single.Name } | Select-Object -First 1
            if ($item) { Set-RowLatency $item $ms }
            if ($ms -eq 99999 -or $ms -le 5) {
                Set-Status "$($Single.Name): unreachable" $T.BAD
                Write-Log 'TEST1' "$($Single.Name) FAIL"
            } else {
                Add-History $Single.Name $ms
                Save-History $script:History
                $avg = Get-AvgMs $Single.Name
                if ($item) { $item.SubItems[2].Text = if ($avg) { "$avg ms" } else { '-' } }
                Set-Status "$($Single.Name): $ms ms" $T.GOOD
                Write-Log 'TEST1' "$($Single.Name) $ms ms"
            }
            return
        }
        if ($script:Servers.Count -eq 0) { Populate-List }
        $snapshot = @($script:Servers)
        if ($snapshot.Count -eq 0) { Set-Status 'No servers' $T.BAD; return }

        $r2[1].Text = '-'; $r3[1].Text = '-'
        $progress.Value = 0; $progress.Maximum = $snapshot.Count
        foreach ($item in $list.Items) {
            $item.SubItems[1].Text = '...'
            $item.SubItems[1].ForeColor = $T.WARN
            $item.SubItems[3].Text = ''
        }
        $form.Refresh()
        [System.Windows.Forms.Application]::DoEvents()

        Set-Status "Pinging $($snapshot.Count) servers" $T.WARN
        $batchResults = Test-ServersBatched -Servers $snapshot -Samples 2 -Timeout 700 -BatchSize 10

        $results = @()
        $failCounts = @{}

        foreach ($s in $snapshot) {
            $item = $list.Items | Where-Object { $_.Text -eq $s.Name } | Select-Object -First 1
            $ms = 99999
            if ($batchResults.ContainsKey($s.Name)) { $ms = [int]$batchResults[$s.Name] }
            if ($item) { Set-RowLatency $item $ms }

            if ($ms -ne 99999 -and $ms -gt 5) {
                Add-History $s.Name $ms
                $avg = Get-AvgMs $s.Name
                if ($item) { $item.SubItems[2].Text = if ($avg) { "$avg ms" } else { '-' } }
                $results += [pscustomobject]@{ Server=$s; Ms=[int]$ms }
                $failCounts[$s.Primary] = 0
            } else {
                [int]$cur = 0
                if ($failCounts.ContainsKey($s.Primary)) { $cur = [int]$failCounts[$s.Primary] }
                $failCounts[$s.Primary] = [int]($cur + 1)
                if ($failCounts[$s.Primary] -ge $script:Settings.blacklist_threshold) {
                    Add-Blacklist $s.Primary
                    Write-Log 'BLKLST' "blacklisted $($s.Primary)"
                }
            }
            $progress.Value += 1
            [System.Windows.Forms.Application]::DoEvents()
        }
        Save-History $script:History
        $valLast.Text = (Get-Date -Format 'HH:mm:ss')

        $arrSorted = @($results | ForEach-Object {
            [pscustomobject]@{ Server = $_.Server; Ms = [int]$_.Ms }
        })
        if ($arrSorted.Count -gt 1) {
            $arrSorted = $arrSorted | Sort-Object -Property @{Expression={[int]$_.Ms}}
        }

        if ($arrSorted.Count -ge 1) {
            $script:Fastest = $arrSorted[0].Server
            $r2[1].Text = ('{0}  ({1} ms)' -f $script:Fastest.Name, [int]$arrSorted[0].Ms)
        } else {
            if ($script:Settings.fallback_chain) {
                $script:Fastest = [pscustomobject]@{ Name='Fallback'; Primary=[string]$script:Settings.fallback_primary; Secondary=[string]$script:Settings.fallback_secondary }
                $r2[1].Text = ('Fallback  ({0})' -f $script:Fastest.Primary)
            } else {
                $script:Fastest = $null; $r2[1].Text = 'none reachable'
            }
        }
        if ($arrSorted.Count -ge 2) {
            $script:Second = $arrSorted[1].Server
            $r3[1].Text = ('{0}  ({1} ms)' -f $script:Second.Name, [int]$arrSorted[1].Ms)
        } else { $script:Second = $null; $r3[1].Text = '-' }
        Highlight-Top2
        if ($script:Fastest) {
            Set-Status ('Winner: {0}' -f $script:Fastest.Name) $T.GOOD
            $first = if ($arrSorted.Count -ge 1) { [int]$arrSorted[0].Ms } else { 0 }
            Write-Log 'TEST' ("winner={0} ({1}ms) tested={2}" -f $script:Fastest.Name, $first, $snapshot.Count)
        } else {
            Set-Status 'All failed' $T.BAD
            Write-Log 'TEST' 'all failed'
        }
    }
    catch {
        $ln = $_.InvocationInfo.ScriptLineNumber
        Write-Log "CRASH" ("line $ln : $($_.Exception.Message)")
        Set-Status ("Error line $ln") $T.BAD
    }
    finally {
        Set-Busy $false
        $btnSet.Enabled = ($null -ne $script:Fastest)
        $miApply.Enabled = ($null -ne $script:Fastest)
    }
}

function Invoke-Apply {
    if ($script:Busy -or -not $script:Fastest) { return }
    Set-Busy $true
    try {
        $previous = Get-CurrentDns
        Set-Status 'Applying' $T.WARN
        $valVerify.Text = '...'; $valVerify.ForeColor = $T.WARN
        $form.Refresh()
        $applied = Apply-Dns $script:Fastest $script:MixOn
        Start-Sleep -Milliseconds 400
        if (Verify-Dns) {
            $valVerify.Text = 'ok'; $valVerify.ForeColor = $T.GOOD
            Refresh-Active
            $mode = if ($script:MixOn -and $script:Second) { 'mixed' } else { 'single' }
            Set-Status "Applied ($mode)" $T.GOOD
            $tray.ShowBalloonTip(2500, 'DNSFrenzy', "Applied $($script:Fastest.Name)", 'Info')
            Write-Log 'APPLY' ("{0} {1}+{2} [{3}] ok" -f $script:Fastest.Name, $applied[0], $applied[1], $mode)
            $script:State.LastApply = [pscustomobject]@{ Name=$script:Fastest.Name; Primary=$applied[0]; Secondary=$applied[1]; Mode=$mode; Time=(Get-Date -Format 'o') }
            Save-State $script:State
        } else {
            $valVerify.Text = 'failed'; $valVerify.ForeColor = $T.BAD
            Set-Status 'Reverting' $T.WARN
            $form.Refresh()
            Get-NetAdapter | Where-Object Status -eq 'Up' | ForEach-Object {
                if ($previous.Count -gt 0) { try { Set-DnsClientServerAddress -InterfaceAlias $_.Name -ServerAddresses $previous -EA Stop } catch {} }
            }
            try { ipconfig /flushdns | Out-Null } catch {}
            Refresh-Active
            Set-Status 'Reverted (verify failed)' $T.BAD
            $tray.ShowBalloonTip(2500, 'DNSFrenzy', "Verify failed for $($script:Fastest.Name). Reverted.", 'Warning')
            Write-Log 'APPLY' ("{0} verify=failed, reverted" -f $script:Fastest.Name)
        }
    }
    catch {
        Set-Status 'Apply error' $T.BAD
        $valVerify.Text = 'error'; $valVerify.ForeColor = $T.BAD
        Write-Log 'ERROR' ("apply: $($_.Exception.Message)")
    }
    finally { Set-Busy $false }
}

$btnMix.Add_Click({
    if ($script:Busy) { return }
    $script:MixOn = -not $script:MixOn
    Update-MixVisual
    $script:State.MixOn = $script:MixOn
    Save-State $script:State
})
$btnGo.Add_Click({ Invoke-Test })
$btnSet.Add_Click({ Invoke-Apply })

$rmTest.Add_Click({
    if ($list.SelectedItems.Count -eq 0) { return }
    $srv = $script:Servers | Where-Object { $_.Name -eq $list.SelectedItems[0].Text } | Select-Object -First 1
    if ($srv) { Invoke-Test -Single $srv }
})
$rmApply.Add_Click({
    if ($list.SelectedItems.Count -eq 0) { return }
    $srv = $script:Servers | Where-Object { $_.Name -eq $list.SelectedItems[0].Text } | Select-Object -First 1
    if ($srv) { $script:Fastest = $srv; $script:Second = $null; Invoke-Apply }
})
$rmCopy.Add_Click({
    if ($list.SelectedItems.Count -eq 0) { return }
    try { [System.Windows.Forms.Clipboard]::SetText($list.SelectedItems[0].SubItems[4].Text) } catch {}
})
$rmUnbl.Add_Click({
    if ($list.SelectedItems.Count -eq 0) { return }
    $ip = $list.SelectedItems[0].SubItems[4].Text
    if ($script:Blacklist.ContainsKey($ip)) {
        $null = $script:Blacklist.Remove($ip)
        Save-Blacklist
        Set-Status "Unblacklisted $ip" $T.GOOD
        Populate-List
    }
})

$auto = New-Object Windows.Forms.Timer
$auto.Interval = 60000
$auto.Add_Tick({ if ($script:Busy) { return }; Invoke-Test; if ($script:Fastest) { Invoke-Apply } })

function Toggle-Auto {
    if ($auto.Enabled) {
        $auto.Stop(); $btnAuto.Text = 'Auto: OFF'; $btnAuto.BackColor = $T.SURFACE2
        $miAuto.Checked = $false; Set-Status 'Idle' $T.FG_DIM
    } else {
        $auto.Start(); $btnAuto.Text = 'Auto: ON'; $btnAuto.BackColor = $T.AUTO_BG
        $miAuto.Checked = $true; Set-Status 'Auto · 60s' $T.GOOD; Invoke-Test
    }
}
$btnAuto.Add_Click({ Toggle-Auto })
$miAuto.Add_Click({ Toggle-Auto })

$miShow.Add_Click({ $form.Show(); $form.WindowState = 'Normal'; $form.Activate() })
$miTest.Add_Click({ Invoke-Test })
$miApply.Add_Click({ Invoke-Apply })
$miStartup.Add_Click({ Set-Autostart (-not (Get-Autostart)); Update-StartupVisual })

$miExport.Add_Click({
    $dlg = New-Object System.Windows.Forms.SaveFileDialog
    $dlg.Filter = 'DNSFrenzy config (*.zip)|*.zip'
    $dlg.FileName = "dnsfrenzy-config-$(Get-Date -Format 'yyyyMMdd').zip"
    if ($dlg.ShowDialog() -eq 'OK') {
        $tmp = Join-Path $env:TEMP "dnsfrenzy-export-$(Get-Random)"
        New-Item -ItemType Directory -Path "$tmp\config" -Force | Out-Null
        Copy-Item $ServerFile "$tmp\config\servers.txt" -Force
        Copy-Item $SettingsFile "$tmp\settings.json" -Force -EA SilentlyContinue
        Copy-Item $StatePath "$tmp\state.json" -Force -EA SilentlyContinue
        Compress-Archive -Path "$tmp\*" -DestinationPath $dlg.FileName -Force
        Remove-Item $tmp -Recurse -Force
        [System.Windows.Forms.MessageBox]::Show("Exported.", 'DNSFrenzy') | Out-Null
        Write-Log 'EXPORT' $dlg.FileName
    }
})
$miImport.Add_Click({
    $dlg = New-Object System.Windows.Forms.OpenFileDialog
    $dlg.Filter = 'DNSFrenzy config (*.zip)|*.zip'
    if ($dlg.ShowDialog() -eq 'OK') {
        $tmp = Join-Path $env:TEMP "dnsfrenzy-import-$(Get-Random)"
        try {
            Expand-Archive -Path $dlg.FileName -DestinationPath $tmp -Force
            $src = Join-Path $tmp 'config\servers.txt'
            if (Test-Path $src) { Copy-Item $src $ServerFile -Force }
            Populate-List
            [System.Windows.Forms.MessageBox]::Show("Imported.", 'DNSFrenzy') | Out-Null
            Write-Log 'IMPORT' $dlg.FileName
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Import failed: $($_.Exception.Message)", 'DNSFrenzy') | Out-Null
        } finally { Remove-Item $tmp -Recurse -Force -EA SilentlyContinue }
    }
})
$miLog.Add_Click({
    if (Test-Path $LogPath) { Start-Process notepad.exe $LogPath }
    else { [System.Windows.Forms.MessageBox]::Show("No log yet.", 'DNSFrenzy') | Out-Null }
})
$miExit.Add_Click({
    $script:Exiting = $true
    $auto.Stop()
    Save-State $script:State
    Save-History $script:History
    Save-Settings
    Write-Log 'EXIT' 'user exit'
    $tray.Visible = $false; $tray.Dispose(); $form.Close()
})

$tray.Add_DoubleClick({ $form.Show(); $form.WindowState = 'Normal'; $form.Activate() })
$form.Add_Resize({ if ($form.WindowState -eq 'Minimized') { $form.Hide() } })
$form.Add_FormClosing({
    param($sender, $e)
    if (-not $script:Exiting) {
        $e.Cancel = $true
        $form.Hide()
        $tray.ShowBalloonTip(1500, 'DNSFrenzy', 'Still running in tray.', 'Info')
    }
})

Update-MixVisual
Update-StartupVisual
Populate-List
Refresh-Active
Set-Status 'Ready' $T.FG_DIM
Write-Log 'START' ("launch (mix={0})" -f $script:MixOn)
[Windows.Forms.Application]::Run($form)

