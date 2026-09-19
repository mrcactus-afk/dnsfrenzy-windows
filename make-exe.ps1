# DNSFrenzy build script
# Compiles src/dnsfrenzy.ps1 into build/DNSFrenzy.exe
# Requires the ps2exe module: Install-Module ps2exe -Scope CurrentUser -Force

$root = $PSScriptRoot
$src = Join-Path $root 'src\dnsfrenzy.ps1'
$buildDir = Join-Path $root 'build'
$exeOut = Join-Path $buildDir 'DNSFrenzy.exe'
$configSrc = Join-Path $root 'config\servers.txt'
$configDst = Join-Path $buildDir 'config\servers.txt'

if (-not (Test-Path $src)) {
    Write-Host "Source not found: $src" -ForegroundColor Red
    exit 1
}

Get-Process DNSFrenzy -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Milliseconds 500

New-Item -ItemType Directory -Path $buildDir -Force | Out-Null
New-Item -ItemType Directory -Path (Split-Path $configDst -Parent) -Force | Out-Null
New-Item -ItemType Directory -Path (Join-Path $buildDir 'data') -Force | Out-Null

if (-not (Get-Module -ListAvailable ps2exe)) {
    Write-Host "Installing ps2exe module..." -ForegroundColor Yellow
    Install-Module ps2exe -Scope CurrentUser -Force
}

Invoke-PS2EXE -InputFile  $src `
              -OutputFile $exeOut `
              -NoConsole -STA -Title 'DNSFrenzy'

Copy-Item $configSrc $configDst -Force

Write-Host "Built: $exeOut" -ForegroundColor Green
