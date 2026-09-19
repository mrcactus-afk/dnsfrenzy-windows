if (-not (Get-Module -ListAvailable ps2exe)) { Install-Module ps2exe -Scope CurrentUser -Force }
Invoke-PS2EXE -InputFile  "$PSScriptRoot\dnsfrenzy.ps1" `
              -OutputFile "$PSScriptRoot\DNSFrenzy.exe" `
              -NoConsole -STA -Title 'DNSFrenzy'
Write-Host "Built: $PSScriptRoot\DNSFrenzy.exe" -ForegroundColor Green
