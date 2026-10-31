# SentinelX Windows endpoint agent installer
# Run from an elevated PowerShell session.
$ErrorActionPreference = "Stop"

$Repo = "https://github.com/eetemanojkumar-sys/sentinelex"
$Branch = "scale-1000-servers"
$InstallDir = Join-Path $env:ProgramFiles "SentinelX"
$DataDir = Join-Path $env:ProgramData "SentinelX"
$TaskName = "SentinelX-Windows-Agent"

# Stop any previous scheduled instance before replacing its executable files.
if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Open PowerShell with Run as administrator, then rerun the installer."
}

Write-Host "SentinelX Windows agent installer" -ForegroundColor Cyan
$CentralUrl = Read-Host "Central API base URL (example: https://172.31.41.98:8443)"
if ([string]::IsNullOrWhiteSpace($CentralUrl)) { throw "Central API URL is required." }
$CentralUrl = $CentralUrl.TrimEnd("/")
$SecureToken = Read-Host "SentinelX agent token" -AsSecureString
if ($SecureToken.Length -eq 0) { throw "Agent token is required." }
$CaSource = Read-Host "Path to central API CA/server certificate (press Enter if publicly trusted)"

$PythonCommand = Get-Command py -ErrorAction SilentlyContinue
if ($PythonCommand) {
    $PythonExe = (& py -3 -c "import sys; print(sys.executable)").Trim()
} else {
    $PythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $PythonCommand) { throw "Python 3.10+ is required. Install Python and rerun." }
    $PythonExe = $PythonCommand.Source
}
if (-not (Test-Path $PythonExe)) { throw "Could not locate Python executable." }

$Zip = Join-Path $env:TEMP "sentinelx-$Branch.zip"
$Extract = Join-Path $env:TEMP "sentinelx-$Branch"
$ArchiveUrl = "$Repo/archive/refs/heads/$Branch.zip"
Write-Host "Downloading SentinelX..." -ForegroundColor Cyan
Invoke-WebRequest -Uri $ArchiveUrl -OutFile $Zip
if (Test-Path $Extract) { Remove-Item $Extract -Recurse -Force }
Expand-Archive -Path $Zip -DestinationPath $Extract -Force
$AgentFile = Get-ChildItem -Path $Extract -Filter "agent.py" -Recurse |
    Where-Object { $_.Directory.Name -eq "agent" } | Select-Object -First 1
if (-not $AgentFile) { throw "Downloaded repository does not contain agent/agent.py." }
$RepoRoot = $AgentFile.Directory.Parent.FullName

if (Test-Path $InstallDir) { Remove-Item $InstallDir -Recurse -Force }
New-Item -ItemType Directory -Path $InstallDir -Force | Out-Null
Copy-Item (Join-Path $RepoRoot "agent") (Join-Path $InstallDir "agent") -Recurse -Force
Copy-Item (Join-Path $RepoRoot "requirements.txt") (Join-Path $InstallDir "requirements.txt") -ErrorAction SilentlyContinue

& $PythonExe -m venv (Join-Path $InstallDir ".venv")
$VenvPython = Join-Path $InstallDir ".venv\Scripts\python.exe"
& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install -r (Join-Path $InstallDir "agent\requirements.txt")

New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
$CaLine = ""
if (-not [string]::IsNullOrWhiteSpace($CaSource)) {
    if (-not (Test-Path $CaSource)) { throw "Certificate file not found: $CaSource" }
    $CaTarget = Join-Path $InstallDir "server-ca.crt"
    Copy-Item $CaSource $CaTarget -Force
    Import-Certificate -FilePath $CaTarget -CertStoreLocation "Cert:\LocalMachine\Root" | Out-Null
    $CaLine = '$env:REQUESTS_CA_BUNDLE = "' + $CaTarget + '"'
}

# Protect the token with machine-scope DPAPI so only this Windows machine can decrypt it.
Add-Type -AssemblyName System.Security
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureToken)
try {
    $plainText = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr)
    $plainBytes = [Text.Encoding]::UTF8.GetBytes($plainText)
    $protectedBytes = [Security.Cryptography.ProtectedData]::Protect(
        $plainBytes, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine
    )
    [Convert]::ToBase64String($protectedBytes) |
        Set-Content -Path (Join-Path $DataDir "agent.token.dpapi") -Encoding ASCII
} finally {
    [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr)
    if ($plainBytes) { [Array]::Clear($plainBytes, 0, $plainBytes.Length) }
    Remove-Variable plainText, SecureToken -ErrorAction SilentlyContinue
}

$Runner = @'
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Security
$tokenFile = Join-Path $env:ProgramData "SentinelX\agent.token.dpapi"
$encrypted = [Convert]::FromBase64String((Get-Content $tokenFile -Raw).Trim())
$plain = [Security.Cryptography.ProtectedData]::Unprotect(
    $encrypted, $null, [Security.Cryptography.DataProtectionScope]::LocalMachine
)
try {
    $env:SENTINELX_AGENT_TOKEN = [Text.Encoding]::UTF8.GetString($plain)
    $env:SENTINELX_URL = "__CENTRAL_URL__"
    $env:SENTINELX_HOST_ID = $env:COMPUTERNAME
    $env:SENTINELX_INTERVAL = "30"
    __CA_LINE__
    Set-Location "__INSTALL_DIR__\agent"
    $python = "__INSTALL_DIR__\.venv\Scripts\python.exe"
    & $python ".\agent.py" *>> (Join-Path $env:ProgramData "SentinelX\agent.log")
} finally {
    [Array]::Clear($plain, 0, $plain.Length)
    [Array]::Clear($encrypted, 0, $encrypted.Length)
    Remove-Item Env:\SENTINELX_AGENT_TOKEN -ErrorAction SilentlyContinue
}
'@
$Runner = $Runner.Replace("__CENTRAL_URL__", $CentralUrl.Replace('"',''))
$Runner = $Runner.Replace("__INSTALL_DIR__", $InstallDir.Replace('"',''))
if ($CaLine) { $Runner = $Runner.Replace("__CA_LINE__", $CaLine) }
else { $Runner = $Runner.Replace("__CA_LINE__", "# Using Windows/Python system certificate trust") }
$RunnerPath = Join-Path $InstallDir "Run-SentinelX.ps1"
Set-Content -Path $RunnerPath -Value $Runner -Encoding UTF8

# Restrict installer data, encrypted token and runner to SYSTEM and local Administrators.
& icacls $DataDir /inheritance:r | Out-Null
& icacls $DataDir /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" | Out-Null
& icacls $InstallDir /inheritance:r | Out-Null
& icacls $InstallDir /grant:r "SYSTEM:(OI)(CI)F" "Administrators:(OI)(CI)F" /T /C | Out-Null

# Test central API reachability using the same certificate bundle before registering the task.
$HealthTest = @'
import os, requests, sys
url = os.environ["SENTINELX_URL"].rstrip("/") + "/health"
ca = os.environ.get("REQUESTS_CA_BUNDLE") or True
response = requests.get(url, verify=ca, timeout=10)
response.raise_for_status()
print(response.json())
'@
$env:SENTINELX_URL = $CentralUrl
if ($CaLine) { $env:REQUESTS_CA_BUNDLE = $CaTarget }
try { $HealthTest | & $VenvPython -; if ($LASTEXITCODE -ne 0) { throw "Central API health check failed." } }
finally { Remove-Item Env:\SENTINELX_URL -ErrorAction SilentlyContinue; Remove-Item Env:\REQUESTS_CA_BUNDLE -ErrorAction SilentlyContinue }

if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
    Stop-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
}
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$RunnerPath`""
$Trigger = New-ScheduledTaskTrigger -AtStartup
$TaskPrincipal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -RestartCount 3 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero)
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $TaskPrincipal -Settings $Settings -Description "SentinelX Windows monitoring agent" -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 5

$Task = Get-ScheduledTask -TaskName $TaskName
$Info = Get-ScheduledTaskInfo -TaskName $TaskName
Write-Host ""
Write-Host "SentinelX Windows agent installation finished." -ForegroundColor Green
Write-Host ("Task state: " + $Task.State)
Write-Host ("Last task result: " + $Info.LastTaskResult)
Write-Host ("Agent log: " + (Join-Path $env:ProgramData "SentinelX\agent.log"))
Write-Host "Verify ingestion on the central server: journalctl -u sentinelx-api -n 20 --no-pager"
