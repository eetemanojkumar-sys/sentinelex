#requires -RunAsAdministrator
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidateNotNullOrEmpty()][string]$CentralUrl,
    [string]$BootstrapToken,
    [ValidateRange(5,3600)][int]$IntervalSeconds = 30,
    [string]$InstallDir = "$env:ProgramFiles\SentinelX"
)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
if ([string]::IsNullOrWhiteSpace($BootstrapToken)) {
    $SecureToken = Read-Host "Enter SentinelX bootstrap token" -AsSecureString
    $Ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($SecureToken)
    try { $BootstrapToken = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($Ptr) }
    finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($Ptr) }
}
function Write-Step([string]$Message) { Write-Host "[SentinelX] $Message" -ForegroundColor Cyan }

if ($CentralUrl -notmatch '^https?://') { throw "CentralUrl must start with http:// or https://." }
$CentralUrl = $CentralUrl.TrimEnd('/')
if ($CentralUrl -match '^http://' -and $CentralUrl -notmatch '^http://(localhost|127\.0\.0\.1|172\.|10\.|192\.168\.)') {
    Write-Warning "The central URL uses unencrypted HTTP. Prefer HTTPS with a trusted certificate for remote endpoints."
}

Write-Step "Checking Python 3.12+"
$PythonCmd = Get-Command python.exe -ErrorAction SilentlyContinue
$PythonPath = $null
if ($PythonCmd) {
    try {
        $Version = & $PythonCmd.Source --version 2>&1
        if ($Version -match 'Python 3\.(1[2-9]|[2-9][0-9])') { $PythonPath = $PythonCmd.Source }
    } catch {}
}
if (-not $PythonPath) {
    $Installer = Join-Path $env:TEMP "python-3.12.10-amd64.exe"
    Invoke-WebRequest -Uri "https://www.python.org/ftp/python/3.12.10/python-3.12.10-amd64.exe" -OutFile $Installer
    $p = Start-Process -FilePath $Installer -ArgumentList "/quiet InstallAllUsers=1 PrependPath=1 Include_test=0" -Wait -PassThru
    if ($p.ExitCode -notin 0,3010) { throw "Python installation failed with exit code $($p.ExitCode)." }
    $PythonPath = "$env:ProgramFiles\Python312\python.exe"
}
if (-not (Test-Path $PythonPath)) { throw "Python executable was not found after installation." }

Write-Step "Downloading SentinelX agent release"
$RepoZip = Join-Path $env:TEMP "sentinelx-deployment-automation.zip"
$ExtractDir = Join-Path $env:TEMP ("sentinelx-" + [guid]::NewGuid().ToString("N"))
Invoke-WebRequest -Uri "https://github.com/eetemanojkumar-sys/sentinelex/archive/refs/heads/deployment-automation.zip" -OutFile $RepoZip
Expand-Archive -Path $RepoZip -DestinationPath $ExtractDir -Force
$RepoRoot = Get-ChildItem $ExtractDir -Directory | Select-Object -First 1
if (-not $RepoRoot) { throw "Could not find extracted SentinelX repository." }

New-Item -ItemType Directory -Force -Path $InstallDir | Out-Null
Copy-Item -Path (Join-Path $RepoRoot.FullName "agent") -Destination $InstallDir -Recurse -Force

Write-Step "Installing Python dependencies"
$Venv = Join-Path $InstallDir "venv"
if (-not (Test-Path (Join-Path $Venv "Scripts\python.exe"))) { & $PythonPath -m venv $Venv }
$VenvPython = Join-Path $Venv "Scripts\python.exe"
& $VenvPython -m pip install --upgrade pip
& $VenvPython -m pip install -r (Join-Path $InstallDir "agent\requirements.txt")

Write-Step "Writing protected configuration"
$DataDir = Join-Path $env:ProgramData "SentinelX"
New-Item -ItemType Directory -Force -Path $DataDir | Out-Null
$Config = Join-Path $DataDir "sentinelx.env"
$StateFile = Join-Path $DataDir "agent.json"
$envLines = @(
    "SENTINELX_URL=$CentralUrl",
    "SENTINELX_AGENT_TOKEN=$BootstrapToken",
    "SENTINELX_INTERVAL=$IntervalSeconds",
    "SENTINELX_STATE_FILE=$StateFile",
    "SENTINELX_INSTALL_DIR=$InstallDir",
    "SENTINELX_WATCH_PATHS=$env:SystemRoot\System32\drivers\etc"
)
[System.IO.File]::WriteAllLines($Config, $envLines, [System.Text.UTF8Encoding]::new($false))
$Acl = Get-Acl $DataDir
$Acl.SetAccessRuleProtection($true, $false)
foreach ($rule in @($Acl.Access)) { [void]$Acl.RemoveAccessRule($rule) }
$SystemRule = New-Object System.Security.AccessControl.FileSystemAccessRule("SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule("Administrators","FullControl","ContainerInherit,ObjectInherit","None","Allow")
$Acl.AddAccessRule($SystemRule)
$Acl.AddAccessRule($AdminRule)
Set-Acl -Path $DataDir -AclObject $Acl

Write-Step "Creating agent launcher"
$Launcher = Join-Path $InstallDir "run-agent.ps1"
@'
$ErrorActionPreference = "Stop"
$Config = Join-Path $env:ProgramData "SentinelX\sentinelx.env"
Get-Content $Config | ForEach-Object {
    if ($_ -match '^([^#=]+)=(.*)$') {
        [Environment]::SetEnvironmentVariable($matches[1], $matches[2], "Process")
    }
}
$Python = Join-Path $PSScriptRoot "venv\Scripts\python.exe"
$Agent = Join-Path $PSScriptRoot "agent\agent.py"
& $Python $Agent
exit $LASTEXITCODE
'@ | Set-Content -Path $Launcher -Encoding UTF8

Write-Step "Registering Windows startup task"
$TaskName = "SentinelX Agent"
$ActionArgs = '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' + $Launcher + '"'
$Action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument $ActionArgs
$Trigger = New-ScheduledTaskTrigger -AtStartup
$Principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
$Settings = New-ScheduledTaskSettingsSet -RestartCount 999 -RestartInterval (New-TimeSpan -Minutes 1) -ExecutionTimeLimit ([TimeSpan]::Zero) -StartWhenAvailable
Register-ScheduledTask -TaskName $TaskName -Action $Action -Trigger $Trigger -Principal $Principal -Settings $Settings -Force | Out-Null
Start-ScheduledTask -TaskName $TaskName
Start-Sleep -Seconds 3
$Task = Get-ScheduledTask -TaskName $TaskName
if ($Task.State -eq "Disabled") { throw "SentinelX scheduled task is disabled." }

Remove-Item $ExtractDir -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item $RepoZip -Force -ErrorAction SilentlyContinue
Write-Host "SentinelX Windows agent installed." -ForegroundColor Green
Write-Host "Task: $TaskName"
Write-Host "Config: $Config (SYSTEM and Administrators only)"
Write-Host "Agent state: $StateFile"
Write-Host "Check: Get-ScheduledTaskInfo -TaskName '$TaskName'"
Write-Host "First run enrolls this Windows endpoint with the central API."
