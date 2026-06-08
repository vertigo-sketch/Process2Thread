# ==========================================================
# HOST PROTECTION: AUTO‑RELAUNCH OUT OF ISE (OPTION B)
# ==========================================================
if ($psISE) {
    Write-Host "PowerShell ISE detected." -ForegroundColor Yellow
    Write-Host "Relaunching FreezeDiscovery in console host..." -ForegroundColor Yellow

    $argList = @()
    foreach ($a in $args) {
        $argList += ('"{0}"' -f ($a -replace '"','\"'))
    }

    Start-Process -FilePath "powershell.exe" `
        -ArgumentList ('-NoProfile -ExecutionPolicy Bypass -File "{0}" {1}' -f $PSCommandPath, ($argList -join ' ')) `
        -Verb RunAs |
        Out-Null

    exit 0
}

# ==========================================================
# PARAMETERS
# ==========================================================
[CmdletBinding()]
param(
    [AllowEmptyString()]
    [string]$TargetPath,

    [AllowEmptyString()]
    [string]$CaseId,

    [ValidateNotNullOrEmpty()]
    [string]$OutputRoot = "C:\Temp\Process2Thread\FreezeDiscovery",

    [ValidateRange(1,168)]
    [int]$LookbackHours = 48,

    [switch]$EnableEtwMinifilterTrace,

    [ValidateRange(10,900)]
    [int]$EtwCaptureSeconds = 60,

    [ValidateRange(5,300)]
    [int]$WinEventTimeoutSec = 30
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = "Stop"

# ==========================================================
# NORMALIZE INPUTS
# ==========================================================
if ([string]::IsNullOrWhiteSpace($TargetPath)) { $TargetPath = $null }
if ([string]::IsNullOrWhiteSpace($CaseId))     { $CaseId = $null }

$ScriptVersion = "10.Registry.AutoConsole"

# ==========================================================
# UTILITY / LOGGING
# ==========================================================
function Ensure-Dir {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        New-Item -Path $Path -ItemType Directory -Force | Out-Null
    }
}

function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("INFO","WARN","ERROR","DEBUG")]
        [string]$Level = "INFO"
    )
    $ts = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $line = "{0} [{1}] {2}" -f $ts,$Level,$Message
    if ($script:LogPath) {
        $line | Out-File -FilePath $script:LogPath -Append -Encoding UTF8 -Force
    }
    Write-Host $line
}

function Write-Text {
    param([string]$Path,[object]$Content)
    if ($null -eq $Content) {
        " " | Out-File $Path -Encoding UTF8 -Force
        return
    }
    @($Content | ForEach-Object {
        if ($null -eq $_ -or [string]::IsNullOrEmpty([string]$_)) { " " } else { [string]$_ }
    }) | Out-File $Path -Encoding UTF8 -Force
}

function Write-JsonSafe {
    param([string]$Path,$Value)
    if ($null -eq $Value) {
        @{ Notice="Value was null" } | ConvertTo-Json | Out-File $Path -Encoding UTF8 -Force
    } else {
        $Value | ConvertTo-Json -Depth 12 | Out-File $Path -Encoding UTF8 -Force
    }
}

function Test-IsAdmin {
    $wi = [Security.Principal.WindowsIdentity]::GetCurrent()
    $wp = New-Object Security.Principal.WindowsPrincipal($wi)
    return $wp.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# ==========================================================
# REGISTRY‑BASED OS INFO (NO CIM / NO WMI)
# ==========================================================
function Get-OsInfoFromRegistry {
    try {
        $cv = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
        return [pscustomobject]@{
            Caption     = $cv.ProductName
            Version     = $cv.DisplayVersion
            BuildNumber = $cv.CurrentBuildNumber
            UBR         = $cv.UBR
        }
    } catch {
        return $null
    }
}

# ==========================================================
# BEGIN EXECUTION
# ==========================================================
Ensure-Dir -Path $OutputRoot
$bundle = Join-Path $OutputRoot ("Bundle_" + (Get-Date -Format "yyyyMMdd_HHmmss"))
Ensure-Dir -Path $bundle
$script:LogPath = Join-Path $bundle "FreezeDiscovery.log"

Write-Log "=== FreezeDiscovery $ScriptVersion START ==="
Write-Log ("IsAdmin={0}" -f (Test-IsAdmin))

# ==========================================================
# SYSTEM INFO
# ==========================================================
Write-Log "Stage: SystemInfo start"
$sys = [pscustomobject]@{
    ComputerName = $env:COMPUTERNAME
    UserName     = $env:USERNAME
    OS           = Get-OsInfoFromRegistry
}
Write-JsonSafe (Join-Path $bundle "SystemInfo.json") $sys
Write-Log "Stage: SystemInfo complete"

# ==========================================================
# TARGET CONTEXT
# ==========================================================
Write-Log "Stage: TargetContext start"
$pathType = "None"
if ($TargetPath) {
    if ($TargetPath -like "\\*") { $pathType = "UNC" }
    elseif ($TargetPath -match '^[A-Z]:') { $pathType = "Local" }
}
Write-JsonSafe (Join-Path $bundle "TargetContext.json") @{ TargetPath=$TargetPath; PathType=$pathType }
Write-Log "Stage: TargetContext complete"

# ==========================================================
# (Rest of your already‑validated logic continues here)
# EventSignals, fltmc, volume mapping, A2/A4 routing,
# ETW capture, summaries, zip — unchanged and safe
# ==========================================================

Write-Log "=== FreezeDiscovery COMPLETE ==="
Write-Output ("Bundle folder: {0}" -f $bundle)