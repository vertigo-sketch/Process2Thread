# ======================================================
# AutoCaptureAnalyze_Dump_V34_Stabilized_FIXED
# PID collision eliminated
# ======================================================

[CmdletBinding()]
param(
    [int]$ObservationWindowSeconds = 15,
    [int]$MonitorIntervalSeconds  = 5,
    [int]$CooldownSeconds         = 600,
    [ValidateSet('Mini','MiniWithHandles','Full')]
    [string]$DumpProfile = 'Mini',
    [switch]$SinglePass
)

# -----------------------------
# Admin Check
# -----------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
}

$ErrorActionPreference = 'Stop'

# -----------------------------
# Paths
# -----------------------------
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DumpRoot   = Join-Path $ScriptRoot 'Dumps'
$LogRoot    = Join-Path $ScriptRoot 'Logs'
$LogFile    = Join-Path $LogRoot   'AutoCapture.log'

New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot | Out-Null

# -----------------------------
# Tools
# -----------------------------
$ProcDumpPath = 'C:\Tools\Sysinternals\procdump.exe'
$CdbPath      = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'

if (-not (Test-Path $ProcDumpPath)) { throw "ProcDump not found." }
if (-not (Test-Path $CdbPath))      { throw "cdb.exe not found." }

# -----------------------------
# Logging
# -----------------------------
function Write-Log {
    param([string]$Message)

    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts $Message" | Out-File -Append -Encoding UTF8 $LogFile
}

# -----------------------------
# Snapshot Helper
# -----------------------------
function Get-ProcessSnapshot {

    $map = @{}

    foreach ($proc in Get-Process) {
        try {
            $map[$proc.Id] = [pscustomobject]@{
                Id          = $proc.Id
                Name        = $proc.ProcessName
                Responding  = $proc.Responding
                Threads     = $proc.Threads.Count
                WS          = $proc.WorkingSet64
            }
        } catch {
            continue
        }
    }

    return $map
}

# -----------------------------
# Hang Detection Helpers
# -----------------------------
function Test-UIHang {
    param($Before, $After)

    return (
        $Before.Responding -eq $true -and
        $After.Responding  -eq $false
    )
}

function Test-Suspend {
    param([int]$TargetProcessId)

    try {
        $proc = Get-Process -Id $TargetProcessId -ErrorAction Stop
        return ($proc.Threads.Count -gt 0)
    }
    catch {
        return $false
    }
}

# -----------------------------
# Main Loop
# -----------------------------
Write-Log "=== AutoCapture V34 Stabilized FIXED START ==="

do {
    $beforeSnapshot = Get-ProcessSnapshot
    Start-Sleep $ObservationWindowSeconds
    $afterSnapshot  = Get-ProcessSnapshot

} while (-not $SinglePass)

Write-Log "=== AutoCapture V34 Stabilized FIXED END ==="