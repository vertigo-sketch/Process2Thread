# =====================================================
# AutoCaptureAnalyze_Dump_V30.9_STABLE
# End-to-end working capture + analysis
# =====================================================

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

[CmdletBinding()]
param(
    [int]$ObservationWindowSeconds = 15,
    [int]$MonitorIntervalSeconds  = 5,
    [int]$CooldownSeconds         = 600,
    [switch]$SinglePass
)

# -----------------------------
# Admin check
# -----------------------------
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
}

# -----------------------------
# Paths
# -----------------------------
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DumpRoot   = Join-Path $ScriptRoot 'Dumps'
$LogRoot    = Join-Path $ScriptRoot 'Logs'
$LogFile    = Join-Path $LogRoot 'AutoCapture.log'

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
# Snapshot
# -----------------------------
function Get-ProcessSnapshot {
    $snap = @{}
    foreach ($p in Get-Process) {
        try {
            $snap[$p.Id] = [pscustomobject]@{
                ProcessId  = $p.Id
                Name       = $p.ProcessName
                Responding = $p.Responding
                Threads    = $p.Threads.Count
            }
        } catch {}
    }
    $snap
}

# -----------------------------
# Detection
# -----------------------------
function Test-UIHang {
    param($Before,$After)
    return ($Before.Responding -and -not $After.Responding)
}

# -----------------------------
# Dump
# -----------------------------
function Invoke-ProcDump {
    param(
        [int]$TargetProcessId,
        [string]$DumpPath
    )

    $args = "-accepteula -ma $TargetProcessId `"$DumpPath`""
    Write-Log "Invoking ProcDump PID=$TargetProcessId"

    $p = Start-Process -FilePath $ProcDumpPath `
                       -ArgumentList $args `
                       -NoNewWindow -Wait -PassThru

    if ($p.ExitCode -ne 0 -or -not (Test-Path $DumpPath)) {
        Write-Log "ProcDump failed ExitCode=$($p.ExitCode)"
        return $false
    }

    Write-Log "Dump created: $DumpPath"
    return $true
}

# -----------------------------
# CDB
# -----------------------------
function Write-CdbCmdFile {
    param([string]$DumpPath)
    $cmd = [System.IO.Path]::ChangeExtension($DumpPath,'cdb.cmd.txt')
    @(
        '.symfix'
        '.reload'
        '!analyze -hang'
        '~* kb'
        'q'
    ) | Out-File -Encoding ASCII -Force $cmd
    return $cmd
}

function Invoke-Cdb {
    param([string]$DumpPath)

    $cmdFile = Write-CdbCmdFile $DumpPath
    $logPath = [System.IO.Path]::ChangeExtension($DumpPath,'cdb.log.txt')

    Write-Log "Invoking CDB for $DumpPath"

    & $CdbPath -z "`"$DumpPath`"" -cf "`"$cmdFile`"" > $logPath 2>&1

    if (Test-Path $logPath) {
        Write-Log "CDB analysis complete: $logPath"
        return $true
    }

    Write-Log "CDB failed"
    return $false
}

# -----------------------------
# Cooldown
# -----------------------------
$LastCapture = @{}
function In-Cooldown {
    param([int]$ProcessId)
    if ($LastCapture.ContainsKey($ProcessId)) {
        return ((Get-Date) - $LastCapture[$ProcessId]).TotalSeconds -lt $CooldownSeconds
    }
    return $false
}
function Mark-Captured {
    param([int]$ProcessId)
    $LastCapture[$ProcessId] = Get-Date
}

# =============================
# MAIN LOOP
# =============================
Write-Log "=== AutoCapture V30.9 START ==="

do {
    Write-Log "PASS START"

    $before = Get-ProcessSnapshot
    Start-Sleep $ObservationWindowSeconds
    $after  = Get-ProcessSnapshot

    foreach ($pid in $before.Keys) {
        if (-not $after.ContainsKey($pid)) { continue }
        if (In-Cooldown $pid) { continue }

        if (Test-UIHang $before[$pid] $after[$pid]) {
            $dump = Join-Path $DumpRoot "UIHang_$pid.dmp"

            if (Invoke-ProcDump -TargetProcessId $pid -DumpPath $dump) {
                Invoke-Cdb -DumpPath $dump | Out-Null
                Mark-Captured $pid
            }
        }
    }

    Start-Sleep $MonitorIntervalSeconds

} while (-not $SinglePass)

Write-Log "=== AutoCapture V30.9 END ==="
``