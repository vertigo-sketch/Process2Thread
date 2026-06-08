<#
AutoCaptureAnalyze_Dump_V37.9_FIXED
Fully working, parser‑clean, end‑to‑end
#>

[CmdletBinding()]
param(
    [int]$ObservationWindowSeconds = 15,
    [int]$MonitorIntervalSeconds  = 5,
    [int]$CooldownSeconds         = 600,
    [switch]$SinglePass
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ===============================
# Admin check
# ===============================
$principal = New-Object Security.Principal.WindowsPrincipal(
    [Security.Principal.WindowsIdentity]::GetCurrent()
)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run PowerShell as Administrator."
}

# ===============================
# Paths
# ===============================
$ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$DumpRoot   = Join-Path $ScriptRoot 'Dumps'
$LogRoot    = Join-Path $ScriptRoot 'Logs'
$LogFile    = Join-Path $LogRoot 'AutoCapture.log'

New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot | Out-Null

# ===============================
# Tools
# ===============================
$ProcDumpPath = 'C:\Tools\Sysinternals\procdump.exe'
$CdbPath      = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'

if (-not (Test-Path $ProcDumpPath)) { throw "ProcDump not found: $ProcDumpPath" }
if (-not (Test-Path $CdbPath))      { throw "cdb.exe not found: $CdbPath" }

# ===============================
# Logging
# ===============================
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts $Message" | Out-File -Append -Encoding UTF8 $LogFile
}

# ===============================
# Snapshot
# ===============================
function Get-ProcessSnapshot {
    $snap = @{}
    foreach ($p in Get-Process) {
        try {
            $snap[$p.Id] = [pscustomobject]@{
                ProcessId  = $p.Id
                Name       = $p.ProcessName
                Responding = $p.Responding
                ThreadCount= $p.Threads.Count
            }
        } catch {}
    }
    return $snap
}

# ===============================
# Detection
# ===============================
function Test-UIHang {
    param($Before, $After)
    return ($Before.Responding -and -not $After.Responding)
}

# ===============================
# ProcDump
# ===============================
function Invoke-ProcDump {
    param(
        [int]$TargetProcessId,
        [string]$DumpPath
    )

    $args = "-accepteula -ma $TargetProcessId `"$DumpPath`""
    Write-Log "ProcDump PID=$TargetProcessId"

    $proc = Start-Process -FilePath $ProcDumpPath `
                          -ArgumentList $args `
                          -NoNewWindow -Wait -PassThru

    if ($proc.ExitCode -ne 0 -or -not (Test-Path $DumpPath)) {
        Write-Log "ProcDump FAILED ExitCode=$($proc.ExitCode)"
        return $false
    }

    Write-Log "Dump created: $DumpPath"
    return $true
}

# ===============================
# CDB
# ===============================
function Write-CdbCmdFile {
    param([string]$DumpPath)

    $cmdFile = [System.IO.Path]::ChangeExtension($DumpPath, 'cdb.cmd.txt')
    @(
        '.symfix'
        '.reload'
        '!analyze -hang'
        '~* kb'
        'q'
    ) | Out-File -Encoding ASCII -Force $cmdFile

    return $cmdFile
}

function Invoke-Cdb {
    param([string]$DumpPath)

    $cmdFile = Write-CdbCmdFile $DumpPath
    $logFile = [System.IO.Path]::ChangeExtension($DumpPath, 'cdb.log.txt')

    Write-Log "CDB analyzing $DumpPath"

    & $CdbPath -z "`"$DumpPath`"" -cf "`"$cmdFile`"" > $logFile 2>&1

    if (Test-Path $logFile) {
        Write-Log "CDB output: $logFile"
        return $true
    }

    Write-Log "CDB FAILED"
    return $false
}

# ===============================
# Cooldown
# ===============================
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

# ===============================
# MAIN LOOP
# ===============================
Write-Log "=== AutoCapture V37.9 START ==="

do {
    Write-Log "PASS START"

    $before = Get-ProcessSnapshot
    Start-Sleep $ObservationWindowSeconds
    $after  = Get-ProcessSnapshot

    foreach ($processId in $before.Keys) {
        if (-not $after.ContainsKey($processId)) { continue }
        if (In-Cooldown $processId) { continue }

        if (Test-UIHang $before[$processId] $after[$processId]) {
            $dumpPath = Join-Path $DumpRoot "UIHang_$processId.dmp"

            if (Invoke-ProcDump -TargetProcessId $processId -DumpPath $dumpPath) {
                Invoke-Cdb -DumpPath $dumpPath | Out-Null
                Mark-Captured $processId
            }
        }
    }

    Start-Sleep $MonitorIntervalSeconds

} while (-not $SinglePass)

Write-Log "=== AutoCapture V37.9 END ==="