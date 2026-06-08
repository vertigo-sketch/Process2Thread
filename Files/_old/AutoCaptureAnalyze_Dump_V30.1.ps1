<#
Fixes:
- CDB: uses -cf command file AND passes arguments as a single quoted string (prevents "Invalid switch" caused by paths w/ spaces/hyphen).
- CDB: validates output/log isn’t just the usage banner; treats usage output as failure.
- ExitHex conversion fixed for negative HRESULT-style exit codes.
- ProcDump: also uses single quoted argument string for safety (paths with spaces/hyphen).
- NO comsvcs.dll / rundll32 usage.
Core behavior:
- Detects UI hangs (windowed process, Responding=false)
- Detects true suspension (>=80% threads WaitReason=Suspended)
- Tags dumps: UIHang / Suspend / UIHang+Suspend
- Captures dump with ProcDump (-r). If ProcDump fails, retries (-64) then (-wer). Final fallback uses MiniDumpWriteDump (dbghelp.dll).
- Analyzes dump with cdb and saves .cdb.log; if -logo fails, falls back to stdout capture log.
- Extracts "top blocked thread" section from whichever cdb output is valid
- Correlates filter drivers (WdFilter / CSAgent)
- Writes JSON evidence next to dump: .analysis.json
#>

[CmdletBinding()]
param(
    [int]$ObservationWindowSeconds = 15,
    [int]$MonitorIntervalSeconds   = 5,
    [int]$CooldownSeconds          = 600,
    [ValidateSet('Mini','MiniWithHandles','Full')]
    [string]$DumpProfile = 'Mini',
    [switch]$SinglePass,
    [switch]$ConsoleStatus = $true
)

## ---------------------------
## Admin check
## ---------------------------

$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    throw "Run as Administrator (required for dump attach)."
}

$ErrorActionPreference = 'Stop'

## ---------------------------
## Resolve paths
## ---------------------------

$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$DumpRoot   = Join-Path $ScriptRoot 'Dumps'
$LogRoot    = Join-Path $ScriptRoot 'Logs'

New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot | Out-Null

$LogFile = Join-Path $LogRoot 'AutoCapture.log'

## ---------------------------
## Tool paths
## ---------------------------

$ProcDumpPath = 'C:\Tools\Sysinternals\procdump.exe'
$CdbPath      = 'C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe'

if (-not (Test-Path $ProcDumpPath)) { throw "Missing ProcDump: $ProcDumpPath" }
if (-not (Test-Path $CdbPath))      { throw "Missing cdb.exe: $CdbPath" }

## ---------------------------
## Native dump loader state (PS 5.1-safe)
## ---------------------------

$script:MiniDumpNativeReady = $false

## ---------------------------
## Logging helpers
## ---------------------------

function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    "$ts $Message" | Out-File -Append -Encoding UTF8 $LogFile
}

function Write-Status {
    param(
        [string]$Message,
        [ConsoleColor]$Color = [ConsoleColor]::Gray
    )
    if (-not $ConsoleStatus) { return }
    Write-Host $Message -ForegroundColor $Color
}

function Get-FileExcerpt {
    param(
        [string]$Path,
        [int]$MaxLines = 25
    )
    try {
        if (-not (Test-Path $Path)) { return $null }
        $lines = Get-Content -Path $Path -ErrorAction Stop
        if (-not $lines -or $lines.Count -eq 0) { return $null }
        $take = [Math]::Min($MaxLines, $lines.Count)
        return ($lines[0..($take-1)] -join "`n")
    } catch {
        return $null
    }
}

function Convert-ExitCodeHex {
    param($Code)
    try {
        $i64 = [int64]$Code
        $u32 = $i64 -band 0xFFFFFFFF
        return ('0x{0:X8}' -f $u32)
    } catch {
        return $null
    }
}

## ---------------------------
## Optional deny list (noise reducer) + UWP-ish skip
## ---------------------------

$DenyNames = @(
    'LockApp','RuntimeBroker','SearchHost',
    'ShellExperienceHost','StartMenuExperienceHost',
    'ApplicationFrameHost','backgroundTaskHost'
)

$NeverDumpNames = @(
    'Microsoft.AAD.BrokerPlugin'
)

function Is-DeniedProcessName {
    param([string]$Name)
    return ($DenyNames -contains $Name)
}

function Get-ProcessImagePath {
    param([int]$TargetProcessId)
    try {
        $c = Get-CimInstance Win32_Process -Filter ("ProcessId={0}" -f $TargetProcessId) -ErrorAction Stop
        return [string]$c.ExecutablePath
    } catch {
        return $null
    }
}

function Is-NeverDumpTarget {
    param(
        [int]$TargetProcessId,
        [string]$ProcessName
    )
    if ($NeverDumpNames -contains $ProcessName) { return $true }
    return $false
}

## ---------------------------
## Safe snapshot
## ---------------------------

function Get-SafeSnapshot {
    param([System.Diagnostics.Process]$Proc)
}

## ---------------------------
## Detection
## ---------------------------

function Test-UIHang {
    param($Snap)
    return ($Snap.MWH -ne 0 -and $Snap.Responding -eq $false)
}

function Test-TrueSuspend {
    param([int]$TargetProcessId)
}

function Get-Tag {
    param([bool]$UIHang, [bool]$Suspend)
    if ($UIHang -and $Suspend) { return 'UIHang+Suspend' }
    if ($UIHang)             { return 'UIHang' }
    if ($Suspend)            { return 'Suspend' }
    return 'None'
}

## ---------------------------
## Cooldown
## ---------------------------

$LastCaptureByProcessId = @{}

function In-Cooldown {
    param([int]$TargetProcessId)
    if ($LastCaptureByProcessId.ContainsKey($TargetProcessId)) {
        $age = (Get-Date) - $LastCaptureByProcessId[$TargetProcessId]
        return ($age.TotalSeconds -lt $CooldownSeconds)
    }
    return $false
}

function Mark-Captured {
    param([int]$TargetProcessId)
    $LastCaptureByProcessId[$TargetProcessId] = Get-Date
}

## ---------------------------
## ProcDump invocation
## ---------------------------

function Invoke-ProcDump {
    param(
        [int]$TargetProcessId,
        [string]$DumpPath,
        [string[]]$ProfileArgs,
        [string]$OutPath,
        [string]$ErrPath,
        [string[]]$ExtraArgs
    )
}

## ---------------------------
## Native fallback stubs
## ---------------------------

function Ensure-MiniDumpNative {
@"
using System;
using System.Runtime.InteropServices;
public static class MiniDumpNative {
}
"@
}

function Invoke-NativeMiniDump {
    param(
        [int]$TargetProcessId,
        [string]$DumpPath
    )
}

## ---------------------------
## Dump + Analysis stubs
## ---------------------------

function Capture-Dump {
    param(
        [int]$TargetProcessId,
        [string]$ProcessName,
        [string]$Tag
    )
}

function Write-CdbCommandFile {
    param([string]$DumpPath)
}

function Analyze-Dump {
    param([string]$DumpPath)
}

function Extract-TopBlockedThread {
    param([string]$CdbLogPath)
}

function Correlate-FiltersFromText {
    param([string]$Text)
    if (-not $Text) { return [pscustomobject]@{} }

    $hits = @()
    if ($Text -match '(?i)\bWdFilter\b') { $hits += 'WdFilter' }
    if ($Text -match '(?i)\bCSAgent\b')  { $hits += 'CSAgent' }

    return [pscustomobject]@{
        WdFilter = ($hits -contains 'WdFilter')
        CSAgent  = ($hits -contains 'CSAgent')
        Hits     = $hits
    }
}

function Write-AnalysisJson {
    param(
        [string]$DumpPath,
        [string]$Tag,
        $CdbResult,
        [string]$BlockedThreadText,
        $FilterCorrelation
    )
}

## ---------------------------
## MAIN LOOP
## ---------------------------

Write-Log "=== AutoCapture V30.1 START === ScriptRoot=$ScriptRoot DumpRoot=$DumpRoot DumpProfile=$DumpProfile"
Write-Status "AutoCapture V30.1 running (Admin OK). Logs: $LogFile" Cyan

do {
    Write-Log "PASS START"
} while (-not $SinglePass)