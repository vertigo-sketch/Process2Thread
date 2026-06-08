<#
AutoCaptureAnalyze_Dump.ps1
Version: 17

Change History:
- V17 (2026-03-25)
  * Added live, single-line status updates (console/ISE-safe)
  * Status updates during SnapshotA, Sleep, SnapshotB, Trigger
  * No console spam; overwrites same line
- V16
  * Console output option
- V15
  * Suppressed SystemApps / LockApp noise
- V14
  * TrueSuspend detection via .NET thread WaitReason=Suspended
#>

[CmdletBinding()]
param(
    [int]$ObservationWindowSeconds = 15,
    [int]$MonitorIntervalSeconds   = 5,
    [double]$CpuDeltaThreshold     = 0.01,
    [int]$SuspendedThreadPercent   = 80,
    [int]$CooldownSeconds          = 600,
    [ValidateSet('Mini','MiniWithHandles','Full')]
    [string]$DumpProfile           = 'Mini',

    [string[]]$DenyProcessNames    = @(),
    [switch]$DisableDefaultDenyList,

    # Enable live, in-place console status
    [switch]$LiveStatus
)

# ==============================
# Resolve script root (ISE-safe)
# ==============================
if ($PSScriptRoot) {
    $ScriptRoot = $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    $ScriptRoot = (Get-Location).Path
}

$DumpRoot = Join-Path $ScriptRoot "Dumps"
$LogRoot  = Join-Path $ScriptRoot "Logs"
New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot | Out-Null

$LogPath = Join-Path $LogRoot "AutoCapture.log"

# ==============================
# Tool paths
# ==============================
$ProcDumpPath = "C:\Tools\Sysinternals\procdump.exe"
$CdbPath      = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"

if (-not (Test-Path $ProcDumpPath)) { throw "Missing ProcDump: $ProcDumpPath" }
if (-not (Test-Path $CdbPath))      { throw "Missing cdb.exe: $CdbPath" }

# ==============================
# Logging
# ==============================
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts $Message" | Out-File -Encoding UTF8 -Append $LogPath
}

# ==============================
# Live status (single-line)
# ==============================
$script:LastStatus = ""
$script:LastTrigger = "None"
$script:TriggerCount = 0

function Update-Status {
    param(
        [string]$Phase,
        [int]$SnapA = 0,
        [int]$SnapB = 0,
        [int]$Checked = 0
    )

    if (-not $LiveStatus) { return }

    $line = "[{0}] {1} | A:{2} B:{3} | Checked:{4} | Triggers:{5} | Last:{6}" -f `
        (Get-Date -Format HH:mm:ss),
        $Phase.PadRight(11),
        $SnapA,
        $SnapB,
        $Checked,
        $script:TriggerCount,
        $script:LastTrigger

    # Overwrite current line (no newline)
    Write-Host "`r$line   " -NoNewline
    $script:LastStatus = $line
}

trap {
    Write-Log ("FATAL: {0}" -f $_.Exception.Message)
    Write-Log ("FATAL: {0}" -f $_.ScriptStackTrace)
    Write-Host "`nFATAL: $($_.Exception.Message)"
    break
}

# ==============================
# Default deny list
# ==============================
$DefaultDeny = @(
    'LockApp',
    'ShellExperienceHost',
    'StartMenuExperienceHost',
    'SearchHost',
    'TextInputHost',
    'RuntimeBroker',
    'ApplicationFrameHost',
    'backgroundTaskHost',
    'dllhost'
)

function Is-DeniedName {
    param([string]$Name)

    if (-not $Name) { return $true }

    if (-not $DisableDefaultDenyList -and ($DefaultDeny -contains $Name)) {
        return $true
    }

    if ($DenyProcessNames -and ($DenyProcessNames -contains $Name)) {
        return $true
    }

    return $false
}

# ==============================
# Safe snapshot
# ==============================
function Get-SafeProcSnapshot {
    param([System.Diagnostics.Process]$Proc)

    try {
        $id = [int]$Proc.Id
        $name = [string]$Proc.Name
    } catch { return $null }

    if (Is-DeniedName $name) { return $null }

    $cpu = 0.0
    $mwh = 0
    $resp = $null

    try { $cpu = [double]$Proc.CPU } catch {}
    try { $mwh = [int64]$Proc.MainWindowHandle } catch {}
    if ($mwh -ne 0) {
        try { $resp = [bool]$Proc.Responding } catch {}
    }

    [PSCustomObject]@{
        ProcId = $id
        Name   = $name
        CPU    = $cpu
        MWH    = $mwh
        Resp   = $resp
    }
}

# ==============================
# True suspend detection
# ==============================
function Get-SuspendedThreadSummary {
    param([int]$TargetProcId)

    try { $p = Get-Process -Id $TargetProcId -ErrorAction Stop } catch { return $null }

    $threads = $p.Threads
    if (-not $threads -or $threads.Count -eq 0) { return $null }

    $total = $threads.Count
    $susp  = 0

    foreach ($t in $threads) {
        try {
            if ($t.ThreadState -eq 'Wait' -and $t.WaitReason -eq 'Suspended') {
                $susp++
            }
        } catch {}
    }

    [PSCustomObject]@{
        Total = $total
        Susp  = $susp
        Pct   = [math]::Round(($susp / $total) * 100, 2)
    }
}

# ==============================
# Dump + Analyze
# ==============================
function Capture-Dump {
    param([int]$Id, [string]$Name)

    $stamp = Get-Date -Format yyyyMMdd_HHmmss
    $path  = Join-Path $DumpRoot "$Name`_$Id`_$stamp.dmp"

    $sw = switch ($DumpProfile) {
        'Mini'            { '-mm' }
        'MiniWithHandles' { '-mm -mh' }
        'Full'            { '-ma' }
    }

    Write-Log "Dumping $Name($Id) -> $path"

    Start-Process $ProcDumpPath `
        "-accepteula $sw $Id `"$path`"" `
        -WindowStyle Hidden |
        Wait-Process -Timeout 60

    if (-not (Test-Path $path)) {
        throw "Dump not created for $Id"
    }

    $path
}

function Analyze-Dump {
    param([string]$DumpPath)

    $log = [IO.Path]::ChangeExtension($DumpPath, ".cdb.log")
    $cmd = '.symfix; .reload; !analyze -hang; ~* kb; q'

    Start-Process $CdbPath `
        "-z `"$DumpPath`" -c `"$cmd`" -logo `"$log`"" `
        -WindowStyle Hidden |
        Wait-Process -Timeout 180

    $log
}

# ==============================
# Cooldown tracking
# ==============================
$LastCapture = @{}
function In-Cooldown($Id) {
    $LastCapture.ContainsKey($Id) -and
    (((Get-Date) - $LastCapture[$Id]).TotalSeconds -lt $CooldownSeconds)
}

# ==============================
# START
# ==============================
Write-Log "=== AutoCapture V17 START ==="
Write-Host "AutoCapture running... (Ctrl+C to stop)"
if ($LiveStatus) { Write-Host "" }

while ($true) {
    Update-Status "PASS"

    # Snapshot A
    $snapA = @{}
    $procsA = Get-Process
    foreach ($p in $procsA) {
        $s = Get-SafeProcSnapshot $p
        if ($s) { $snapA[$s.ProcId] = $s }
    }
    Update-Status "SNAPSHOT-A" $snapA.Count

    Start-Sleep $ObservationWindowSeconds
    Update-Status "SNAPSHOT-B" $snapA.Count

    $checked = 0
    foreach ($p in Get-Process) {
        $b = Get-SafeProcSnapshot $p
        if (-not $b) { continue }
        if (-not $snapA.ContainsKey($b.ProcId)) { continue }
        if (In-Cooldown $b.ProcId) { continue }

        $a = $snapA[$b.ProcId]
        $checked++

        $cpuDelta = $b.CPU - $a.CPU
        $uiHang = ($b.MWH -ne 0 -and $b.Resp -eq $false)

        $trueSuspend = $false
        if (-not $uiHang -and $cpuDelta -lt $CpuDeltaThreshold) {
            $ts = Get-SuspendedThreadSummary $b.ProcId
            if ($ts -and $ts.Susp -gt 0 -and $ts.Pct -ge $SuspendedThreadPercent) {
                $trueSuspend = $true
            }
        }

        if ($uiHang -or $trueSuspend) {
            $script:TriggerCount++
            $script:LastTrigger = "$($b.Name)($($b.ProcId))"
            Update-Status "TRIGGER" $snapA.Count 0 $checked

            Write-Log "TRIGGER $($b.Name)($($b.ProcId)) UIHang=$uiHang TrueSuspend=$trueSuspend"

            $LastCapture[$b.ProcId] = Get-Date
            try {
                $d = Capture-Dump $b.ProcId $b.Name
                Analyze-Dump $d | Out-Null
                Write-Log "CAPTURE COMPLETE $d"
            } catch {
                Write-Log "ERROR $($b.Name)($($b.ProcId)) $_"
            }
        }
    }

    Update-Status "IDLE" $snapA.Count 0 $checked
    Start-Sleep $MonitorIntervalSeconds
}