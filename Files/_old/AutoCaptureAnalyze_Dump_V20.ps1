<#
AutoCaptureAnalyze_Dump.ps1
Version: 23

Change History:
- V23 (2026-03-25)
  * Added color-coded console status lines
  * Each status update prints on a new line
  * Color reflects severity / phase
  * No change to detection, dump, or analysis logic
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
    [switch]$LiveStatus
)

# ==============================
# ADMIN CHECK (PARSER SAFE)
# ==============================
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    throw "Run this script as Administrator."
}

# ==============================
# Resolve script root
# ==============================
$ScriptRoot = if ($PSScriptRoot) {
    $PSScriptRoot
} elseif ($MyInvocation.MyCommand.Path) {
    Split-Path -Parent $MyInvocation.MyCommand.Path
} else {
    (Get-Location).Path
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
if (-not (Test-Path $ProcDumpPath)) { throw "Missing ProcDump.exe" }
if (-not (Test-Path $CdbPath))      { throw "Missing cdb.exe" }

# ==============================
# Logging
# ==============================
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts $Message" | Out-File -Append -Encoding UTF8 $LogPath
}

# ==============================
# COLOR STATUS LINE WRITER
# ==============================
$script:TriggerCount = 0
$script:LastTrigger  = "None"

function Write-Status {
    param(
        [string]$Phase,
        [int]$SnapA = 0,
        [int]$Checked = 0
    )

    if (-not $LiveStatus) { return }

    $color = switch ($Phase) {
        'START'   { 'Cyan' }
        'PASS'    { 'DarkGray' }
        'SNAP-A'  { 'Gray' }
        'SLEEP'   { 'DarkYellow' }
        'SNAP-B'  { 'Gray' }
        'IDLE'    { 'DarkGray' }
        'TRIGGER' { 'Red' }
        'FATAL'   { 'DarkRed' }
        default   { 'White' }
    }

    $line = "[{0}] {1,-8} | A:{2,-4} | Checked:{3,-4} | Trig:{4,-3} | Last:{5}" -f `
        (Get-Date -Format HH:mm:ss),
        $Phase,
        $SnapA,
        $Checked,
        $script:TriggerCount,
        $script:LastTrigger

    Write-Host $line -ForegroundColor $color
}

trap {
    Write-Log ("FATAL: {0}" -f $_.Exception.Message)
    Write-Status -Phase 'FATAL'
    Write-Host ("FATAL: {0}" -f $_.Exception.Message) -ForegroundColor DarkRed
    break
}

# ==============================
# Noise deny list
# ==============================
$DenyNames = @(
    'LockApp','ShellExperienceHost','StartMenuExperienceHost',
    'SearchHost','TextInputHost','RuntimeBroker',
    'ApplicationFrameHost','backgroundTaskHost','dllhost'
)

function Is-DeniedName {
    param([string]$Name)
    return ($DenyNames -contains $Name)
}

# ==============================
# Safe process snapshot
# ==============================
function Get-SafeSnapshot {
    param([System.Diagnostics.Process]$Proc)

    try {
        $id = [int]$Proc.Id
        $name = [string]$Proc.Name
    } catch { return $null }

    if (Is-DeniedName $name) { return $null }

    $cpu = 0; $mwh = 0; $resp = $null
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
function Get-SuspendSummary {
    param([int]$TargetProcId)

    try { $p = Get-Process -Id $TargetProcId -ErrorAction Stop } catch { return $null }
    $threads = $p.Threads
    if ($threads.Count -eq 0) { return $null }

    $susp = 0
    foreach ($t in $threads) {
        try {
            if ($t.ThreadState -eq 'Wait' -and $t.WaitReason -eq 'Suspended') {
                $susp++
            }
        } catch {}
    }

    [PSCustomObject]@{
        Total = $threads.Count
        Susp  = $susp
        Pct   = [math]::Round(($susp / $threads.Count) * 100, 2)
    }
}

# ==============================
# Dump + Analyze
# ==============================
function Capture-Dump {
    param([int]$TargetProcId, [string]$ProcName)

    $stamp = Get-Date -Format yyyyMMdd_HHmmss
    $dumpPath = Join-Path $DumpRoot ("{0}_{1}_{2}.dmp" -f $ProcName, $TargetProcId, $stamp)

    $sw = switch ($DumpProfile) {
        'Mini'            { '-mm' }
        'MiniWithHandles' { '-mm -mh' }
        'Full'            { '-ma' }
    }

    Write-Log "Dumping $ProcName($TargetProcId)"
    $args = "-accepteula $sw -r $TargetProcId `"$dumpPath`""
    Start-Process $ProcDumpPath -ArgumentList $args -Wait -WindowStyle Hidden | Out-Null

    if (-not (Test-Path $dumpPath)) {
        throw "Dump not created for $TargetProcId"
    }

    return $dumpPath
}

function Analyze-Dump {
    param([string]$DumpPath)

    $log = [IO.Path]::ChangeExtension($DumpPath, ".cdb.log")
    $cmd = '.symfix; .reload; !analyze -hang; ~* kb; q'
    Start-Process $CdbPath "-z `"$DumpPath`" -c `"$cmd`" -logo `"$log`"" -Wait -WindowStyle Hidden | Out-Null
    return $log
}

# ==============================
# Cooldown
# ==============================
$LastCapture = @{}
function In-Cooldown {
    param([int]$ProcId)
    if ($LastCapture.ContainsKey($ProcId)) {
        return (((Get-Date) - $LastCapture[$ProcId]).TotalSeconds -lt $CooldownSeconds)
    }
    return $false
}

# ==============================
# START
# ==============================
Write-Log "=== AutoCapture V23 START ==="
Write-Status -Phase 'START'
Write-Host "AutoCapture V23 running (Admin OK). Ctrl+C to stop." -ForegroundColor Cyan

while ($true) {
    Write-Status -Phase 'PASS'

    $snapA = @{}
    foreach ($p in Get-Process) {
        $s = Get-SafeSnapshot $p
        if ($s) { $snapA[$s.ProcId] = $s }
    }
    Write-Status -Phase 'SNAP-A' -SnapA $snapA.Count

    Write-Status -Phase 'SLEEP' -SnapA $snapA.Count
    Start-Sleep $ObservationWindowSeconds
    Write-Status -Phase 'SNAP-B' -SnapA $snapA.Count

    $checked = 0
    foreach ($p in Get-Process) {
        $b = Get-SafeSnapshot $p
        if (-not $b) { continue }
        if (-not $snapA.ContainsKey($b.ProcId)) { continue }
        if (In-Cooldown $b.ProcId) { continue }

        $a = $snapA[$b.ProcId]
        $checked++

        $cpuDelta = $b.CPU - $a.CPU
        $uiHang   = ($b.MWH -ne 0 -and $b.Resp -eq $false)

        $trueSuspend = $false
        if (-not $uiHang -and $cpuDelta -lt $CpuDeltaThreshold) {
            $ts = Get-SuspendSummary $b.ProcId
            if ($ts -and $ts.Susp -gt 0 -and $ts.Pct -ge $SuspendedThreadPercent) {
                $trueSuspend = $true
            }
        }

        if ($uiHang -or $trueSuspend) {
            $script:TriggerCount++
            $script:LastTrigger = "{0}({1})" -f $b.Name, $b.ProcId

            Write-Status -Phase 'TRIGGER' -SnapA $snapA.Count -Checked $checked
            Write-Log ("TRIGGER {0}" -f $script:LastTrigger)

            try {
                $LastCapture[$b.ProcId] = Get-Date
                $dump = Capture-Dump $b.ProcId $b.Name
                Analyze-Dump $dump | Out-Null
                Write-Log ("CAPTURE COMPLETE {0}" -f $dump)
            } catch {
                Write-Log ("ERROR {0}: {1}" -f $script:LastTrigger, $_.Exception.Message)
            }
        }
    }

    Write-Status -Phase 'IDLE' -SnapA $snapA.Count -Checked $checked
    Start-Sleep $MonitorIntervalSeconds
}