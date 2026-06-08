<#
AutoCaptureAnalyze_Dump.ps1
Version: 20

FINAL SCRIPT – PARSER SAFE
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
    throw "This script MUST be run as Administrator."
}

# ==============================
# PATH RESOLUTION
# ==============================
if ($PSScriptRoot) {
    $ScriptRoot = $PSScriptRoot
} else {
    $ScriptRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
}

$DumpRoot = Join-Path $ScriptRoot "Dumps"
$LogRoot  = Join-Path $ScriptRoot "Logs"

New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot | Out-Null

$LogPath = Join-Path $LogRoot "AutoCapture.log"

# ==============================
# TOOL PATHS
# ==============================
$ProcDumpPath = "C:\Tools\Sysinternals\procdump.exe"
$CdbPath      = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"

if (-not (Test-Path $ProcDumpPath)) { throw "Missing ProcDump.exe" }
if (-not (Test-Path $CdbPath))      { throw "Missing cdb.exe" }

# ==============================
# LOGGING
# ==============================
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts $Message" | Out-File -Append -Encoding UTF8 $LogPath
}

# ==============================
# LIVE STATUS
# ==============================
$script:TriggerCount = 0
$script:LastTrigger  = "None"

function Update-Status {
    param([string]$Phase, [int]$Checked = 0)

    if (-not $LiveStatus) { return }

    $line = "[{0}] {1} Checked:{2} Triggers:{3} Last:{4}" -f `
        (Get-Date -Format HH:mm:ss),
        $Phase.PadRight(10),
        $Checked,
        $script:TriggerCount,
        $script:LastTrigger

    Write-Host "`r$line   " -NoNewline
}

# ==============================
# DENY LIST
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
# SAFE PROCESS SNAPSHOT
# ==============================
function Get-SafeSnapshot {
    param([System.Diagnostics.Process]$Proc)

    try {
        $id   = [int]$Proc.Id
        $name = [string]$Proc.Name
    } catch {
        return $null
    }

    if (Is-DeniedName $name) { return $null }

    $cpu = 0.0
    $mwh = 0
    $resp = $null

    try { $cpu = [double]$Proc.CPU } catch {}
    try { $mwh = [int64]$Proc.MainWindowHandle } catch {}
    if ($mwh -ne 0) {
        try { $resp = [bool]$Proc.Responding } catch {}
    }

    return [PSCustomObject]@{
        ProcId = $id
        Name   = $name
        CPU    = $cpu
        MWH    = $mwh
        Resp   = $resp
    }
}

# ==============================
# TRUE SUSPEND DETECTION
# ==============================
function Get-SuspendSummary {
    param([int]$ProcId)

    try {
        $p = Get-Process -Id $ProcId -ErrorAction Stop
    } catch {
        return $null
    }

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

    return [PSCustomObject]@{
        Total = $threads.Count
        Susp  = $susp
        Pct   = [math]::Round(($susp / $threads.Count) * 100, 2)
    }
}

# ==============================
# DUMP + ANALYZE (IMMEDIATE)
# ==============================
function Capture-Dump {
    param([int]$ProcId, [string]$Name)

    $stamp = Get-Date -Format yyyyMMdd_HHmmss
    $dump  = Join-Path $DumpRoot "$Name`_$ProcId`_$stamp.dmp"

    $sw = switch ($DumpProfile) {
        'Mini'            { '-mm' }
        'MiniWithHandles' { '-mm -mh' }
        'Full'            { '-ma' }
    }

    $args = "-accepteula $sw -r $ProcId `"$dump`""

    Write-Log "ProcDump $Name($ProcId)"
    $p = Start-Process $ProcDumpPath -ArgumentList $args -Wait -PassThru -WindowStyle Hidden

    if (-not (Test-Path $dump)) {
        throw "Dump not created (exit=$($p.ExitCode))"
    }

    return $dump
}

function Analyze-Dump {
    param([string]$DumpPath)

    $log = [IO.Path]::ChangeExtension($DumpPath, ".cdb.log")
    $cmd = '.symfix; .reload; !analyze -hang; ~* kb; q'

    Start-Process $CdbPath `
        "-z `"$DumpPath`" -c `"$cmd`" -logo `"$log`"" `
        -Wait -WindowStyle Hidden

    return $log
}

# ==============================
# COOLDOWN
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
Write-Log "=== AutoCapture V20 START ==="
Write-Host "AutoCapture running. Ctrl+C to stop."

while ($true) {
    Update-Status "PASS"

    $snapA = @{}
    foreach ($p in Get-Process) {
        $s = Get-SafeSnapshot $p
        if ($s) { $snapA[$s.ProcId] = $s }
    }

    Start-Sleep $ObservationWindowSeconds

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
            $script:LastTrigger = "$($b.Name)($($b.ProcId))"
            Update-Status "TRIGGER" $checked

            Write-Log "TRIGGER $($b.Name)($($b.ProcId))"

            try {
                $LastCapture[$b.ProcId] = Get-Date
                $dump = Capture-Dump $b.ProcId $b.Name
                Analyze-Dump $dump | Out-Null
                Write-Log "CAPTURE COMPLETE $dump"
            } catch {
                Write-Log "ERROR $($b.Name) $($_.Exception.Message)"
            }
        }
    }

    Update-Status "IDLE" $checked
    Start-Sleep $MonitorIntervalSeconds
}