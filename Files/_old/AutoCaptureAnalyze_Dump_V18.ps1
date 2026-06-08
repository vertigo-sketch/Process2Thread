<#
AutoCaptureAnalyze_Dump.ps1
Version: 19

FINAL fixes:
- Fixed broken Admin check (root cause of parser error)
- Guaranteed ProcDump dump creation (-r)
- Live status updates
- Full rewrite (no partial patches)
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
# ADMIN CHECK (SYNTAX SAFE)
# ==============================
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)

if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator) {
    throw "This script MUST be run as Administrator. ProcDump cannot attach without elevation."
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
# Live status
# ==============================
$script:TriggerCount = 0
$script:LastTrigger  = "None"

function Update-Status($Phase, $Checked = 0) {
    if (-not $LiveStatus) { return }
    $line = "[{0}] {1} | Checked:{2} | Triggers:{3} | Last:{4}" -f `
        (Get-Date -Format HH:mm:ss),
        $Phase.PadRight(12),
        $Checked,
        $script:TriggerCount,
        $script:LastTrigger
    Write-Host "`r$line   " -NoNewline
}

trap {
    Write-Log "FATAL: $($_.Exception.Message)"
    Write-Host "`nFATAL: $($_.Exception.Message)"
    break
}

# ==============================
# Deny list (noise)
# ==============================
$DenyNames = @(
    'LockApp','ShellExperienceHost','StartMenuExperienceHost',
    'SearchHost','TextInputHost','RuntimeBroker',
    'ApplicationFrameHost','backgroundTaskHost','dllhost'
)

function Is-DeniedName($Name) {
    $DenyNames -contains $Name
}

# ==============================
# Safe process snapshot
# ==============================
function Get-SafeSnapshot {
    param([System.Diagnostics.Process]$P)

    try {
        $id   = [int]$P.Id
        $name = [string]$P.Name
    } catch { return $null }

    if (Is-DeniedName $name) { return $null }

    $cpu = 0; $mwh = 0; $resp = $null
    try { $cpu = [double]$P.CPU } catch {}
    try { $mwh = [int64]$P.MainWindowHandle } catch {}
    if ($mwh -ne 0) {
        try { $resp = [bool]$P.Responding } catch {}
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
function Get-SuspendSummary($ProcId) {
    try { $p = Get-Process -Id $ProcId -ErrorAction Stop } catch { return $null }

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
# Dump + Analyze (immediate)
# ==============================
function Capture-Dump($ProcId, $Name) {
    $stamp = Get-Date -Format yyyyMMdd_HHmmss
    $path  = Join-Path $DumpRoot "$Name`_$ProcId`_$stamp.dmp"

    $sw = switch ($DumpProfile) {
        'Mini'            { '-mm' }
        'MiniWithHandles' { '-mm -mh' }
        'Full'            { '-ma' }
    }

    Write-Log "Dumping $Name($ProcId) immediately"

    $args = "-accepteula $sw -r $ProcId `"$path`""
    $p = Start-Process $ProcDumpPath -ArgumentList $args -Wait -WindowStyle Hidden -PassThru

    Write-Log "ProcDump exit code: $($p.ExitCode)"

    if (-not (Test-Path $path)) {
        throw "ProcDump exited but no dump was created (exit=$($p.ExitCode))"
    }

    return $path
}

function Analyze-Dump($DumpPath) {
    $log = [IO.Path]::ChangeExtension($DumpPath, ".cdb.log")
    $cmd = '.symfix; .reload; !analyze -hang; ~* kb; q'

    Start-Process $CdbPath `
        "-z `"$DumpPath`" -c `"$cmd`" -logo `"$log`"" `
        -WindowStyle Hidden | Wait-Process -Timeout 180

    return $log
}

# ==============================
# Cooldown
# ==============================
$LastCapture = @{}
function In-Cooldown($Id) {
    $LastCapture.ContainsKey($Id) -and
    (((Get-Date) - $LastCapture[$Id]).TotalSeconds -lt $CooldownSeconds)
}

# ==============================
# START
# ==============================
Write-Log "=== AutoCapture V19 START ==="
Write-Host "AutoCapture running (Admin verified). Ctrl+C to stop."

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

            Write-Log "TRIGGER $($b.Name)($($b.ProcId)) UIHang=$uiHang TrueSuspend=$trueSuspend"

            try {
                $LastCapture[$b.ProcId] = Get-Date
                $dump = Capture-Dump $b.ProcId $b.Name
                Analyze-Dump $dump | Out-Null
                Write-Log "CAPTURE COMPLETE $dump"
            } catch {
                Write-Log "ERROR $($b.Name)($($b.ProcId)) $($_.Exception.Message)"
            }
        }
    }

    Update-Status "IDLE" $checked
    Start-Sleep $MonitorIntervalSeconds
}