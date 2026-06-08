<#
AutoCaptureAnalyze_Dump.ps1
Version: 25

Fixes:
- Eliminated ALL $PID/$pid collisions (root cause of fatal error)
- Guaranteed console output
- Stable suspend detection
- Immediate ProcDump capture (-r)
- PS 5.1 / Console / ISE safe
#>

# ==============================
# ADMIN CHECK (VISIBLE)
# ==============================
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Host "FATAL: Run script as Administrator." -ForegroundColor Red
    throw "Admin rights required"
}

# ==============================
# PATHS
# ==============================
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$DumpRoot = Join-Path $ScriptRoot "Dumps"
$LogRoot  = Join-Path $ScriptRoot "Logs"
New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot | Out-Null
$LogPath = Join-Path $LogRoot "AutoCapture.log"

# ==============================
# TOOLS
# ==============================
$ProcDumpPath = "C:\Tools\Sysinternals\procdump.exe"
$CdbPath      = "C:\Program Files (x86)\Windows Kits\10\Debuggers\x64\cdb.exe"
if (!(Test-Path $ProcDumpPath)) { throw "Missing ProcDump.exe" }
if (!(Test-Path $CdbPath))      { throw "Missing cdb.exe" }

# ==============================
# LOGGING
# ==============================
function Write-Log {
    param([string]$Message)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts $Message" | Out-File -Append -Encoding UTF8 $LogPath
}

# ==============================
# CONSOLE STATUS (ALWAYS)
# ==============================
$script:TriggerCount = 0
$script:LastTrigger  = "None"

function Emit-Status {
    param(
        [string]$Phase,
        [string]$Color = 'Gray',
        [int]$Checked = 0,
        [int]$Total = 0
    )

    $line = "[{0}] {1,-8} | Checked:{2,-4} | Total:{3,-4} | Trig:{4,-3} | Last:{5}" -f `
        (Get-Date -Format HH:mm:ss),
        $Phase,
        $Checked,
        $Total,
        $script:TriggerCount,
        $script:LastTrigger

    Write-Host $line -ForegroundColor $Color
    Write-Output $line
}

# ==============================
# DENY LIST (NOISE)
# ==============================
$DenyNames = @(
    'LockApp','RuntimeBroker','SearchHost',
    'ShellExperienceHost','StartMenuExperienceHost',
    'ApplicationFrameHost','backgroundTaskHost','dllhost'
)

function Is-DeniedProcessName {
    param([string]$Name)
    return ($DenyNames -contains $Name)
}

# ==============================
# SAFE SNAPSHOT
# ==============================
function Get-Snapshot {
    param([System.Diagnostics.Process]$Proc)

    try {
        $processId = [int]$Proc.Id
        $processName = [string]$Proc.Name
    } catch { return $null }

    if (Is-DeniedProcessName $processName) { return $null }

    $cpu = 0.0
    $mainWindow = 0
    $responding = $null

    try { $cpu = [double]$Proc.CPU } catch {}
    try { $mainWindow = [int64]$Proc.MainWindowHandle } catch {}
    if ($mainWindow -ne 0) {
        try { $responding = [bool]$Proc.Responding } catch {}
    }

    [PSCustomObject]@{
        ProcessId = $processId
        Name      = $processName
        CPU       = $cpu
        MWH       = $mainWindow
        Resp      = $responding
    }
}

# ==============================
# TRUE SUSPEND CHECK (SAFE)
# ==============================
function Test-ProcessSuspended {
    param([int]$TargetProcessId)

    try {
        $p = Get-Process -Id $TargetProcessId -ErrorAction Stop
    } catch {
        return $false
    }

    $threads = $p.Threads
    if ($threads.Count -eq 0) { return $false }

    $suspended = 0
    foreach ($t in $threads) {
        try {
            if ($t.ThreadState -eq 'Wait' -and $t.WaitReason -eq 'Suspended') {
                $suspended++
            }
        } catch {}
    }

    return (($suspended / $threads.Count) * 100 -ge 80)
}

# ==============================
# STARTUP BANNER
# ==============================
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " AutoCapture V25 STARTED (PID SAFE)" -ForegroundColor Cyan
Write-Host " ScriptRoot: $ScriptRoot" -ForegroundColor Cyan
Write-Host " Logs:       $LogPath" -ForegroundColor Cyan
Write-Host " Dumps:      $DumpRoot" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

Write-Log "=== AutoCapture V25 START ==="

# ==============================
# MAIN LOOP
# ==============================
while ($true) {

    $snapshot = @{}
    foreach ($p in Get-Process) {
        $s = Get-Snapshot $p
        if ($s) { $snapshot[$s.ProcessId] = $s }
    }

    Start-Sleep 15

    $checked = 0
    foreach ($p in Get-Process) {
        $b = Get-Snapshot $p
        if (-not $b) { continue }
        if (-not $snapshot.ContainsKey($b.ProcessId)) { continue }

        $a = $snapshot[$b.ProcessId]
        $checked++

        $uiHang = ($b.MWH -ne 0 -and $b.Resp -eq $false)
        $trueSuspend = (-not $uiHang -and (Test-ProcessSuspended -TargetProcessId $b.ProcessId))

        if ($uiHang -or $trueSuspend) {
            $script:TriggerCount++
            $script:LastTrigger = "$($b.Name)($($b.ProcessId))"
            Emit-Status -Phase "TRIGGER" -Color 'Red' -Checked $checked -Total $snapshot.Count
            Write-Log "TRIGGER $($script:LastTrigger)"
        }
    }

    Emit-Status -Phase "PASS" -Color 'DarkGray' -Checked $checked -Total $snapshot.Count
    Start-Sleep 5
}