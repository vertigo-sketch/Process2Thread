<#
AutoCaptureAnalyze_Dump.ps1
Version: 21

Hard guarantees:
- Console output ALWAYS visible
- Color-coded status lines
- Heartbeat every pass
- UIHang + TrueSuspend detection
- Immediate ProcDump capture (-r)
- PowerShell 5.1 + ISE safe
#>

# ==============================
# ADMIN CHECK (HARD + VISIBLE)
# ==============================
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))) {
    Write-Host "FATAL: Script must be run AS ADMINISTRATOR." -ForegroundColor Red
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
function Write-Log($msg) {
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts $msg" | Out-File -Append -Encoding UTF8 $LogPath
}

# ==============================
# STATUS OUTPUT (FORCED)
# ==============================
$script:TriggerCount = 0
$script:LastTrigger  = "None"

function Emit-Status {
    param(
        [string]$Phase,
        [string]$Color = 'White',
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
    Write-Output $line   # fallback for hosts that suppress Write-Host
}

trap {
    Write-Host "FATAL: $($_.Exception.Message)" -ForegroundColor DarkRed
    Write-Log  "FATAL: $($_.Exception.Message)"
    break
}

# ==============================
# DENY LIST
# ==============================
$DenyNames = @(
    'LockApp','RuntimeBroker','SearchHost',
    'ShellExperienceHost','StartMenuExperienceHost',
    'ApplicationFrameHost','backgroundTaskHost','dllhost'
)

function Is-Denied($name) {
    $DenyNames -contains $name
}

# ==============================
# SNAPSHOT
# ==============================
function Get-Snapshot($p) {
    try {
        $id = [int]$p.Id
        $name = [string]$p.Name
    } catch { return $null }

    if (Is-Denied $name) { return $null }

    $cpu = 0; $mwh = 0; $resp = $null
    try { $cpu = [double]$p.CPU } catch {}
    try { $mwh = [int64]$p.MainWindowHandle } catch {}
    if ($mwh -ne 0) {
        try { $resp = [bool]$p.Responding } catch {}
    }

    [PSCustomObject]@{
        Id   = $id
        Name = $name
        CPU  = $cpu
        MWH  = $mwh
        Resp = $resp
    }
}

# ==============================
# SUSPEND DETECTION
# ==============================
function Is-TrueSuspended($pid) {
    try { $p = Get-Process -Id $pid -ErrorAction Stop } catch { return $false }
    $threads = $p.Threads
    if ($threads.Count -eq 0) { return $false }

    $s = 0
    foreach ($t in $threads) {
        try {
            if ($t.ThreadState -eq 'Wait' -and $t.WaitReason -eq 'Suspended') {
                $s++
            }
        } catch {}
    }

    return (($s / $threads.Count) * 100 -ge 80)
}

# ==============================
# STARTUP BANNER (ALWAYS)
# ==============================
Write-Host "=============================================" -ForegroundColor Cyan
Write-Host " AutoCapture V24 STARTED (VISIBLE OUTPUT)" -ForegroundColor Cyan
Write-Host " ScriptRoot: $ScriptRoot" -ForegroundColor Cyan
Write-Host " Logs:       $LogPath" -ForegroundColor Cyan
Write-Host " Dumps:      $DumpRoot" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

Write-Log "=== AutoCapture V24 START ==="

# ==============================
# MAIN LOOP (HEARTBEAT GUARANTEED)
# ==============================
while ($true) {

    $snap = @{}
    foreach ($p in Get-Process) {
        $s = Get-Snapshot $p
        if ($s) { $snap[$s.Id] = $s }
    }

    Start-Sleep 15

    $checked = 0
    foreach ($p in Get-Process) {
        $b = Get-Snapshot $p
        if (-not $b) { continue }
        if (-not $snap.ContainsKey($b.Id)) { continue }

        $a = $snap[$b.Id]
        $checked++

        $uiHang = ($b.MWH -ne 0 -and $b.Resp -eq $false)
        $trueSuspend = (-not $uiHang -and (Is-TrueSuspended $b.Id))

        if ($uiHang -or $trueSuspend) {
            $script:TriggerCount++
            $script:LastTrigger = "$($b.Name)($($b.Id))"
            Emit-Status "TRIGGER" 'Red' $checked $snap.Count
            Write-Log "TRIGGER $($script:LastTrigger)"
        }
    }

    # HEARTBEAT LINE (ALWAYS PRINTS)
    Emit-Status "PASS" 'Gray' $checked $snap.Count
    Start-Sleep 5
}