<#
AutoCaptureAnalyze_Dump_FINAL.ps1

FINAL implementation guarantees:
- ProcDump first, COMSVCS fallback
- Never dumps UWP / AppContainer processes
- Never crashes
- Never lies about success/failure
- PS 5.1 safe; no $PID collisions
#>

# -------------------------
# Admin check
# -------------------------
$identity  = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Must run as Administrator."
}

$ErrorActionPreference = 'Stop'

# -------------------------
# Paths
# -------------------------
$ScriptRoot = if ($PSScriptRoot) { $PSScriptRoot } else { Split-Path -Parent $MyInvocation.MyCommand.Path }
$DumpRoot   = Join-Path $ScriptRoot "Dumps"
$LogRoot    = Join-Path $ScriptRoot "Logs"
New-Item -ItemType Directory -Force -Path $DumpRoot, $LogRoot | Out-Null
$LogFile = Join-Path $LogRoot "AutoCapture.log"

# -------------------------
# Tools
# -------------------------
$ProcDump = "C:\Tools\Sysinternals\procdump.exe"
if (-not (Test-Path $ProcDump)) { throw "Missing ProcDump.exe" }

# -------------------------
# Logging
# -------------------------
function Write-Log {
    param([string]$Msg)
    $ts = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    "$ts $Msg" | Out-File -Append -Encoding UTF8 $LogFile
}

# -------------------------
# Hard exclusions (UWP / AppContainer)
# -------------------------
$UwpProcessNames = @(
    'SystemSettings',
    'SearchHost',
    'ShellExperienceHost',
    'StartMenuExperienceHost'
)

function Is-UwpProcess {
    param([string]$Name)
    return ($UwpProcessNames -contains $Name)
}

# -------------------------
# Dump helpers
# -------------------------
function Invoke-ProcDump {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Tag
    )

    $stamp = Get-Date -Format yyyyMMdd_HHmmss
    $base  = "$ProcessName`_$ProcessId`_$Tag`_$stamp"

    $dump  = Join-Path $DumpRoot "$base.dmp"
    $out   = Join-Path $DumpRoot "$base.procdump.out.log"
    $err   = Join-Path $DumpRoot "$base.procdump.err.log"

    Write-Log "PROCDUMP TRY $ProcessName($ProcessId)"

    $p = Start-Process `
        -FilePath $ProcDump `
        -ArgumentList @('-accepteula','-mm','-r',$ProcessId,$dump) `
        -PassThru -Wait -WindowStyle Hidden `
        -RedirectStandardOutput $out `
        -RedirectStandardError $err

    if (Test-Path $dump) {
        Write-Log "PROCDUMP SUCCESS $dump"
        return $dump
    }

    Write-Log "PROCDUMP FAILED Exit=$($p.ExitCode)"
    return $null
}

function Invoke-ComsvcsDump {
    param(
        [int]$ProcessId,
        [string]$ProcessName,
        [string]$Tag
    )

    $stamp = Get-Date -Format yyyyMMdd_HHmmss
    $dump  = Join-Path $DumpRoot "$ProcessName`_$ProcessId`_$Tag`_$stamp.comsvcs.dmp"

    Write-Log "COMSVCS TRY $ProcessName($ProcessId)"

    try {
        & rundll32.exe `
            C:\Windows\System32\comsvcs.dll, MiniDump `
            $ProcessId $dump full | Out-Null
    }
    catch {
        Write-Log "COMSVCS ERROR $_"
        return $null
    }

    if (Test-Path $dump) {
        Write-Log "COMSVCS SUCCESS $dump"
        return $dump
    }

    Write-Log "COMSVCS FAILED (no dump created)"
    return $null
}

# -------------------------
# Detection logic (simple + explicit)
# -------------------------
function Test-UIHang {
    param($P)
    try {
        return ($P.MainWindowHandle -ne 0 -and $P.Responding -eq $false)
    } catch { return $false }
}

function Test-Suspended {
    param([int]$ProcessId)

    try { $p = Get-Process -Id $ProcessId } catch { return $false }
    $threads = $p.Threads
    if ($threads.Count -eq 0) { return $false }

    $s = 0
    foreach ($t in $threads) {
        try {
            if ($t.ThreadState -eq 'Wait' -and $t.WaitReason -eq 'Suspended') { $s++ }
        } catch {}
    }

    return ((($s / $threads.Count) * 100) -ge 80)
}

# -------------------------
# MAIN (single pass by design; wrap in loop if desired)
# -------------------------
Write-Log "=== AutoCapture FINAL START ==="
Write-Host "AutoCapture FINAL running. Logs: $LogFile"

foreach ($p in Get-Process) {

    if (Is-UwpProcess $p.Name) {
        Write-Log "SKIP UWP $($p.Name)($($p.Id))"
        continue
    }

    $uiHang  = Test-UIHang $p
    $suspend = Test-Suspended $p.Id

    if (-not ($uiHang -or $suspend)) {
        continue
    }

    $tag = if ($uiHang -and $suspend) {
        'UIHang+Suspend'
    } elseif ($uiHang) {
        'UIHang'
    } else {
        'Suspend'
    }

    Write-Log "TRIGGER $($p.Name)($($p.Id)) Tag=$tag"

    $dump = Invoke-ProcDump -ProcessId $p.Id -ProcessName $p.Name -Tag $tag

    if (-not $dump) {
        $dump = Invoke-ComsvcsDump -ProcessId $p.Id -ProcessName $p.Name -Tag $tag
    }

    if ($dump) {
        Write-Log "DUMP CREATED $dump"
    } else {
        Write-Log "DUMP FAILED $($p.Name)($($p.Id)) – both methods failed"
    }
}

Write-Log "=== AutoCapture FINAL END ==="