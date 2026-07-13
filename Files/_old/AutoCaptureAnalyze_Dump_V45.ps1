<# =====================================================================
 AutoCaptureAnalyze_Dump_V45.ps1
 HARD-PROOF VERSION (WPR ONLY)
 ===================================================================== #>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
cls
# ===============================
# CONFIG
# ===============================

$ObservationWindowSeconds = 15
$ScriptRoot = $PSScriptRoot
$DumpRoot   = Join-Path $ScriptRoot "Dumps"
$LogPath    = Join-Path $DumpRoot "AutoCapture.log"

New-Item -ItemType Directory -Path $DumpRoot -Force | Out-Null

# ===============================
# LOGGING
# ===============================

function Write-Log {
    param([Parameter(Mandatory)][string]$Message)

    $line = "{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $Message
    Add-Content -Path $LogPath -Value $line
    Write-Host $line
}

# ===============================
# ADMIN CHECK
# ===============================

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    throw "AutoCaptureAnalyze_Dump_V45 must be run elevated (admin)."
}

# ===============================
# HARD PROOF – WPR (ENTERPRISE SAFE)
# ===============================

$global:WprActive = $false

function Start-AutoCapHardProof {
    param([string]$WorkingDir)

    # Cancel anything orphaned
    & wpr -cancel 1>$null 2>$null

    & wpr -start GeneralProfile -filemode 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Log "WPR START FAILED – kernel tracing blocked"
        $global:WprActive = $false
        return
    }

    $global:WprActive = $true
    Write-Log "WPR kernel recording STARTED"
}

function Stop-AutoCapHardProof {
    param([string]$OutputEtl)

    if (-not $global:WprActive) {
        Write-Log "WPR not active – skipping stop"
        return $false
    }

    & wpr -stop $OutputEtl 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        Write-Log "WPR STOP FAILED"
        return $false
    }

    $global:WprActive = $false
    Write-Log "WPR kernel trace SAVED: $OutputEtl"
    return $true
}

# ===============================
# FILTER DELAY MARKER (TRUTHFUL)
# ===============================

function Write-HardProofSummary {
    param([string]$EtlPath)

    # We do NOT lie and claim attribution without WPA analysis.
    # Presence of ETL == kernel evidence captured.
    Write-Log "HARDPROOF ETL READY:$EtlPath (Analyze with WPA: File I/O + Filter Manager)"
}

# ===============================
# ASSUMED EXISTING FUNCTIONS
# ===============================
# NOT redefined on purpose:
#   Get-ProcessSnapshot
#   Test-UIHang
#   Invoke-ProcDump
#   Invoke-Cdb
#   In-Cooldown
#   Mark-Captured

# ===============================
# MAIN LOOP
# ===============================

Write-Log "=== AutoCaptureAnalyze_Dump_V45 START (WPR MODE) ==="

Start-AutoCapHardProof -WorkingDir $DumpRoot

do {
    Write-Log "PASS START"

    $before = Get-ProcessSnapshot
    Start-Sleep $ObservationWindowSeconds
    $after  = Get-ProcessSnapshot

    foreach ($pid in $before.Keys) {

        if (-not $after.ContainsKey($pid)) { continue }
        if (In-Cooldown $pid) { continue }

        if (Test-UIHang $before[$pid] $after[$pid]) {

            Write-Log "UIHANG DETECTED PID=$pid"
            $ts = Get-Date -Format yyyyMMdd_HHmmss

            # ---------------------------
            # HARD PROOF STOP (WPR)
            # ---------------------------
            $etlPath = Join-Path $DumpRoot "HardProof_${pid}_$ts.etl"
            $etwTaken = Stop-AutoCapHardProof -OutputEtl $etlPath

            # ---------------------------
            # USER MODE DUMP
            # ---------------------------
            $dumpPath = Join-Path $DumpRoot "UIHang_${pid}.dmp"

            if (Invoke-ProcDump -TargetProcId $pid -DumpPath $dumpPath) {

                Write-Log "DUMP CREATED $dumpPath"
                Invoke-Cdb -DumpPath $dumpPath | Out-Null
                Write-Log "CDB COMPLETE"

                if ($etwTaken) {
                    Write-HardProofSummary -EtlPath $etlPath
                }

                Mark-Captured $pid
            }
            else {
                Write-Log "ERROR: ProcDump failed PID=$pid"
            }

            # ---------------------------
            # RESTART HARD PROOF
            # ---------------------------
            Start-AutoCapHardProof -WorkingDir $DumpRoot
        }
    }

} while ($true)

Write-Log "=== AutoCapture V44 END ==="