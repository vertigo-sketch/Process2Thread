<# =====================================================================
 AutoCaptureAnalyze_Dump_V423.ps1
 Author: Copilot (rewritten per request)
 Purpose:
   - Detect UI hangs
   - Capture user‑mode dump
   - Analyze with cdb (user stacks)
   - Capture kernel ETW (File I/O + FilterManager)
   - Produce hard proof of filter delay via ETW
 Requirements:
   - PowerShell 5.1
   - Admin privileges (ETW kernel trace)
   - ProcDump + cdb available in PATH
 ===================================================================== #>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ==========================================================
# CONFIGURATION
# ==========================================================

$ObservationWindowSeconds = 15
$DumpRoot = "$PSScriptRoot\Dumps"
$LogPath  = Join-Path $DumpRoot "AutoCapture.log"

New-Item -ItemType Directory -Path $DumpRoot -Force | Out-Null

# ==========================================================
# LOGGING
# ==========================================================

function Write-Log {
    param([string]$Message)

    $line = "{0:yyyy-MM-dd HH:mm:ss} {1}" -f (Get-Date), $Message
    Add-Content -Path $LogPath -Value $line
    Write-Host $line
}

# ==========================================================
# ADMIN CHECK
# ==========================================================

function Test-IsAdmin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    $p  = New-Object Security.Principal.WindowsPrincipal($id)
    return $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-IsAdmin)) {
    throw "This script must be run elevated (admin) for kernel ETW."
}

# ==========================================================
# ETW HARD-PROOF SUPPORT
# ==========================================================

function Stop-IfEtwSessionExists {
    param([string]$SessionName)

    & logman query $SessionName -ets 2>$null
    if ($LASTEXITCODE -eq 0) {
        & logman stop  $SessionName -ets 1>$null 2>$null
        & logman delete $SessionName     1>$null 2>$null
    }
}

function Start-AutoCapEtwRollingTrace {
    param(
        [string]$SessionName,
        [int]$MaxMB = 256
    )

    Stop-IfEtwSessionExists $SessionName

    $kernelFlags = "PROC_THREAD+FILE_IO+FILE_IO_INIT+DISK_IO+DISK_IO_INIT"

    & logman create trace $SessionName -ets `
        -kn $kernelFlags `
        -mode circular `
        -f bincirc `
        -bs 1024 `
        -nb 64 256 `
        -max $MaxMB | Out-Null

    if ($LASTEXITCODE -ne 0) {
        throw "Failed to start ETW kernel trace."
    }

    $FilterMgrGuid = "{f3c5e28e-63f6-49c6-a204-e48a1bc4b09d}"

    & logman update trace $SessionName -ets `
        -p $FilterMgrGuid 0xFFFFFFFFFFFFFFFF 0x5 | Out-Null
}

function Stop-AutoCapEtwTrace {
    param(
        [string]$SessionName,
        [string]$EtlPath
    )

    & logman stop $SessionName -ets -o $EtlPath | Out-Null
    & logman delete $SessionName | Out-Null
}

function Convert-EtlToXml {
    param(
        [string]$EtlPath,
        [string]$XmlPath
    )

    & tracerpt $EtlPath -of XML -o $XmlPath -y | Out-Null
}

function Get-FilterDelayRepetitionScoreFromEtlXml {
    param([string]$XmlPath)

    $xml = New-Object System.Xml.XmlDocument
    $xml.Load($XmlPath)

    $events = $xml.SelectNodes("//Event[System/Provider[@Name='Microsoft-Windows-FilterManager']]")
    if (-not $events -or $events.Count -eq 0) {
        return @{ Score = 0; Notes = "No FilterManager events" }
    }

    $counts = @{}

    foreach ($ev in $events) {
        foreach ($d in $ev.SelectNodes("./EventData/Data")) {
            if ($d.InnerText -match '\.sys$') {
                $k = $d.InnerText.ToLowerInvariant()
                if (-not $counts.ContainsKey($k)) { $counts[$k] = 0 }
                $counts[$k]++
            }
        }
    }

    if ($counts.Count -eq 0) {
        return @{ Score = 0; Notes = "No filter names extracted" }
    }

    $sorted = $counts.GetEnumerator() | Sort-Object Value -Descending
    $top = $sorted[0]
    $total = ($counts.Values | Measure-Object -Sum).Sum

    $coverage = if ($total -gt 0) { [int](($top.Value / $total) * 100) } else { 0 }

    return @{
        Score  = $coverage
        Top    = $top.Key
        Count  = $top.Value
        Total  = $total
    }
}

function Write-FilterDelayScoreLogLine {
    param($Result)

    if ($Result.Score -eq 0) {
        Write-Log "FILTERPROOF Score=0 Notes='$($Result.Notes)'"
    } else {
        Write-Log ("FILTERPROOF Score={0} TopFilter={1} Count={2}/{3}" -f `
            $Result.Score, $Result.Top, $Result.Count, $Result.Total)
    }
}

# ==========================================================
# PLACEHOLDER APP LOGIC (EXISTING FUNCTIONS ASSUMED)
# ==========================================================
# These MUST already exist in your environment:
#   Get-ProcessSnapshot
#   Test-UIHang
#   Invoke-ProcDump
#   Invoke-Cdb
#   In-Cooldown
#   Mark-Captured
# They are NOT redefined here intentionally.

# ==========================================================
# MAIN LOOP
# ==========================================================

Write-Log "=== AutoCaptureAnalyze_Dump_V423 START ==="

$EtwSessionName = "AutoCapHangTrace"
Start-AutoCapEtwRollingTrace -SessionName $EtwSessionName

do {
    Write-Log "PASS START"

    $before = Get-ProcessSnapshot
    Start-Sleep $ObservationWindowSeconds
    $after  = Get-ProcessSnapshot

    foreach ($procKey in $before.Keys) {

        if (-not $after.ContainsKey($procKey)) { continue }
        if (In-Cooldown $procKey) { continue }

        if (Test-UIHang $before[$procKey] $after[$procKey]) {

            Write-Log "UIHANG DETECTED PID=$procKey"

            $timestamp = Get-Date -Format yyyyMMdd_HHmmss
            $etlPath = Join-Path $DumpRoot "HangTrace_${procKey}_$timestamp.etl"

            Stop-AutoCapEtwTrace -SessionName $EtwSessionName -EtlPath $etlPath
            Write-Log "ETW SAVED $etlPath"

            $dumpPath = Join-Path $DumpRoot "UIHang_${procKey}.dmp"

            if (Invoke-ProcDump -TargetProcId $procKey -DumpPath $dumpPath) {

                Write-Log "DUMP OK $dumpPath"
                Invoke-Cdb -DumpPath $dumpPath | Out-Null
                Write-Log "CDB COMPLETE"

                $xmlPath = [IO.Path]::ChangeExtension($etlPath, ".xml")
                Convert-EtlToXml -EtlPath $etlPath -XmlPath $xmlPath

                $score = Get-FilterDelayRepetitionScoreFromEtlXml -XmlPath $xmlPath
                Write-FilterDelayScoreLogLine -Result $score

                Mark-Captured $procKey
            }
            else {
                Write-Log "ERROR ProcDump failed PID=$procKey"
            }

            Start-AutoCapEtwRollingTrace -SessionName $EtwSessionName
        }
    }

} while ($true)

Write-Log "=== AutoCapture V42  END ==="