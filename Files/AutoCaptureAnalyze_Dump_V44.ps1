<# =====================================================================
 AutoCaptureAnalyze_Dump_V44.ps1
 ===================================================================== #>

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ===============================
# CONFIGURATION
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
    throw "AutoCaptureAnalyze_Dump_V44 MUST be run elevated (admin)."
}

# ===============================
# ETW – KERNEL SAFE IMPLEMENTATION
# ===============================

function Stop-IfEtwSessionExists {
    param([string]$SessionName)

    & logman query $SessionName 1>$null 2>$null
    if ($LASTEXITCODE -eq 0) {
        & logman stop    $SessionName 1>$null 2>$null
        & logman delete  $SessionName 1>$null 2>$null
    }
}

function Start-AutoCapEtwRollingTrace {
    param(
        [Parameter(Mandatory)][string]$SessionName,
        [int]$MaxMB = 256
    )

    Stop-IfEtwSessionExists $SessionName

    $kernelFlags = "PROC_THREAD+FILE_IO+FILE_IO_INIT+DISK_IO+DISK_IO_INIT"
    $tempEtl = Join-Path $env:TEMP "$SessionName.etl"

    & logman create trace $SessionName `
        -kn $kernelFlags `
        -bs 1024 `
        -nb 64 256 `
        -max $MaxMB `
        -f bincirc `
        -o $tempEtl 1>$null 2>$null

    if ($LASTEXITCODE -ne 0) {
        throw "ETW CREATE FAILED (kernel logger)."
    }

    & logman start $SessionName 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "ETW START FAILED (kernel logger)."
    }

    $FilterMgrGuid = "{f3c5e28e-63f6-49c6-a204-e48a1bc4b09d}"

    & logman update trace $SessionName `
        -p $FilterMgrGuid 0xFFFFFFFFFFFFFFFF 0x5 1>$null 2>$null

    Write-Log "ETW STARTED ($SessionName)"
}

function Stop-AutoCapEtwTrace {
    param(
        [Parameter(Mandatory)][string]$SessionName,
        [Parameter(Mandatory)][string]$EtlPath
    )

    & logman stop $SessionName -o $EtlPath 1>$null 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "ETW STOP FAILED ($SessionName)"
    }

    & logman delete $SessionName 1>$null 2>$null

    Write-Log "ETW STOPPED ($SessionName) -> $EtlPath"
}

function Convert-EtlToXml {
    param(
        [Parameter(Mandatory)][string]$EtlPath,
        [Parameter(Mandatory)][string]$XmlPath
    )

    & tracerpt $EtlPath -of XML -o $XmlPath -y 1>$null 2>$null
}

function Get-FilterDelayScoreFromXml {
    param([Parameter(Mandatory)][string]$XmlPath)

    $xml = New-Object System.Xml.XmlDocument
    $xml.Load($XmlPath)

    $events = $xml.SelectNodes("//Event[System/Provider[@Name='Microsoft-Windows-FilterManager']]")

    if (-not $events -or $events.Count -eq 0) {
        return @{ Score = 0; Notes = "No FilterManager events" }
    }

    $counts = @{}

    foreach ($e in $events) {
        foreach ($d in $e.SelectNodes("./EventData/Data")) {
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
    $top    = $sorted[0]
    $total  = ($counts.Values | Measure-Object -Sum).Sum

    $pct = [math]::Round(($top.Value / $total) * 100, 2)

    return @{
        Score = $pct
        Top   = $top.Key
        Count = $top.Value
        Total = $total
    }
}

function Write-FilterScoreLog {
    param($Result)

    if ($Result.Score -eq 0) {
        Write-Log "FILTERPROOF Score=0 Notes='$($Result.Notes)'"
    } else {
        Write-Log "FILTERPROOF Score=$($Result.Score)% Top=$($Result.Top) Count=$($Result.Count)/$($Result.Total)"
    }
}

# ===============================
# DEPENDENCIES (ASSUMED EXISTING)
# ===============================
# These must already exist in your environment.
# They are intentionally NOT redefined:
#   Get-ProcessSnapshot
#   Test-UIHang
#   Invoke-ProcDump
#   Invoke-Cdb
#   In-Cooldown
#   Mark-Captured

# ===============================
# MAIN LOOP
# ===============================

Write-Log "=== AutoCaptureAnalyze_Dump_V44 START ==="

$EtwSessionName = "AutoCapHangTrace"
Start-AutoCapEtwRollingTrace -SessionName $EtwSessionName

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

            $etlPath = Join-Path $DumpRoot "HangTrace_${pid}_$ts.etl"
            Stop-AutoCapEtwTrace -SessionName $EtwSessionName -EtlPath $etlPath

            $dumpPath = Join-Path $DumpRoot "UIHang_${pid}.dmp"

            if (Invoke-ProcDump -TargetProcId $pid -DumpPath $dumpPath) {

                Write-Log "DUMP CREATED $dumpPath"
                Invoke-Cdb -DumpPath $dumpPath | Out-Null
                Write-Log "CDB COMPLETE"

                $xmlPath = [IO.Path]::ChangeExtension($etlPath, ".xml")
                Convert-EtlToXml -EtlPath $etlPath -XmlPath $xmlPath

                $score = Get-FilterDelayScoreFromXml -XmlPath $xmlPath
                Write-FilterScoreLog -Result $score

                Mark-Captured $pid
            }
            else {
                Write-Log "ERROR: ProcDump failed PID=$pid"
            }

            Start-AutoCapEtwRollingTrace -SessionName $EtwSessionName
        }
    }

} while ($true)

Write-Log "=== AutoCapture V44 END ==="