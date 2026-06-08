## The Script — Save as `Analyze-EtlStack.ps1`

```powershell
#Requires -RunAsAdministrator
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# ============================================================
# Analyze-EtlStack.ps1
# Parses a WPA/xperf ETL CPU sampled stack export (CSV)
# Scores .sys drivers by Weight and Stack Depth
# Outputs ranked HTML + CSV report
# PowerShell 5.1 safe
# ============================================================

param(
    [Parameter(Mandatory=$true)]
    [string]$EtlCsvPath,          # Path to WPA exported CSV (CPU Usage Sampled)

    [string]$OutDir = "$env:ProgramData\CpuSpikeCapture\Reports",

    [int]$TopN = 20               # Top N drivers to report
)

# -------------------------------------------------------
# INIT
# -------------------------------------------------------
if (-not (Test-Path $EtlCsvPath)) {
    Write-Error "CSV not found: $EtlCsvPath"
    exit 1
}

New-Item -ItemType Directory -Path $OutDir -Force | Out-Null

$Timestamp   = Get-Date -Format 'yyyyMMdd_HHmmss'
$ReportCsv   = Join-Path $OutDir "DriverScores_$Timestamp.csv"
$ReportHtml  = Join-Path $OutDir "DriverScores_$Timestamp.html"
$LogFile     = Join-Path $OutDir "Analyze_$Timestamp.log"

function Log {
    param($Msg)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') $Msg"
    $line | Tee-Object -FilePath $LogFile -Append
}

Log "=== ETL Stack Analyzer START ==="
Log "Input : $EtlCsvPath"
Log "OutDir: $OutDir"

# -------------------------------------------------------
# STEP 1 — PARSE CSV
# -------------------------------------------------------
Log "Parsing CSV..."

$raw = Import-Csv -Path $EtlCsvPath

# Detect stack column name (WPA exports vary slightly)
$stackCol  = ($raw[0].PSObject.Properties.Name | Where-Object { $_ -match 'Stack' })[0]
$weightCol = ($raw[0].PSObject.Properties.Name | Where-Object { $_ -match 'Weight' })[0]

if (-not $stackCol -or -not $weightCol) {
    Write-Error "Could not find Stack or Weight columns. Check CSV export format."
    exit 1
}

Log "Stack column  : $stackCol"
Log "Weight column : $weightCol"
Log "Total rows    : $($raw.Count)"

# -------------------------------------------------------
# STEP 2 — EXTRACT .SYS ENTRIES PER ROW
# -------------------------------------------------------
Log "Extracting .sys entries from stacks..."

# Hashtable: driver name -> list of [weight, depth] pairs
$driverData = @{}

foreach ($row in $raw) {
    $stackRaw  = $row.$stackCol
    $weightRaw = $row.$weightCol

    if (:IsNullOrWhiteSpace($stackRaw)) { continue }
    if (:IsNullOrWhiteSpace($weightRaw)) { continue }

    # Clean weight — remove commas, parse as double
    $weightClean = $weightRaw -replace ',', '' -replace '\s', ''
    $weightVal   = 0.0
    if (-not :TryParse($weightClean, [ref]$weightVal)) { continue }

    # Count stack depth = number of pipe/indent segments before the driver name
    # WPA indents with "  |    " per level — count leading pipe chars
    $depthMatch = :Match($stackRaw, '^(\s*\|[\s\|]*)-\s*')
    $depth = 0
    if ($depthMatch.Success) {
        # Count occurrences of "|" in the indent prefix
        $depth = ($depthMatch.Value.ToCharArray() | Where-Object { $_ -eq '|' }).Count
    }

    # Extract .sys filename (case insensitive)
    $sysMatch = :Match($stackRaw, '([a-zA-Z0-9_\-]+\.sys)', 'IgnoreCase')
    if (-not $sysMatch.Success) { continue }

    $driverName = $sysMatch.Groups[1].Value.ToLower()

    if (-not $driverData.ContainsKey($driverName)) {
        $driverData[$driverName] = [System.Collections.Generic.List[PSObject]]::new()
    }

    $driverData[$driverName].Add([pscustomobject]@{
        Weight = $weightVal
        Depth  = $depth
    })
}

Log "Unique .sys drivers found: $($driverData.Keys.Count)"

# -------------------------------------------------------
# STEP 3 — SCORE EACH DRIVER
# -------------------------------------------------------
Log "Scoring drivers..."

$totalWeight = ($driverData.Values | ForEach-Object { $_ } |
    Measure-Object -Property Weight -Sum).Sum

if ($totalWeight -eq 0) {
    Write-Error "Total weight is zero — check CSV content."
    exit 1
}

$scores = @()

foreach ($driver in $driverData.Keys) {
    $entries     = $driverData[$driver]
    $count       = $entries.Count
    $totalW      = ($entries | Measure-Object -Property Weight -Sum).Sum
    $maxDepth    = ($entries | Measure-Object -Property Depth -Maximum).Maximum
    $avgDepth    = ($entries | Measure-Object -Property Depth -Average).Average
    $pctWeight   = :Round(($totalW / $totalWeight) * 100, 4)

    # -------------------------------------------------------
    # SCORING FORMULA
    #
    # WeightScore  = % of total CPU weight (0-100)
    # DepthScore   = normalized avg depth (deeper = higher score)
    #                capped at depth 30 to avoid outlier skew
    # CompositeScore = (WeightScore * 0.70) + (DepthScore * 0.30)
    #
    # Rationale:
    #   Weight is the primary signal (actual CPU time consumed)
    #   Depth amplifies drivers buried deep in kernel call chains
    #   (deep = likely called by many others = systemic impact)
    # -------------------------------------------------------

    $depthCapped    = :Min($avgDepth, 30)
    $depthScore     = :Round(($depthCapped / 30) * 100, 4)
    $compositeScore = :Round(($pctWeight * 0.70) + ($depthScore * 0.30), 4)

    # Risk grade
    $grade = switch ($true) {
        { $compositeScore -ge 10 } { 'CRITICAL' ; break }
        { $compositeScore -ge 5  } { 'HIGH'     ; break }
        { $compositeScore -ge 2  } { 'MEDIUM'   ; break }
        { $compositeScore -ge 0.5} { 'LOW'      ; break }
        default                    { 'TRACE'    }
    }

    # Classify driver type
    $classification = switch -Regex ($driver) {
        'csagent|cspcm|csstatic|crowdstrike' { 'EDR/Security' }
        'wdfilter|mpfilter|mpsdrv'           { 'Windows Defender' }
        'ntfs|refs|fat'                      { 'Filesystem' }
        'fltmgr'                             { 'Filter Manager' }
        'ntoskrnl|ntkrnl|hal'               { 'OS Kernel' }
        'tcpip|ndis|netio'                   { 'Network' }
        'storport|stornvme|disk'             { 'Storage' }
        'dxgkrnl|nvlddmkm|igdkmd'           { 'GPU/Display' }
        default                              { 'Unknown/Third-Party' }
    }

    $scores += [pscustomobject]@{
        Rank            = 0   # filled after sort
        Driver          = $driver
        Classification  = $classification
        Grade           = $grade
        CompositeScore  = $compositeScore
        WeightPct       = $pctWeight
        TotalWeightMs   = :Round($totalW, 2)
        MaxDepth        = $maxDepth
        AvgDepth        = :Round($avgDepth, 2)
        Occurrences     = $count
    }
}

# Sort and assign rank
$ranked = $scores | Sort-Object CompositeScore -Descending
$rank   = 1
foreach ($s in $ranked) { $s.Rank = $rank; $rank++ }

$topResults = $ranked | Select-Object -First $TopN

# -------------------------------------------------------
# STEP 4 — EXPORT CSV
# -------------------------------------------------------
$topResults | Export-Csv -Path $ReportCsv -NoTypeInformation
Log "CSV report saved: $ReportCsv"

# -------------------------------------------------------
# STEP 5 — EXPORT HTML REPORT
# -------------------------------------------------------
Log "Generating HTML report..."

function Get-GradeColor {
    param($g)
    switch ($g) {
        'CRITICAL' { return '#c0392b' }
        'HIGH'     { return '#e67e22' }
        'MEDIUM'   { return '#f1c40f' }
        'LOW'      { return '#27ae60' }
        default    { return '#95a5a6' }
    }
}

$tableRows = foreach ($r in $topResults) {
    $color = Get-GradeColor $r.Grade
    @"
<tr>
  <td>$($r.Rank)</td>
  <td><strong>$($r.Driver)</strong></td>
  <td>$($r.Classification)</td>
  <td style='color:$color;font-weight:bold'>$($r.Grade)</td>
  <td>$($r.CompositeScore)</td>
  <td>$($r.WeightPct)%</td>
  <td>$($r.TotalWeightMs) ms</td>
  <td>$($r.MaxDepth)</td>
  <td>$($r.AvgDepth)</td>
  <td>$($r.Occurrences)</td>
</tr>
"@
}

$html = @"
<!DOCTYPE html>
<html>
<head>
<title>CPU Spike - Driver Stack Analysis</title>
<style>
  body { font-family: Segoe UI, sans-serif; background:#1e1e2e; color:#cdd6f4; padding:20px; }
  h1   { color:#89b4fa; }
  h3   { color:#a6e3a1; }
  table{ border-collapse:collapse; width:100%; margin-top:10px; }
  th   { background:#313244; color:#cba6f7; padding:8px 12px; text-align:left; }
  td   { padding:7px 12px; border-bottom:1px solid #45475a; }
  tr:hover { background:#313244; }
  .badge { padding:2px 8px; border-radius:4px; font-size:0.85em; }
</style>
</head>
<body>
<h1>🔍 CPU Spike — Driver Stack Analyzer</h1>
<h3>Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</h3>
<p>Source: <code>$EtlCsvPath</code></p>
<p>Total Unique Drivers: <strong>$($driverData.Keys.Count)</strong> &nbsp;|&nbsp;
   Total Weight Sampled: <strong>$(:Round($totalWeight,2)) ms</strong></p>

<table>
<thead>
<tr>
  <th>Rank</th><th>Driver</th><th>Type</th><th>Grade</th>
  <th>Composite Score</th><th>CPU Weight %</th><th>Total Weight (ms)</th>
  <th>Max Depth</th><th>Avg Depth</th><th>Occurrences</th>
</tr>
</thead>
<tbody>
$($tableRows -join "`n")
</tbody>
</table>

<br/>
<h3>📐 Scoring Formula</h3>
<pre style='background:#313244;padding:12px;border-radius:6px'>
CompositeScore = (WeightScore × 0.70) + (DepthScore × 0.30)

WeightScore  = driver's % of total sampled CPU weight
DepthScore   = normalized avg stack depth (max cap = 30 levels)

Grade Thresholds:
  CRITICAL  ≥ 10.0
  HIGH      ≥  5.0
  MEDIUM    ≥  2.0
  LOW       ≥  0.5
  TRACE     <  0.5
</pre>
</body>
</html>
"@

$html | Out-File -FilePath $ReportHtml -Encoding UTF8
Log "HTML report saved: $ReportHtml"

# -------------------------------------------------------
# STEP 6 — CONSOLE SUMMARY
# -------------------------------------------------------
Log "=== TOP DRIVERS BY COMPOSITE SCORE ==="

$topResults | Format-Table Rank, Driver, Classification, Grade,
    CompositeScore, WeightPct, MaxDepth, Occurrences -AutoSize

Log "=== ETL Stack Analyzer COMPLETE ==="
Write-Host "`nReports saved to: $OutDir" -ForegroundColor Cyan