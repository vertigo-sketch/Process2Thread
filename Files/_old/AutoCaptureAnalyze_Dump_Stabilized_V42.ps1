# =========================================
# MAIN LOOP – AutoCapture V37.9 PIDSAFE + HARD PROOF
# =========================================

Write-Log "=== AutoCapture V37.9 PIDSAFE START ==="

# --- Start rolling ETW once (kernel File I/O + FilterManager) ---
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

            # -----------------------------
            # HARD PROOF: STOP ETW (pre-hang kernel evidence)
            # -----------------------------
            $etlPath = Join-Path $DumpRoot ("HangTrace_{0}_{1}.etl" -f `
                $procKey, (Get-Date -Format yyyyMMdd_HHmmss))

            Stop-AutoCapEtwTrace -SessionName $EtwSessionName -EtlPath $etlPath
            Write-Log "ETW TRACE SAVED: $etlPath"

            # -----------------------------
            # DUMP CAPTURE
            # -----------------------------
            $dumpPath = Join-Path $DumpRoot ("UIHang_{0}.dmp" -f $procKey)

            if (Invoke-ProcDump -TargetProcId $procKey -DumpPath $dumpPath) {

                Write-Log "DUMP CREATED: $dumpPath"

                # -----------------------------
                # CDB USER-MODE ANALYSIS
                # -----------------------------
                Invoke-Cdb -DumpPath $dumpPath | Out-Null
                Write-Log "CDB ANALYSIS COMPLETE"

                # -----------------------------
                # HARD PROOF: ETL → XML → FILTER SCORE
                # -----------------------------
                $xmlPath = [System.IO.Path]::ChangeExtension($etlPath, ".xml")
                Convert-EtlToXml -EtlPath $etlPath -XmlPath $xmlPath

                $filterScore = Get-FilterDelayRepetitionScoreFromEtlXml -XmlPath $xmlPath
                Write-FilterDelayScoreLogLine -Result $filterScore -LogPath $LogPath

                Mark-Captured $procKey
                Write-Log "CAPTURE MARKED PID=$procKey"
            }
            else {
                Write-Log "ERROR: ProcDump failed for PID=$procKey"
            }

            # -----------------------------
            # HARD PROOF: Restart rolling ETW
            # -----------------------------
            Start-AutoCapEtwRollingTrace -SessionName $EtwSessionName
        }
    }

} while ($true)
