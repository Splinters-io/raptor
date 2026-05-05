r"""Check ExpLoading run status on rengy."""

STATUS_SCRIPT = r'''
$resultsFile = "C:\Users\agent\exploading-results\results.jsonl"
$checkpoint = "C:\Users\agent\exploading-results\checkpoint.log"
$artifactsDir = "C:\Users\agent\exploading-results\artifacts"

Write-Host "=== ExpLoading Status ==="
Write-Host ""

# Task status
$task = schtasks /query /tn RaptorExpLoading /fo LIST 2>$null
if ($task) {
    $status = ($task | Select-String "Status").ToString().Split(":")[1].Trim()
    Write-Host "Task: $status"
} else {
    Write-Host "Task: not found"
}

# Checkpoint — read with file sharing to avoid lock conflict
$checkpointLines = @()
if (Test-Path $checkpoint) {
    try {
        $fs = [System.IO.FileStream]::new(
            $checkpoint,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
        $sr = [System.IO.StreamReader]::new($fs)
        $raw = $sr.ReadToEnd()
        $sr.Close()
        $fs.Close()
        $checkpointLines = @($raw -split "`r?`n" | Where-Object { $_.Trim() })
    } catch {
        # Last resort: estimate from file size
        $size = (Get-Item $checkpoint -ErrorAction SilentlyContinue).Length
        $estLines = [math]::Round($size / 120)  # ~120 bytes per line avg
        Write-Host "Checkpoint: locked (est. ~$estLines entries from ${size} bytes)"
    }
}

if ($checkpointLines.Count -gt 0) {
    $done = ($checkpointLines | Where-Object { $_ -match '^DONE' }).Count
    $skipped = ($checkpointLines | Where-Object { $_ -match '^SKIPPED' }).Count
    $crashed = ($checkpointLines | Where-Object { $_ -match '^CRASHED' }).Count
    $started = ($checkpointLines | Where-Object { $_ -match '^STARTED' }).Count
    $inflight = $started - $done - $skipped - $crashed

    $total = $done + $skipped + $crashed
    $pct = if ($total -gt 0) { [math]::Round(($total / 19450) * 100, 1) } else { 0 }

    Write-Host "Processed: $done done, $skipped skipped, $crashed crashed"
    Write-Host "In flight: $inflight"
    Write-Host "Progress: $total / 19450 ($pct%)"

    # Rate and ETA
    if ($done -gt 10) {
        $firstLine = $checkpointLines | Select-Object -First 1
        $lastLine = $checkpointLines | Select-Object -Last 1
        $firstParts = $firstLine -split '\|'
        $lastParts = $lastLine -split '\|'
        if ($firstParts.Count -ge 2 -and $lastParts.Count -ge 2) {
            try {
                $t1 = [datetime]::ParseExact($firstParts[1].Trim(), 'yyyy-MM-dd HH:mm:ss', $null)
                $t2 = [datetime]::ParseExact($lastParts[1].Trim(), 'yyyy-MM-dd HH:mm:ss', $null)
                $elapsed = ($t2 - $t1).TotalSeconds
                if ($elapsed -gt 0) {
                    $rate = $total / $elapsed
                    $remaining = (19450 - $total) / $rate
                    $eta = (Get-Date).AddSeconds($remaining)
                    Write-Host "Rate: $([math]::Round($rate, 2))/sec"
                    Write-Host "ETA: $($eta.ToString('yyyy-MM-dd HH:mm'))"
                }
            } catch {}
        }
    }

    Write-Host ""
    Write-Host "Last 5 entries:"
    $checkpointLines | Select-Object -Last 5 | ForEach-Object { Write-Host "  $_" }
}

Write-Host ""

# Results
if (Test-Path $resultsFile) {
    try {
        $fs2 = [System.IO.FileStream]::new(
            $resultsFile,
            [System.IO.FileMode]::Open,
            [System.IO.FileAccess]::Read,
            [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
        $sr2 = [System.IO.StreamReader]::new($fs2)
        $raw2 = $sr2.ReadToEnd()
        $sr2.Close()
        $fs2.Close()
        $hitLines = @($raw2 -split "`r?`n" | Where-Object { $_.Trim() })
    } catch {
        $hitLines = @()
    }

    Write-Host "NAME_NOT_FOUND hits: $($hitLines.Count)"
    Write-Host ""

    foreach ($line in $hitLines | Select-Object -Last 15) {
        try {
            $obj = $line | ConvertFrom-Json
            $wants = $obj.name_not_found -join ', '
            $dropped = ''
            if ($obj.dropped_files -and $obj.dropped_files.Count -gt 0) {
                $dropped = " [dropped: $($obj.dropped_files -join ', ')]"
            }
            Write-Host "  $($obj.binary_name) -> $wants$dropped"
        } catch {}
    }
} else {
    Write-Host "No hits yet"
}

# Artifacts
if (Test-Path $artifactsDir) {
    $artCount = (Get-ChildItem $artifactsDir -Recurse -File -ErrorAction SilentlyContinue).Count
    if ($artCount -gt 0) {
        Write-Host ""
        Write-Host "Artifacts: $artCount files dropped into m00 and archived"
    }
}
'''


def build_status_script() -> str:
    return STATUS_SCRIPT
