r"""Independent resource watchdog — kills Procmon before the box dies.

Runs as a separate scheduled task. Checks every 10 seconds:
- Kernel nonpaged pool
- User RAM
- Commit charge

If any crosses critical threshold, immediately kills Procmon and
logs what happened. The harness detects Procmon is gone and handles
the interrupted batch gracefully.

Deploy as a separate scheduled task that starts before the harness.
"""

WATCHDOG_RESOURCE_SCRIPT = r'''
param(
    [int]$CheckIntervalSec = 10,
    [int]$RamThresholdPct = 75,
    [int]$PoolThresholdMB = 2048,
    [int]$CommitThresholdPct = 85
)

$logFile = "C:\Users\agent\exploading-results\watchdog-resource.log"

function Log($msg) {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "$ts | $msg"
    Add-Content -Path $logFile -Value $line
}

Log "WATCHDOG STARTED: RAM>$RamThresholdPct% Pool>$($PoolThresholdMB)MB Commit>$CommitThresholdPct%"

while ($true) {
    Start-Sleep -Seconds $CheckIntervalSec

    try {
        $os = Get-CimInstance Win32_OperatingSystem
        $ramTotal = $os.TotalVisibleMemorySize
        $ramFree = $os.FreePhysicalMemory
        $ramPct = [math]::Round((($ramTotal - $ramFree) / $ramTotal) * 100, 1)

        $perf = Get-CimInstance Win32_PerfFormattedData_PerfOS_Memory
        $poolNonpagedMB = [math]::Round($perf.PoolNonpagedBytes / 1MB, 0)

        $commitTotal = $os.SizeStoredInPagingFiles
        $commitUsed = $commitTotal - $os.FreeSpaceInPagingFiles
        $commitPct = if ($commitTotal -gt 0) { [math]::Round(($commitUsed / $commitTotal) * 100, 1) } else { 0 }

        $kill = $false
        $reason = ""

        if ($ramPct -gt $RamThresholdPct) {
            $kill = $true
            $reason = "RAM at $ramPct% (threshold $RamThresholdPct%)"
        }
        elseif ($poolNonpagedMB -gt $PoolThresholdMB) {
            $kill = $true
            $reason = "Kernel pool at ${poolNonpagedMB}MB (threshold ${PoolThresholdMB}MB)"
        }
        elseif ($commitPct -gt $CommitThresholdPct) {
            $kill = $true
            $reason = "Commit charge at $commitPct% (threshold $CommitThresholdPct%)"
        }

        if ($kill) {
            Log "KILL: $reason"
            $procmonCount = (Get-Process Procmon64 -ErrorAction SilentlyContinue).Count
            if ($procmonCount -gt 0) {
                taskkill /F /IM Procmon64.exe 2>$null
                Log "Killed $procmonCount Procmon instance(s)"
            }

            # Also kill any hung cmd.exe children from the harness
            $cmdProcs = Get-CimInstance Win32_Process -Filter "Name = 'cmd.exe'" -ErrorAction SilentlyContinue |
                Where-Object { $_.CommandLine -match 'm00' }
            if ($cmdProcs) {
                foreach ($p in $cmdProcs) {
                    Stop-Process -Id $p.ProcessId -Force -ErrorAction SilentlyContinue
                }
                Log "Killed $($cmdProcs.Count) harness cmd.exe processes"
            }

            # Wait for resources to recover before allowing Procmon to restart
            Start-Sleep -Seconds 60
        }
    } catch {
        Log "ERROR: $($_.Exception.Message)"
    }
}
'''


def build_watchdog_resource_script() -> str:
    return WATCHDOG_RESOURCE_SCRIPT
