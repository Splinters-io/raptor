r"""ExpLoading Phase 2 — low-priv execution, SYSTEM monitoring.

Run as SYSTEM. Launches each binary as carroll (low-priv) from
C:\Users\carroll\Desktop\m00\. Procmon as SYSTEM captures all
NAME_NOT_FOUND events in m00, including the process owner.

The CSV includes "User Name" column — we use this to tag each hit:
  - SYSTEM/service = LPE candidate
  - carroll = user-level (still useful for lateral/persistence)

Key difference from phase 1: execution is low-priv, monitoring is high-priv.
If a high-priv process searches a low-priv controlled path, that's LPE.
"""

HARNESS_PHASE2_SCRIPT = r'''
param(
    [string]$RunlistPath,
    [string]$CheckpointPath,
    [string]$OutputDir,
    [string]$Tier = 'safe',
    [int]$TimeoutSec = 5,
    [int]$BatchSize = 200,
    [int]$RamThreshold = 80,
    [string]$LowPrivUser = 'carroll',
    [string]$LowPrivPass = 'Pewpewpew2020!!**'
)

$ErrorActionPreference = 'SilentlyContinue'

$m00 = "C:\Users\$LowPrivUser\Desktop\m00"
$procmon = "C:\Tools\sysinternals\Procmon64.exe"
$psexec = "C:\Tools\sysinternals\PsExec64.exe"
$resultsFile = Join-Path $OutputDir "results-phase2.jsonl"
$resourceLog = Join-Path $OutputDir "resource-phase2.log"
$m00re = [regex]::Escape($m00)

if (-not (Test-Path $m00)) { New-Item -Path $m00 -ItemType Directory -Force | Out-Null }
if (-not (Test-Path $OutputDir)) { New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null }

function Get-ResourceUsage {
    $os = Get-CimInstance Win32_OperatingSystem
    $ramTotal = $os.TotalVisibleMemorySize
    $ramFree = $os.FreePhysicalMemory
    $ramPct = [math]::Round((($ramTotal - $ramFree) / $ramTotal) * 100, 1)
    return [PSCustomObject]@{ Ram = $ramPct; RamFreeMB = [math]::Round($ramFree / 1024, 0) }
}

function Log($msg) {
    $ts = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $r = Get-ResourceUsage
    $line = "$ts | RAM:$($r.Ram)% Free:$($r.RamFreeMB)MB | $msg"
    Add-Content -Path $resourceLog -Value $line
    [Console]::Error.WriteLine($line)
}

function Kill-AllProcmon {
    taskkill /F /IM Procmon64.exe 2>$null
    Start-Sleep -Seconds 2
    taskkill /F /IM Procmon64.exe 2>$null
    Start-Sleep -Seconds 1
}

function Start-Procmon([string]$pmlPath) {
    Kill-AllProcmon
    Remove-Item $pmlPath -Force -ErrorAction SilentlyContinue
    Start-Process -FilePath $procmon -ArgumentList "/Quiet","/Minimized","/BackingFile",$pmlPath,"/AcceptEula" -Wait:$false
    Start-Sleep -Seconds 4
    return (Get-Process Procmon64 -ErrorAction SilentlyContinue).Count
}

# --- Init ---
. C:\Users\agent\checkpoint.ps1
$state = Initialize-Checkpoint -Path $CheckpointPath
Log "PHASE 2 START: low-priv=$LowPrivUser, monitor=SYSTEM"
Log "Checkpoint: $($state.TotalProcessed) already processed"
if ($state.CrashCulprit) { Log "CRASH RECOVERY: $($state.CrashCulprit)" }
$runtimeBlocked = $state.Blocked

$runlist = (Get-Content $RunlistPath -Raw | ConvertFrom-Json).runlist
$targets = $runlist | Where-Object { $_.tier -eq $Tier }
Log "Targets: $($targets.Count) ($Tier)"

$remaining = [System.Collections.Generic.List[PSObject]]::new()
foreach ($t in $targets) {
    if (-not $state.Completed.Contains($t.path) -and -not $runtimeBlocked.Contains($t.path)) {
        $remaining.Add($t)
    }
}
Log "Remaining: $($remaining.Count)"

Kill-AllProcmon

$totalProcessed = 0
$totalHits = 0
$batchNum = 0

for ($i = 0; $i -lt $remaining.Count; $i += $BatchSize) {
    $batchNum++
    $batchEnd = [math]::Min($i + $BatchSize, $remaining.Count)
    $batch = $remaining[$i..($batchEnd - 1)]

    Log "=== Batch $batchNum ($($batch.Count) binaries) ==="

    # Resource check
    $r = Get-ResourceUsage
    if ($r.Ram -gt $RamThreshold) {
        Log "THROTTLE: RAM $($r.Ram)%, waiting..."
        Kill-AllProcmon
        do { Start-Sleep -Seconds 30; $r = Get-ResourceUsage } while ($r.Ram -gt 60)
        Log "RESUMED"
    }

    $pmlFile = Join-Path $OutputDir "batch_$batchNum.pml"
    $csvFile = Join-Path $OutputDir "batch_$batchNum.csv"

    Get-ChildItem $m00 -Force | Remove-Item -Recurse -Force

    $pmCount = Start-Procmon $pmlFile
    if ($pmCount -eq 0) {
        Log "ERROR: Procmon failed, skipping batch"
        continue
    }

    $launchLog = [System.Collections.Generic.List[PSObject]]::new()

    # Build a batch script for this batch — runs all binaries as carroll from m00
    $batchScript = Join-Path $OutputDir "batch_$batchNum.bat"
    $batchLines = @("@echo off", "cd /d `"$m00`"")

    $validTargets = [System.Collections.Generic.List[PSObject]]::new()
    foreach ($target in $batch) {
        if (-not (Test-Path $target.path)) {
            Write-CheckpointSkipped -BinaryPath $target.path -Reason "file_not_found"
            continue
        }
        $validTargets.Add($target)
        # Each binary: run with timeout, clean m00 after
        $batchLines += "cmd.exe /c `"$($target.path)`""
        $batchLines += "timeout /t 1 /nobreak >nul"
        $batchLines += "del /q /f `"$m00\*`" 2>nul"
    }
    $batchLines | Out-File -FilePath $batchScript -Encoding ASCII

    # Checkpoint all as started
    foreach ($target in $validTargets) {
        Write-CheckpointStarted -BinaryPath $target.path
    }

    # Run the entire batch as carroll — ONE PsExec call
    Log "Running batch as $LowPrivUser ($($validTargets.Count) binaries)..."
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $psexec
    $psi.Arguments = "-accepteula -u $LowPrivUser -p $LowPrivPass -w `"$m00`" cmd.exe /c `"$batchScript`""
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true

    $batchProc = [System.Diagnostics.Process]::Start($psi)

    # Wait for batch with total timeout (TimeoutSec * batch count + buffer)
    $totalTimeout = ($TimeoutSec + 2) * $validTargets.Count * 1000
    if (-not $batchProc.WaitForExit($totalTimeout)) {
        try { $batchProc.Kill() } catch {}
        Log "Batch timed out"
    }

    # Mark all as done
    foreach ($target in $validTargets) {
        $launchLog.Add([PSCustomObject]@{
            path = $target.path; name = $target.name; exit_code = 0; dropped = @()
        })
        Write-CheckpointDone -BinaryPath $target.path -ExitCode 0
        $totalProcessed++
    }

    # Archive anything left in m00
    $leftover = Get-ChildItem $m00 -Force -ErrorAction SilentlyContinue
    if ($leftover) {
        $artifactDir = Join-Path $OutputDir "artifacts-phase2\batch_$batchNum"
        New-Item -Path $artifactDir -ItemType Directory -Force | Out-Null
        foreach ($f in $leftover) {
            Move-Item -Path $f.FullName -Destination $artifactDir -Force -ErrorAction SilentlyContinue
        }
    }
    Get-ChildItem $m00 -Force | Remove-Item -Recurse -Force

    Remove-Item $batchScript -Force -ErrorAction SilentlyContinue
    Log "Batch execution complete"

    # Stop Procmon and export
    Log "Stopping Procmon..."
    Kill-AllProcmon

    $batchHits = 0
    if (Test-Path $pmlFile) {
        Log "Exporting CSV..."
        $exportProc = Start-Process -FilePath $procmon -ArgumentList "/OpenLog",$pmlFile,"/SaveAs",$csvFile,"/AcceptEula" -PassThru -NoNewWindow
        while (-not $exportProc.HasExited) {
            Start-Sleep -Seconds 10
            $r = Get-ResourceUsage
            if ($r.Ram -gt 90) {
                Log "Export killed - RAM critical"
                taskkill /F /IM Procmon64.exe 2>$null
                break
            }
        }
        Kill-AllProcmon

        if (Test-Path $csvFile) {
            $csvSize = [math]::Round((Get-Item $csvFile).Length / 1MB, 1)
            Log "Parsing CSV ($csvSize MB)..."

            # Procmon CSV with user info:
            # "Time","Process Name","PID","Operation","Path","Result","Detail","User"
            $hitsByProcess = @{}

            $fs = [System.IO.FileStream]::new($csvFile, 'Open', 'Read', 'ReadWrite')
            $sr = [System.IO.StreamReader]::new($fs)
            $header = $sr.ReadLine()
            Log "CSV header: $header"

            while (-not $sr.EndOfStream) {
                $line = $sr.ReadLine()
                if ($line -match 'NAME NOT FOUND' -and $line -match $m00re) {
                    # Parse: "Time","Process Name","PID","Operation","Path","Result","Detail"
                    if ($line -match '"([^"]+)","(\d+)","([^"]+)","([^"]+)","([^"]+)","([^"]*)"') {
                        $procName = $Matches[1]
                        $pid = $Matches[2]
                        $op = $Matches[3]
                        $wantedPath = $Matches[4]
                        $result = $Matches[5]
                        $detail = $Matches[6]

                        $wantedFile = [System.IO.Path]::GetFileName($wantedPath)
                        if (-not $wantedFile) { continue }

                        # Get process owner from the PID (if still alive) or from Detail
                        $key = "$procName|$pid"
                        if (-not $hitsByProcess.ContainsKey($key)) {
                            $hitsByProcess[$key] = [PSCustomObject]@{
                                process_name = $procName
                                pid = $pid
                                files = [System.Collections.Generic.HashSet[string]]::new(
                                    [System.StringComparer]::OrdinalIgnoreCase)
                            }
                        }
                        $hitsByProcess[$key].files.Add($wantedFile) | Out-Null
                    }
                }
            }
            $sr.Close(); $fs.Close()

            # Write results grouped by process
            foreach ($key in $hitsByProcess.Keys) {
                $hit = $hitsByProcess[$key]
                $info = $launchLog | Where-Object {
                    $_.name -eq $hit.process_name -or
                    [System.IO.Path]::GetFileNameWithoutExtension($_.name) -eq $hit.process_name
                } | Select-Object -First 1

                $result = [PSCustomObject]@{
                    process_name = $hit.process_name
                    process_pid = $hit.pid
                    launched_as = $LowPrivUser
                    binary_path = if ($info) { $info.path } else { "" }
                    binary_name = if ($info) { $info.name } else { $hit.process_name }
                    exit_code = if ($info) { $info.exit_code } else { -1 }
                    name_not_found = @($hit.files)
                    count = $hit.files.Count
                    dropped_files = if ($info) { @($info.dropped) } else { @() }
                    batch = $batchNum
                }
                ($result | ConvertTo-Json -Compress) | Add-Content -Path $resultsFile
                $batchHits++
            }

            Remove-Item $csvFile -Force -ErrorAction SilentlyContinue
        }
        Remove-Item $pmlFile -Force -ErrorAction SilentlyContinue
    }

    $totalHits += $batchHits
    Log "Batch $batchNum done: $($batch.Count) binaries, $batchHits hits"
}

Kill-AllProcmon
$summary = Get-CheckpointSummary
[PSCustomObject]@{
    hostname = $env:COMPUTERNAME
    timestamp = (Get-Date -Format o)
    phase = 2; tier = $Tier; m00 = $m00
    method = "Procmon SYSTEM + PsExec low-priv"
    low_priv_user = $LowPrivUser
    total_processed = $totalProcessed; total_hits = $totalHits
    batches = $batchNum; checkpoint = $summary
} | ConvertTo-Json -Depth 4 | Out-File (Join-Path $OutputDir "exploading-summary-phase2.json") -Encoding UTF8

Log "COMPLETE: $totalProcessed processed, $totalHits hits"
'''


def build_harness_phase2_script() -> str:
    return HARNESS_PHASE2_SCRIPT
