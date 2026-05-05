r"""Diagnostic — verify Procmon captures the full PATHEXT search chain.

Runs known ExpLoading targets (from the blog) and dumps every
NAME_NOT_FOUND event in m00 to validate we see all extensions.
"""

DIAGNOSTIC_SCRIPT = r'''
$ErrorActionPreference = 'SilentlyContinue'

$m00 = "$env:USERPROFILE\Desktop\m00"
$outputDir = "$env:USERPROFILE\exploading-results"
$procmon = "C:\Tools\sysinternals\Procmon64.exe"

# Clean m00
if (-not (Test-Path $m00)) { New-Item -Path $m00 -ItemType Directory -Force | Out-Null }
Get-ChildItem $m00 -Force | Remove-Item -Recurse -Force

# Test binaries — known from the blog post
$testCases = @(
    @{ Name = "workfolders";       Cmd = "workfolders";                                       Expected = "control" },
    @{ Name = "mode";              Cmd = "mode";                                              Expected = "cmd" },
    @{ Name = "GatherNetworkInfo"; Cmd = "GatherNetworkInfo";                                 Expected = "cmd,powershell" },
    @{ Name = "iediagcmd";         Cmd = '"C:\Program Files\Internet Explorer\iediagcmd.exe"'; Expected = "ipconfig,route,netsh" }
)

$pml = "$outputDir\diagnostic.pml"
$csv = "$outputDir\diagnostic.csv"

# Remove old captures
Remove-Item $pml -Force -ErrorAction SilentlyContinue
Remove-Item $csv -Force -ErrorAction SilentlyContinue

Write-Host "=== ExpLoading Diagnostic ==="
Write-Host "m00: $m00"
Write-Host "Procmon: $procmon"
Write-Host ""

# Start Procmon - no filter config, capture everything
Write-Host "Starting Procmon (full capture, no filters)..."
& $procmon /Quiet /Minimized /BackingFile $pml /AcceptEula
Start-Sleep -Seconds 3

# Run each test binary
foreach ($tc in $testCases) {
    Write-Host ""
    Write-Host "--- Testing: $($tc.Name) ---"
    Write-Host "  Command: cmd /c $($tc.Cmd)"
    Write-Host "  Expected to want: $($tc.Expected)"

    # Clean m00 between runs
    Get-ChildItem $m00 -Force | Remove-Item -Recurse -Force

    $p = Start-Process -FilePath "cmd.exe" -ArgumentList "/c $($tc.Cmd)" `
        -WorkingDirectory $m00 -PassThru -NoNewWindow -RedirectStandardOutput "NUL"

    Start-Sleep -Seconds 4
    if (-not $p.HasExited) {
        # Kill process tree
        $children = Get-CimInstance Win32_Process -Filter "ParentProcessId = $($p.Id)"
        foreach ($child in $children) {
            Stop-Process -Id $child.ProcessId -Force -ErrorAction SilentlyContinue
        }
        Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    }
    Write-Host "  PID: $($p.Id), Exit: $($p.ExitCode)"

    # Check if anything was dropped in m00
    $dropped = Get-ChildItem $m00 -Force
    if ($dropped) {
        Write-Host "  Dropped files:"
        foreach ($f in $dropped) { Write-Host "    $($f.Name)" }
    }
}

# Stop Procmon
Write-Host ""
Write-Host "Stopping Procmon..."
& $procmon /Terminate
Start-Sleep -Seconds 3

# Export to CSV
Write-Host "Exporting to CSV..."
& $procmon /OpenLog $pml /SaveAs $csv /AcceptEula
Start-Sleep -Seconds 5

if (-not (Test-Path $csv)) {
    Write-Host "ERROR: CSV not created"
    exit 1
}

$csvSize = (Get-Item $csv).Length
Write-Host "CSV size: $([math]::Round($csvSize / 1MB, 1)) MB"
Write-Host ""

# Parse ALL events referencing m00
Write-Host "=== All NAME NOT FOUND events in m00 ==="
Write-Host ""

$fs = [System.IO.FileStream]::new($csv, [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
$reader = [System.IO.StreamReader]::new($fs)
$header = $reader.ReadLine()

Write-Host "CSV header: $header"
Write-Host ""

$m00Escaped = [regex]::Escape($m00)
$allHits = @()
$lineCount = 0

while (-not $reader.EndOfStream) {
    $line = $reader.ReadLine()
    $lineCount++
    if ($line -match 'NAME NOT FOUND' -and $line -match $m00Escaped) {
        $allHits += $line
    }
}
$reader.Close()
$fs.Close()

Write-Host "Total CSV lines: $lineCount"
Write-Host "NAME NOT FOUND in m00: $($allHits.Count)"
Write-Host ""

# Group by process and show every wanted file
$byProcess = @{}
foreach ($hit in $allHits) {
    # CSV: "Time","Process Name","PID","Operation","Path","Result","Detail"
    if ($hit -match '"([^"]+)","(\d+)","([^"]+)","([^"]*m00[^"]*)"') {
        $procName = $Matches[1]
        $pid = $Matches[2]
        $op = $Matches[3]
        $wantedPath = $Matches[4]
        $wantedFile = [System.IO.Path]::GetFileName($wantedPath)

        $key = "$procName (PID $pid)"
        if (-not $byProcess.ContainsKey($key)) {
            $byProcess[$key] = [System.Collections.Generic.List[string]]::new()
        }
        $byProcess[$key].Add("$op -> $wantedFile")
    }
}

foreach ($proc in $byProcess.Keys | Sort-Object) {
    Write-Host "$proc"
    foreach ($entry in $byProcess[$proc]) {
        Write-Host "  $entry"
    }
    Write-Host ""
}

# Also show the raw lines for inspection
Write-Host "=== Raw CSV lines (first 50) ==="
$allHits | Select-Object -First 50 | ForEach-Object { Write-Host $_ }

# Cleanup
Remove-Item $pml -Force -ErrorAction SilentlyContinue
Remove-Item $csv -Force -ErrorAction SilentlyContinue
'''


def build_diagnostic_script() -> str:
    return DIAGNOSTIC_SCRIPT
