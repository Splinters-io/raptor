r"""Classify executables by danger level for ExpLoading.

Three tiers:
  blocked  — will shutdown/reboot/kill/format the system
  caution  — may hang, prompt for input, or have side effects
  safe     — fine to launch with a timeout

Classification sources:
  1. Name blocklist (known dangerous binaries)
  2. PE import scan (shutdown/reboot/format APIs — NOT TerminateProcess, too noisy)
  3. Script content scan (.bat/.cmd/.vbs/.ps1/.wsf — grep for shutdown commands)
  4. PE subsystem (native subsystem = potential BSOD)

Also produces a checkpoint log for resume-after-crash.
"""

BLOCKED_NAMES = frozenset({
    "shutdown.exe", "logoff.exe", "slidetoshutdown.exe",
    "taskkill.exe", "tskill.exe", "kill.exe",
    "pskill.exe", "pskill64.exe",
    "format.com", "diskpart.exe", "cipher.exe",
    "bcdedit.exe", "bcdboot.exe", "bootsect.exe", "bootcfg.exe",
    "reset.exe", "resetengine.exe", "sysreseterr.exe", "systemreset.exe",
    "wpeutil.exe", "wpeinit.exe",
    "iisreset.exe", "ntdsutil.exe",
    "pssuspend.exe", "pssuspend64.exe",
    "frida-kill.exe", "gkill.exe",
    "passwordreset.bat",
    "restartagent.exe",
})

CAUTION_NAMES = frozenset({
    "mmc.exe", "mstsc.exe", "msconfig.exe",
    "explorer.exe", "taskmgr.exe",
    "regedit.exe", "regedt32.exe",
    "notepad.exe", "write.exe", "wordpad.exe",
    "calc.exe", "charmap.exe", "snippingtool.exe",
    "mspaint.exe", "magnify.exe", "narrator.exe",
    "osk.exe", "utilman.exe",
    "ping.exe", "tracert.exe", "nslookup.exe",
    "telnet.exe", "ftp.exe",
    "cmd.exe", "powershell.exe", "pwsh.exe",
    "wscript.exe", "cscript.exe",
    "bash.exe", "wsl.exe",
    "msiexec.exe", "setup.exe", "install.exe",
    "sc.exe", "net.exe", "net1.exe",
    "wsreset.exe",
})

LAUNCHABLE_EXTENSIONS = frozenset({
    ".exe", ".com", ".bat", ".cmd", ".vbs", ".vbe",
    ".js", ".jse", ".wsf", ".wsh", ".msc", ".ps1",
    ".cpl", ".scr",
})

SKIP_EXTENSIONS = frozenset({
    ".dll", ".ocx", ".ax", ".drv", ".tsp", ".sys",
})

# -------------------------------------------------------------------
# PE import scan: only truly dangerous APIs (not TerminateProcess)
# -------------------------------------------------------------------

CLASSIFY_PE_SCRIPT = r'''
param([string]$InventoryPath, [string]$OutputPath)

$ErrorActionPreference = 'SilentlyContinue'

$inventory = Get-Content $InventoryPath -Raw | ConvertFrom-Json
$exes = $inventory.executables | Where-Object {
    $_.extension -in @('.exe','.com','.scr','.cpl')
}

[Console]::Error.WriteLine("PE scan: $($exes.Count) binaries")

$results = [System.Collections.Generic.List[PSObject]]::new()

# Only APIs that actually shutdown/reboot/format — NOT TerminateProcess
$dangerousAPIs = @(
    'InitiateShutdown',
    'InitiateSystemShutdown',
    'InitiateSystemShutdownEx',
    'ExitWindowsEx',
    'NtShutdownSystem',
    'NtSetSystemPowerState',
    'FormatEx',
    'SetSuspendState'
)

$count = 0
foreach ($exe in $exes) {
    $count++
    if ($count % 1000 -eq 0) {
        [Console]::Error.WriteLine("  $count / $($exes.Count) ...")
    }

    $path = $exe.path
    if (-not (Test-Path $path)) { continue }

    try {
        $bytes = [System.IO.File]::ReadAllBytes($path)
        if ($bytes.Length -lt 64) { continue }
        if ($bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) { continue }

        $peOffset = [BitConverter]::ToInt32($bytes, 60)
        if ($peOffset -le 0 -or ($peOffset + 6) -ge $bytes.Length) { continue }
        if ($bytes[$peOffset] -ne 0x50 -or $bytes[$peOffset+1] -ne 0x45) { continue }

        $ohOffset = $peOffset + 24
        $magic = [BitConverter]::ToUInt16($bytes, $ohOffset)
        $is64 = ($magic -eq 0x20B)

        # Subsystem
        $subsystem = [BitConverter]::ToUInt16($bytes, $ohOffset + 68)

        # String scan for dangerous API names
        $text = [System.Text.Encoding]::ASCII.GetString($bytes)
        $found = @()
        foreach ($api in $dangerousAPIs) {
            if ($text.Contains($api)) {
                $found += $api
            }
        }

        if ($found.Count -gt 0 -or $subsystem -eq 1) {
            $results.Add([PSCustomObject]@{
                path = $path
                name = $exe.name
                imports = $found
                subsystem = $subsystem
                reason = if ($subsystem -eq 1) { "NATIVE_SUBSYSTEM" }
                         elseif ($found.Count -gt 0) { "DANGEROUS_API" }
                         else { "UNKNOWN" }
            })
        }
    } catch { continue }
}

[Console]::Error.WriteLine("PE flagged: $($results.Count)")

[PSCustomObject]@{
    total_scanned = $exes.Count
    flagged = $results.Count
    results = $results
} | ConvertTo-Json -Depth 4 -Compress | Out-File $OutputPath -Encoding UTF8
'''

# -------------------------------------------------------------------
# Script content scan: grep .bat/.cmd/.vbs/.ps1/.wsf for danger words
# -------------------------------------------------------------------

CLASSIFY_SCRIPTS_SCRIPT = r'''
param([string]$InventoryPath, [string]$OutputPath)

$ErrorActionPreference = 'SilentlyContinue'

$inventory = Get-Content $InventoryPath -Raw | ConvertFrom-Json
$scripts = $inventory.executables | Where-Object {
    $_.extension -in @('.bat','.cmd','.vbs','.vbe','.ps1','.wsf','.wsh','.js','.jse')
}

[Console]::Error.WriteLine("Script scan: $($scripts.Count) files")

$dangerPatterns = @(
    'shutdown\s',
    'shutdown\s*/[srfat]',
    'Restart-Computer',
    'Stop-Computer',
    'logoff',
    'ExitWindowsEx',
    'InitiateShutdown',
    'format\s+[a-zA-Z]:',
    'diskpart',
    'Remove-Partition',
    'Clear-Disk',
    'taskkill\s+/f',
    'Stop-Process\s+-Force',
    'bcdedit',
    'wpeutil\s+shutdown',
    'wpeutil\s+reboot',
    'Restart-Service\s+.*wuauserv',
    'net\s+stop',
    'sc\s+stop',
    'del\s+/[sfq].*\\Windows',
    'rmdir\s+/[sq].*\\Windows',
    'rd\s+/[sq].*\\Windows'
)
$regex = ($dangerPatterns -join '|')

$results = [System.Collections.Generic.List[PSObject]]::new()

$count = 0
foreach ($s in $scripts) {
    $count++
    if ($count % 500 -eq 0) {
        [Console]::Error.WriteLine("  $count / $($scripts.Count) ...")
    }

    $path = $s.path
    if (-not (Test-Path $path)) { continue }

    try {
        $size = (Get-Item $path).Length
        if ($size -gt 1MB) { continue }  # skip huge JS bundles

        $content = Get-Content $path -Raw -ErrorAction SilentlyContinue
        if (-not $content) { continue }

        $matches = [regex]::Matches($content, $regex, 'IgnoreCase')
        if ($matches.Count -gt 0) {
            $found = ($matches | ForEach-Object { $_.Value.Trim() } | Select-Object -Unique)
            $results.Add([PSCustomObject]@{
                path = $path
                name = $s.name
                extension = $s.extension
                matches = $found
                match_count = $matches.Count
            })
        }
    } catch { continue }
}

[Console]::Error.WriteLine("Script flagged: $($results.Count)")

[PSCustomObject]@{
    total_scanned = $count
    flagged = $results.Count
    results = $results
} | ConvertTo-Json -Depth 4 -Compress | Out-File $OutputPath -Encoding UTF8
'''


def build_classify_pe_script() -> str:
    return CLASSIFY_PE_SCRIPT


def build_classify_scripts_script() -> str:
    return CLASSIFY_SCRIPTS_SCRIPT
