# CDN Accelerator - uninstaller / emergency restore
# Stops the process, removes the scheduled task, restores the original DNS.
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path
$backup = Join-Path $dir 'dns-backup.txt'
$schtasks = "$env:SystemRoot\System32\schtasks.exe"

# 1. stop running instance (match cdn-accelerator.py command line)
$procs = Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'cdn-accelerator\.py' }
foreach ($p in $procs) {
    try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; Write-Host "Stopped PID $($p.ProcessId)" } catch { }
}

# 2. remove scheduled task
try { & $schtasks /Delete /TN "cdn_accelerator" /F | Out-Null; Write-Host "Scheduled task removed" } catch { Write-Host "No scheduled task found" }

# 3. restore original DNS
if (Test-Path -LiteralPath $backup) {
    $lines = [System.IO.File]::ReadAllLines($backup)
    foreach ($ln in $lines) {
        if (-not $ln) { continue }
        $parts = $ln.Split("`t")
        if ($parts.Count -ge 2) {
            $idx = [int]$parts[0]
            $servers = $parts[1].Split(',') | Where-Object { $_ }
            if ($servers.Count -gt 0) {
                try {
                    Set-DnsClientServerAddress -InterfaceIndex $idx -ServerAddresses $servers -ErrorAction Stop
                    Write-Host "Restored DNS on interface $idx : $($servers -join ',')"
                } catch { Write-Host "WARN: could not restore interface $idx : $_" }
            }
        }
    }
} else {
    Write-Host "WARN: no dns-backup.txt found - restore DNS manually (e.g. netsh or router 192.168.1.1)"
}

# restore IPv6 DNS if we have a backup, else reset to DHCP
$backup6 = Join-Path $dir 'dns-backup-v6.txt'
$netsh = "$env:SystemRoot\System32\netsh.exe"
if (Test-Path -LiteralPath $backup6) {
    $lines6 = [System.IO.File]::ReadAllLines($backup6)
    foreach ($ln in $lines6) {
        if (-not $ln) { continue }
        $parts = $ln.Split("`t")
        if ($parts.Count -ge 2) {
            $idx = [int]$parts[0]
            $servers = $parts[1].Split(',') | Where-Object { $_ }
            $ad = Get-NetAdapter -InterfaceIndex $idx -ErrorAction SilentlyContinue
            $alias = if ($ad) { $ad.Name } else { $idx }
            if ($servers.Count -gt 0) {
                try {
                    & $netsh interface ipv6 set dns "$alias" static $servers[0] | Out-Null
                    Write-Host "Restored IPv6 DNS on interface $idx : $($servers[0])"
                } catch { Write-Host "WARN: could not restore IPv6 interface $idx : $_" }
            }
        }
    }
} else {
    try {
        $ad6 = Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | Where-Object { $_.ServerAddresses -contains '::1' }
        foreach ($a in $ad6) {
            $ad = Get-NetAdapter -InterfaceIndex $a.InterfaceIndex -ErrorAction SilentlyContinue
            $alias = if ($ad) { $ad.Name } else { $a.InterfaceIndex }
            & $netsh interface ipv6 delete dns "$alias" all | Out-Null
            Write-Host "Reset IPv6 DNS on interface $($a.InterfaceIndex) to DHCP"
        }
    } catch { Write-Host "WARN: could not reset IPv6 DNS : $_" }
}

# 4. flush
& "$env:SystemRoot\System32\ipconfig.exe" /flushdns | Out-Null
Write-Host "Done. DNS flushed."
