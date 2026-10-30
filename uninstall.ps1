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
try { & $schtasks /Delete /TN "cdn_accelerator_watch" /F | Out-Null; Write-Host "Watchdog task removed" } catch { Write-Host "No watchdog task found" }

# 2b. stop the watchdog process too
$wprocs = Get-CimInstance Win32_Process -Filter "Name like 'python%'" -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -match 'watch\.py' }
foreach ($p in $wprocs) {
    try { Stop-Process -Id $p.ProcessId -Force -ErrorAction Stop; Write-Host "Stopped watchdog PID $($p.ProcessId)" } catch { }
}

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
                } catch {
                    # restore via DHCP as fallback - never leave a stale ::1 behind
                    try { & $netsh interface ipv6 delete dns "$alias" all | Out-Null } catch { }
                    Write-Host "WARN: could not restore IPv6 interface $idx, reset to DHCP : $_"
                }
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

# 4. sweep any stale ::1 left on non-loopback adapters (belt & braces:
#    virtual NICs from older installs may hold a dead ::1)
$stale = Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
    Where-Object { $_.ServerAddresses -contains '::1' -and $_.InterfaceAlias -notmatch 'Loopback' }
foreach ($a in $stale) {
    try {
        & $netsh interface ipv6 delete dns "$($a.InterfaceAlias)" all | Out-Null
        Write-Host "Swept stale IPv6 DNS on $($a.InterfaceAlias)"
    } catch { Write-Host "WARN: could not sweep $($a.InterfaceAlias) : $_" }
}

# 4b. remove the LAN-mode firewall rule if present
try {
    & "$env:SystemRoot\System32\netsh.exe" advfirewall firewall delete rule name="cdn-accelerator-dns" | Out-Null
    Write-Host "Firewall rule 'cdn-accelerator-dns' removed"
} catch { }

# 5. flush
& "$env:SystemRoot\System32\ipconfig.exe" /flushdns | Out-Null
Write-Host "Done. DNS flushed."
