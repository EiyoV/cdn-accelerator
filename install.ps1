# CDN Accelerator - installer
# Backs up current DNS, points system DNS to the local optimizer,
# registers an on-logon scheduled task so it runs automatically.
$ErrorActionPreference = 'Stop'
$dir = Split-Path -Parent $MyInvocation.MyCommand.Path

# --- locate a usable Python (auto-detect; works on any machine) ---
$pyExe = $null
$candidates = @(
    (Join-Path $dir 'runtime\python312\python.exe'),  # bundled python (has system CA)
    (Join-Path $dir 'python\python.exe'),             # portable python next to this script
    (Join-Path $dir 'python.exe'),
    'pythonw.exe', 'python.exe',                 # on PATH
    "$env:LOCALAPPDATA\Programs\Python\Python*\python.exe",
    "$env:ProgramFiles\Python*\python.exe",
    "C:\Python*\python.exe"
)
foreach ($c in $candidates) {
    $m = Get-Item $c -ErrorAction SilentlyContinue | Where-Object { -not $_.PSIsContainer }
    if ($m) { $pyExe = $m.FullName; break }
}
if (-not $pyExe) {
    $g = Get-Command python.exe -ErrorAction SilentlyContinue
    if ($g -and $g.Source) { $pyExe = $g.Source }
}
if (-not $pyExe) {
    throw "Python not found. Install Python 3.10+ from https://www.python.org/downloads/ (tick 'Add python.exe to PATH'), or place a portable python folder named 'python' next to this script, then rerun."
}
$pywExe = $pyExe -replace 'python\.exe$', 'pythonw.exe'
if (-not (Test-Path -LiteralPath $pywExe)) { $pywExe = $pyExe }
Write-Host "Using Python: $pyExe"

$script = Join-Path $dir 'cdn-accelerator.py'
$backup = Join-Path $dir 'dns-backup.txt'
$schtasks = "$env:SystemRoot\System32\schtasks.exe"

# 2. backup current IPv4 + IPv6 DNS per adapter
$adapters = Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.ServerAddresses.Count -gt 0 -and $_.ServerAddresses -notcontains '127.0.0.1' }
$adapters6 = Get-DnsClientServerAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue |
    Where-Object { $_.ServerAddresses.Count -gt 0 -and $_.ServerAddresses -notcontains '::1' }
if ($adapters.Count -eq 0 -and $adapters6.Count -eq 0) { Write-Host "No upstream DNS found to change; nothing to do."; exit 0 }
if ($adapters.Count -gt 0) {
    $lines = @()
    foreach ($a in $adapters) { $lines += "$($a.InterfaceIndex)`t$($a.ServerAddresses -join ',')" }
    [System.IO.File]::WriteAllLines($backup, $lines)
    Write-Host "DNS backed up to: $backup"
}
$backup6 = Join-Path $dir 'dns-backup-v6.txt'
if ($adapters6.Count -gt 0) {
    $lines6 = @()
    foreach ($a in $adapters6) { $lines6 += "$($a.InterfaceIndex)`t$($a.ServerAddresses -join ',')" }
    [System.IO.File]::WriteAllLines($backup6, $lines6)
    Write-Host "IPv6 DNS backed up to: $backup6"
}

# 3. point system DNS (v4 + v6) to local optimizer
foreach ($a in $adapters) {
    Set-DnsClientServerAddress -InterfaceIndex $a.InterfaceIndex -ServerAddresses @('127.0.0.1') -ErrorAction Stop
}
foreach ($a in $adapters6) {
    # Set-DnsClientServerAddress has no -AddressFamily here; use netsh for IPv6
    & "$env:SystemRoot\System32\netsh.exe" interface ipv6 set dns "$($a.InterfaceAlias)" static ::1 | Out-Null
}
Write-Host "System DNS -> 127.0.0.1 / ::1"

# 4. on-logon scheduled task
$upstreams = ($adapters | ForEach-Object { $_.ServerAddresses } | Where-Object { $_ -ne '127.0.0.1' } | Select-Object -Unique | Select-Object -First 2) -join ','
if (-not $upstreams) { $upstreams = '223.5.5.5' }
& $schtasks /Create /TN "cdn_accelerator" /TR "`"$pywExe`" -u `"$script`" --upstream $upstreams" /SC ONLOGON /F | Out-Null
Write-Host "Scheduled task created (on logon), upstream=$upstreams"

# 5. start it right now
$argList = @('-u', "`"$script`"", '--upstream', $upstreams)
Start-Process -FilePath $pywExe -ArgumentList $argList -WindowStyle Hidden
Start-Sleep -Seconds 4

# 6. verify
$endpoint = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue
if ($endpoint) { Write-Host "OK: listening on UDP 53" } else { Write-Host "WARN: nothing listening on UDP 53 - check log" }
