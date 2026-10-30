# cdn-accelerator periodic keeper (runs from Task Scheduler every 5 min)
# Independent of any app process tree: if the optimizer or watchdog died
# (crash, kill, app-exit cleanup), relaunch them.
$ErrorActionPreference = "SilentlyContinue"
$dir = "D:\Program Files\cdn-accelerator"
$pyw = Join-Path $dir "runtime\python312\pythonw.exe"
$main = Join-Path $dir "cdn-accelerator.py"
$watch = Join-Path $dir "watch.py"
$upstreams = "192.168.1.1,223.5.5.5,119.29.29.29"
$lan = "--lan"
# is anything answering on UDP 53?
$ep = Get-NetUDPEndpoint -LocalPort 53 -ErrorAction SilentlyContinue
if (-not $ep) {
    Start-Process -FilePath $pyw -ArgumentList @('-u', "`"$main`"", '--upstream', $upstreams, $lan) -WindowStyle Hidden
}
# is the watchdog running?
$w = Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -match 'watch\.py' }
if (-not $w) {
    Start-Process -FilePath $pyw -ArgumentList @("`"$watch`"", '--upstream', $upstreams, $lan) -WindowStyle Hidden
}