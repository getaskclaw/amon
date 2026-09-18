<#
amon verification probe — run on real Windows, no internet dependency.

The "remote" peer for the IPv4 case is this machine's own LAN address, so the probe works
behind any proxy and on an offline box.

  -Exe   path to amon.exe (default: .\amon.exe next to the current directory)
  -Root  state directory for this probe (default: %TEMP%\amon-probe\<name>)

These scripts only create their own listeners/clients and run amon against a scratch state
directory. amon itself never writes outside --root.
#>
param(
    [string]$Exe  = '.\amon.exe',
    [string]$Root = (Join-Path $env:TEMP 'amon-probe\cadence'),
    [int]$ConnSec = 2,
    [int]$PollSec = 30,
    [int]$Port = 18491
)

# --conn-sec must be an independent cadence. With --poll 30 the whole run is shorter than
# one poll interval, so if the connection poll were nested inside the poll tick, NO event
# would be emitted at all. Event timestamps are printed for a manual check.
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Root | Out-Null

$lan = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '100.*' -and $_.IPAddress -notlike '169.254.*' } |
    Sort-Object { if ($_.IPAddress -like '192.168.*') { 0 } else { 1 } } |
    Select-Object -First 1).IPAddress

$t0 = Get-Date
$watch = Start-Process -FilePath $Exe -ArgumentList @('--watch', '--root', $Root, '--conn-sec', "$ConnSec", '--poll', "$PollSec", '--quiet') -PassThru -WindowStyle Hidden
Write-Output "RUN_START=$($t0.ToString('HH:mm:ss.fff')) conn=$ConnSec poll=$PollSec"

try {
    Start-Sleep -Seconds 4
    $listener = New-Object System.Net.Sockets.Socket(([System.Net.Sockets.AddressFamily]::InterNetwork), ([System.Net.Sockets.SocketType]::Stream), ([System.Net.Sockets.ProtocolType]::Tcp))
    $listener.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, $Port)))
    $listener.Listen(8)
    $client = New-Object System.Net.Sockets.Socket(([System.Net.Sockets.AddressFamily]::InterNetwork), ([System.Net.Sockets.SocketType]::Stream), ([System.Net.Sockets.ProtocolType]::Tcp))
    $client.Connect((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($lan), $Port)))
    $accepted = $listener.Accept()
    Write-Output "RUN_CONNECT=$((Get-Date).ToString('HH:mm:ss.fff'))"
    Start-Sleep -Seconds 6
    $client.Close(); $accepted.Close(); $listener.Close()
    Start-Sleep -Seconds 4
} finally {
    Stop-Process -Id $watch.Id -Force -ErrorAction SilentlyContinue
}

Write-Output 'PROBE_DONE'
Write-Output "ASSERT: events.jsonl contains conn_opened/conn_closed for $lan`:$Port with timestamps"
Write-Output "        ~$ConnSec s after RUN_CONNECT — not at the $PollSec s poll tick"
Get-Content (Join-Path $Root 'events.jsonl') | Select-String "$Port"
