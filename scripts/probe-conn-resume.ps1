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
    [string]$Root = (Join-Path $env:TEMP 'amon-probe\resume'),
    [int]$Port = 18527,
    [int]$SessionSec = 16,
    [int]$Count = 3
)

# Sockets are held open ACROSS two watch sessions on one root. Session 2 must seed from
# conn-state.json and re-report none of them. A pre-change baseline (no `conn` section)
# should be overwritten into the root first to exercise the upgrade path.
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Root | Out-Null

$lan = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '100.*' -and $_.IPAddress -notlike '169.254.*' } |
    Sort-Object { if ($_.IPAddress -like '192.168.*') { 0 } else { 1 } } |
    Select-Object -First 1).IPAddress

$listener = New-Object System.Net.Sockets.Socket(([System.Net.Sockets.AddressFamily]::InterNetwork), ([System.Net.Sockets.SocketType]::Stream), ([System.Net.Sockets.ProtocolType]::Tcp))
$listener.Bind((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, $Port)))
$listener.Listen(16)
$clients = @(); $accepted = @()
for ($i = 0; $i -lt $Count; $i++) {
    $c = New-Object System.Net.Sockets.Socket(([System.Net.Sockets.AddressFamily]::InterNetwork), ([System.Net.Sockets.SocketType]::Stream), ([System.Net.Sockets.ProtocolType]::Tcp))
    $c.Connect((New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Parse($lan), $Port)))
    $clients += $c; $accepted += $listener.Accept()
}
Write-Output "HOLD_OPEN=$Count peers=$lan`:$Port"

function Invoke-Watch {
    param([string]$Tag)
    $p = Start-Process -FilePath $Exe -ArgumentList @('--watch', '--root', $Root, '--conn-sec', '1', '--poll', '30', '--quiet') -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds $SessionSec
    Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue
    Write-Output "SESSION_END=$Tag"
}

& $Exe --baseline --root $Root | Out-String | Write-Output
Invoke-Watch 'run1'
Move-Item (Join-Path $Root 'events.jsonl') (Join-Path $Root 'events-run1.jsonl') -Force
Copy-Item (Join-Path $Root 'conn-state.json') (Join-Path $Root 'sidecar-before-run2.json') -Force
Invoke-Watch 'run2'
$clients | ForEach-Object { $_.Close() }; $accepted | ForEach-Object { $_.Close() }; $listener.Close()

Write-Output 'PROBE_DONE'
Write-Output "ASSERT: run2 events.jsonl has 0 conn_opened whose (pid|peer) key appears in"
Write-Output "        sidecar-before-run2.json, and one meta/conn_state_resumed with source=sidecar"
