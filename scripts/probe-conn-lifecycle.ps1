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
    [string]$Base = (Join-Path $env:TEMP 'amon-probe\lifecycle')
)

$ErrorActionPreference = 'Stop'
if (Test-Path $Base) { Remove-Item -Recurse -Force $Base }
New-Item -ItemType Directory -Path $Base | Out-Null

$lan = (Get-NetIPAddress -AddressFamily IPv4 |
    Where-Object { $_.IPAddress -notlike '127.*' -and $_.IPAddress -notlike '100.*' -and $_.IPAddress -notlike '169.254.*' } |
    Sort-Object { if ($_.IPAddress -like '192.168.*') { 0 } else { 1 } } |
    Select-Object -First 1).IPAddress
if (-not $lan) { throw 'no non-loopback IPv4 address found' }
Write-Output "PROBE_EXE_SHA256=$((Get-FileHash $Exe -Algorithm SHA256).Hash)"
Write-Output "PROBE_LAN=$lan"

function New-Sock {
    param([string]$Family)
    $af = if ($Family -eq 'v6') { [System.Net.Sockets.AddressFamily]::InterNetworkV6 } else { [System.Net.Sockets.AddressFamily]::InterNetwork }
    return New-Object System.Net.Sockets.Socket($af, ([System.Net.Sockets.SocketType]::Stream), ([System.Net.Sockets.ProtocolType]::Tcp))
}

function Invoke-Conv {
    param([string]$Name, [string[]]$ExtraArgs, [int]$Port, [string]$Family, [System.Net.IPAddress]$Peer)
    $root = Join-Path $Base $Name
    New-Item -ItemType Directory -Path $root | Out-Null

    & $Exe --selftest --root $root | Out-Null
    & $Exe --baseline --root $root | Out-String | Write-Output

    $watch = Start-Process -FilePath $Exe -ArgumentList (@('--watch', '--root', $root, '--conn-sec', '1', '--poll', '1', '--quiet') + $ExtraArgs) -PassThru -WindowStyle Hidden
    Start-Sleep -Seconds 2

    $bind = if ($Family -eq 'v6') { [System.Net.IPAddress]::IPv6Loopback } else { [System.Net.IPAddress]::Any }
    $listener = New-Sock -Family $Family
    $listener.Bind((New-Object System.Net.IPEndPoint($bind, $Port)))
    $listener.Listen(8)
    Start-Sleep -Seconds 2

    $client = New-Sock -Family $Family
    $client.Connect((New-Object System.Net.IPEndPoint($Peer, $Port)))
    $accepted = $listener.Accept()
    $state = "$($client.Connected)/$($accepted.Connected)"
    Start-Sleep -Seconds 6
    $client.Close(); $accepted.Close(); $listener.Close()
    Start-Sleep -Seconds 5

    Stop-Process -Id $watch.Id -Force
    Write-Output "RUN=$Name connected=$state root=$root"
}

# A: default filters + LAN peer -> opened/closed on both sides; loopback must stay hidden
Invoke-Conv -Name 'default'  -ExtraArgs @()                  -Port 18481 -Family 'v4' -Peer ([System.Net.IPAddress]::Parse($lan))
# B: loopback explicitly included
Invoke-Conv -Name 'loopback' -ExtraArgs @('--conn-loopback') -Port 18482 -Family 'v4' -Peer ([System.Net.IPAddress]::Loopback)
# C: IPv6 ::1
Invoke-Conv -Name 'v6'       -ExtraArgs @('--conn-loopback') -Port 18483 -Family 'v6' -Peer ([System.Net.IPAddress]::IPv6Loopback)

Write-Output 'PROBE_DONE'
Write-Output "ASSERT: default run has conn_opened/conn_closed for $lan`:18481, no 127.0.0.1 event,"
Write-Output "        loopback run shows 127.0.0.1:18482, v6 run shows [::1]:18483 open+ESTABLISHED+close"
