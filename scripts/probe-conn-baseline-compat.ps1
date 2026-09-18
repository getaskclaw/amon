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
    [string]$Root = (Join-Path $env:TEMP 'amon-probe\compat'),
    [string]$BaselineWithoutConn = ''    # path to a pre-`conn` baseline.json, optional
)

# A baseline.json written by a build without the `conn` section must still load
# (serde default). Signature of a successful load: the first poll reports the current
# conversations once. If the file failed to load, the tool silently re-captures instead and
# no burst appears.
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Root | Out-Null

if ($BaselineWithoutConn -and (Test-Path $BaselineWithoutConn)) {
    Copy-Item $BaselineWithoutConn (Join-Path $Root 'baseline.json') -Force
} else {
    & $Exe --baseline --root $Root | Out-String | Write-Output
    Write-Output 'NOTE: no pre-change baseline supplied; generating a current-format one.'
    Write-Output '      To test the real upgrade path, strip the "conn" key from a baseline.json'
    Write-Output '      produced by a previous build and pass it via -BaselineWithoutConn.'
}

$p = Start-Process -FilePath $Exe -ArgumentList @('--watch', '--root', $Root, '--conn-sec', '1', '--poll', '1', '--quiet') -PassThru -WindowStyle Hidden
Start-Sleep -Seconds 6
Stop-Process -Id $p.Id -Force -ErrorAction SilentlyContinue

Write-Output 'PROBE_DONE'
Write-Output "ASSERT: with a pre-change baseline, the first poll emits one conn_opened per existing"
Write-Output "        conversation; a reload of the same root afterwards emits none."
