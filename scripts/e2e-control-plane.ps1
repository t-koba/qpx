Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent $PSScriptRoot
$QpxdBin = if ($env:QPXD_BIN) { $env:QPXD_BIN } else { Join-Path $RootDir "target\debug\qpxd.exe" }
$TmpDir = Join-Path ([System.IO.Path]::GetTempPath()) ("qpx-control-plane." + [System.Guid]::NewGuid().ToString("N"))
$ConfigFile = Join-Path $TmpDir "control-plane.yaml"
$LogFile = Join-Path $TmpDir "qpxd.stdout.log"
$ErrFile = Join-Path $TmpDir "qpxd.stderr.log"
$StateDir = Join-Path $TmpDir "state"
$Port = if ($env:QPX_CONTROL_PLANE_PORT) { [int]$env:QPX_CONTROL_PLANE_PORT } else { 0 }
$RestartPort = if ($env:QPX_CONTROL_PLANE_RESTART_PORT) { [int]$env:QPX_CONTROL_PLANE_RESTART_PORT } else { 0 }
$TrackedPids = [System.Collections.Generic.List[int]]::new()

function Register-Pid {
    param([int]$Pid)
    if ($Pid -gt 0 -and -not $TrackedPids.Contains($Pid)) {
        $TrackedPids.Add($Pid)
    }
}

function Get-QpxdProcessIdsForConfig {
    $needle = $ConfigFile.Replace('\', '\\')
    $processes = Get-CimInstance Win32_Process -Filter "Name = 'qpxd.exe'" |
        Where-Object { $_.CommandLine -and $_.CommandLine -like "*$needle*" }
    @($processes | ForEach-Object { [int]$_.ProcessId })
}

function Stop-PidIfRunning {
    param([int]$Pid)
    try {
        $process = Get-Process -Id $Pid -ErrorAction Stop
        Stop-Process -Id $process.Id -Force -ErrorAction Stop
        $null = $process.WaitForExit(5000)
    } catch {
    }
}

function Cleanup {
    foreach ($pid in $TrackedPids) {
        Stop-PidIfRunning -Pid $pid
    }
    foreach ($pid in Get-QpxdProcessIdsForConfig) {
        Stop-PidIfRunning -Pid $pid
    }
    if (Test-Path $TmpDir) {
        Remove-Item -LiteralPath $TmpDir -Recurse -Force -ErrorAction SilentlyContinue
    }
}

trap {
    Cleanup
    throw
}

function Require-Path {
    param([string]$Path)
    if (-not (Test-Path $Path)) {
        throw "missing required path: $Path"
    }
}

function Get-FreeTcpPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    $listener.Start()
    try {
        $endpoint = [System.Net.IPEndPoint]$listener.LocalEndpoint
        return $endpoint.Port
    } finally {
        $listener.Stop()
    }
}

function Test-PortOpen {
    param([int]$Port)
    $client = [System.Net.Sockets.TcpClient]::new()
    try {
        $iar = $client.BeginConnect("127.0.0.1", $Port, $null, $null)
        if (-not $iar.AsyncWaitHandle.WaitOne(200)) {
            return $false
        }
        $client.EndConnect($iar)
        return $true
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Wait-Port {
    param([int]$Port, [int]$Pid)
    for ($i = 0; $i -lt 100; $i++) {
        if (Test-PortOpen -Port $Port) {
            return
        }
        if (-not (Get-Process -Id $Pid -ErrorAction SilentlyContinue)) {
            $stdout = if (Test-Path $LogFile) { Get-Content -Raw $LogFile } else { "" }
            $stderr = if (Test-Path $ErrFile) { Get-Content -Raw $ErrFile } else { "" }
            throw "qpxd exited before opening port $Port`nSTDOUT:`n$stdout`nSTDERR:`n$stderr"
        }
        Start-Sleep -Milliseconds 100
    }
    $stdout = if (Test-Path $LogFile) { Get-Content -Raw $LogFile } else { "" }
    $stderr = if (Test-Path $ErrFile) { Get-Content -Raw $ErrFile } else { "" }
    throw "timeout waiting for port $Port`nSTDOUT:`n$stdout`nSTDERR:`n$stderr"
}

function Wait-LogContains {
    param([string]$Needle)
    for ($i = 0; $i -lt 120; $i++) {
        if (Test-Path $LogFile) {
            $content = Get-Content -Raw $LogFile
            if ($content.Contains($Needle)) {
                return
            }
        }
        if (Test-Path $ErrFile) {
            $content = Get-Content -Raw $ErrFile
            if ($content.Contains($Needle)) {
                return
            }
        }
        Start-Sleep -Milliseconds 100
    }
    $stdout = if (Test-Path $LogFile) { Get-Content -Raw $LogFile } else { "" }
    $stderr = if (Test-Path $ErrFile) { Get-Content -Raw $ErrFile } else { "" }
    throw "missing expected log line: $Needle`nSTDOUT:`n$stdout`nSTDERR:`n$stderr"
}

function Invoke-HealthRequest {
    $response = Invoke-WebRequest -Uri ("http://127.0.0.1:{0}/health" -f $Port) -Headers @{ Host = "control.local" } -TimeoutSec 3
    return [string]$response.Content
}

function Wait-Body {
    param([string]$Expected)
    $body = ""
    for ($i = 0; $i -lt 120; $i++) {
        try {
            $body = Invoke-HealthRequest
            if ($body -eq $Expected) {
                return
            }
        } catch {
        }
        Start-Sleep -Milliseconds 100
    }
    $stdout = if (Test-Path $LogFile) { Get-Content -Raw $LogFile } else { "" }
    $stderr = if (Test-Path $ErrFile) { Get-Content -Raw $ErrFile } else { "" }
    throw "unexpected response body (expected=$Expected actual=$body)`nSTDOUT:`n$stdout`nSTDERR:`n$stderr"
}

function Quote-YamlPath {
    param([string]$Path)
    "'" + ($Path -replace "'", "''") + "'"
}

function Install-Config {
    param(
        [string]$Body,
        [int]$Acceptors
    )
    $tcpBacklog = if ($Acceptors -gt 1) { 4097 } else { 4096 }
    $content = @"
state_dir: $(Quote-YamlPath $StateDir)
runtime:
  acceptor_tasks_per_listener: $Acceptors
  reuse_port: false
  tcp_backlog: $tcpBacklog
reverse:
- name: control
  listen: 127.0.0.1:$Port
  routes:
  - name: health
    match:
      host:
      - control.local
      path:
      - /health
    local_response:
      status: 200
      body: $Body
"@
    if ($Acceptors -gt 1) {
        $content += @"
- name: control-extra
  listen: 127.0.0.1:$RestartPort
  routes:
  - name: health
    match:
      host:
      - control.local
      path:
      - /health
    local_response:
      status: 200
      body: $Body
"@
    }
    Set-Content -LiteralPath $ConfigFile -Value $content -NoNewline
}

New-Item -ItemType Directory -Path $TmpDir, $StateDir | Out-Null
Require-Path -Path $QpxdBin

if ($Port -eq 0) {
    $Port = Get-FreeTcpPort
}
if ($RestartPort -eq 0) {
    $RestartPort = Get-FreeTcpPort
}

Install-Config -Body "OLD" -Acceptors 1

Write-Host "[CONTROL] start qpxd (windows)"
$parent = Start-Process -FilePath $QpxdBin `
    -ArgumentList @("run", "--config", $ConfigFile) `
    -RedirectStandardOutput $LogFile `
    -RedirectStandardError $ErrFile `
    -PassThru
Register-Pid -Pid $parent.Id
Wait-Port -Port $Port -Pid $parent.Id
Wait-Body -Expected "OLD"

Write-Host "[CONTROL] hot reload in place (windows)"
Install-Config -Body "RELOADED" -Acceptors 1
Wait-LogContains -Needle "config reloaded"
Wait-Body -Expected "RELOADED"

Write-Host "[CONTROL] hot reload with listener/reverse restart (windows)"
Install-Config -Body "RESTARTED" -Acceptors 2
Wait-LogContains -Needle "config reloaded; listener/reverse server set restarted"
Wait-Body -Expected "RESTARTED"

Write-Host "[CONTROL] binary upgrade (windows)"
& $QpxdBin upgrade --pid $parent.Id

$childPid = $null
for ($i = 0; $i -lt 120; $i++) {
    $candidate = Get-QpxdProcessIdsForConfig | Where-Object { $_ -ne $parent.Id } | Select-Object -First 1
    if ($candidate) {
        $childPid = [int]$candidate
        break
    }
    Start-Sleep -Milliseconds 100
}
if (-not $childPid) {
    $stdout = if (Test-Path $LogFile) { Get-Content -Raw $LogFile } else { "" }
    $stderr = if (Test-Path $ErrFile) { Get-Content -Raw $ErrFile } else { "" }
    throw "failed to locate upgraded child process`nSTDOUT:`n$stdout`nSTDERR:`n$stderr"
}
Register-Pid -Pid $childPid

for ($i = 0; $i -lt 120; $i++) {
    if (-not (Get-Process -Id $parent.Id -ErrorAction SilentlyContinue)) {
        break
    }
    Start-Sleep -Milliseconds 100
}
if (Get-Process -Id $parent.Id -ErrorAction SilentlyContinue) {
    $stdout = if (Test-Path $LogFile) { Get-Content -Raw $LogFile } else { "" }
    $stderr = if (Test-Path $ErrFile) { Get-Content -Raw $ErrFile } else { "" }
    throw "parent did not exit after binary upgrade`nSTDOUT:`n$stdout`nSTDERR:`n$stderr"
}

Wait-Body -Expected "RESTARTED"
Write-Host "[CONTROL] hot reload and binary upgrade e2e passed (windows)"

Cleanup
