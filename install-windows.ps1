[CmdletBinding()]
param(
    [switch]$AllExtras,
    [switch]$SkipNmap
)

$ErrorActionPreference = "Stop"
$RootDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$VenvDir = if ($env:NETMAPPER_VENV_DIR) { $env:NETMAPPER_VENV_DIR } else { Join-Path $RootDir ".venv-windows" }

$pythonCommand = Get-Command py -ErrorAction SilentlyContinue
if ($pythonCommand) {
    $pythonExecutable = $pythonCommand.Source
    $pythonPrefix = @("-3")
} else {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if (-not $pythonCommand) {
        throw "Python 3 não foi encontrado. Instale-o com: winget install Python.Python.3.12"
    }
    $pythonExecutable = $pythonCommand.Source
    $pythonPrefix = @()
}

& $pythonExecutable @pythonPrefix -m venv $VenvDir
if ($LASTEXITCODE -ne 0) {
    throw "Não foi possível criar o ambiente virtual em $VenvDir."
}

$venvPython = Join-Path $VenvDir "Scripts\python.exe"
$venvNetscan = Join-Path $VenvDir "Scripts\Netscan.exe"
$venvDashboard = Join-Path $VenvDir "Scripts\netmapper-dashboard.exe"
& $venvPython -m pip install --upgrade pip
if ($LASTEXITCODE -ne 0) {
    throw "Não foi possível atualizar o pip."
}

$packageSpec = if ($AllExtras) { "$RootDir[all]" } else { $RootDir }
& $venvPython -m pip install $packageSpec
if ($LASTEXITCODE -ne 0) {
    throw "Não foi possível instalar o NetMapper."
}

if (-not $SkipNmap -and -not (Get-Command nmap -ErrorAction SilentlyContinue)) {
    $winget = Get-Command winget -ErrorAction SilentlyContinue
    if ($winget) {
        & $winget.Source install --id Insecure.Nmap --exact --accept-package-agreements --accept-source-agreements
    } else {
        Write-Warning "WinGet não foi encontrado; instale o Nmap em https://nmap.org/download.html"
    }
}

$nmapCandidates = @()
$existingNmap = Get-Command nmap -ErrorAction SilentlyContinue
if ($existingNmap) {
    $nmapCandidates += $existingNmap.Source
}
$nmapCandidates += "C:\Program Files\Nmap\nmap.exe"
$nmapCandidates += "C:\Program Files (x86)\Nmap\nmap.exe"
$nmapCandidates = $nmapCandidates | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -Unique

if ($nmapCandidates.Count -gt 0) {
    $nmapDir = Split-Path -Parent $nmapCandidates[0]
    $env:Path = "$nmapDir;$env:Path"
    & $nmapCandidates[0] --version | Select-Object -First 1
} else {
    Write-Warning "Nmap não foi localizado. O CLI passivo funciona, mas scans externos exigem Nmap."
}

if (-not (Get-Service -Name npcap -ErrorAction SilentlyContinue)) {
    Write-Warning "Npcap não foi detectado. Instale o Nmap novamente ou o Npcap para ARP local."
}

& $venvNetscan --help | Select-Object -First 3
Write-Host ""
Write-Host "NetMapper instalado para Windows."
Write-Host "Use: $venvNetscan"
Write-Host "Para o dashboard: $venvDashboard"
