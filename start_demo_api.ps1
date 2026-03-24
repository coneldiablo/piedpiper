$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    throw "Python virtual environment not found at .\.venv\Scripts\python.exe"
}

if (-not $env:TI_API_HOST) {
    $env:TI_API_HOST = "127.0.0.1"
}

if (-not $env:TI_API_PORT) {
    $env:TI_API_PORT = "8080"
}

Write-Host "Starting Pied Piper API on http://$($env:TI_API_HOST):$($env:TI_API_PORT)/api/docs"
& ".\.venv\Scripts\python.exe" -m api.server
