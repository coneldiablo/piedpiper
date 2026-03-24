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

$apiCommand = "cd `"$projectRoot`"; `$env:TI_API_HOST=`"$($env:TI_API_HOST)`"; `$env:TI_API_PORT=`"$($env:TI_API_PORT)`"; & `".\.venv\Scripts\python.exe`" -m api.server"
Start-Process powershell -ArgumentList "-NoExit", "-Command", $apiCommand | Out-Null

Start-Sleep -Seconds 2
Write-Host "API launching in separate window: http://$($env:TI_API_HOST):$($env:TI_API_PORT)/api/docs"
Write-Host "Starting Pied Piper GUI"
& ".\.venv\Scripts\python.exe" main.py gui
