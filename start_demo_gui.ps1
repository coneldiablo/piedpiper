$ErrorActionPreference = "Stop"

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

if (-not (Test-Path ".\.venv\Scripts\python.exe")) {
    throw "Python virtual environment not found at .\.venv\Scripts\python.exe"
}

Write-Host "Starting Pied Piper GUI"
& ".\.venv\Scripts\python.exe" main.py gui
