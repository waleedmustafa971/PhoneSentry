# Builds dist\PhoneSentry.exe (single file, windowed, with icon, adb and threat database bundled).
#   powershell -ExecutionPolicy Bypass -File build.ps1            # build
#   powershell -ExecutionPolicy Bypass -File build.ps1 -UpdateIocs # refresh bundled indicators first
param([switch]$UpdateIocs)
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot
$py = ".\.venv\Scripts\python.exe"
New-Item -ItemType Directory -Force build-tmp | Out-Null

if (-not (Test-Path $py)) {
    $base = if (Test-Path C:\Python314\python.exe) { "C:\Python314\python.exe" } else { (Get-Command python).Source }
    & $base -m venv .venv
    & $py -m pip install --upgrade pip
    & $py -m pip install -r requirements.txt
}
if (-not (Test-Path vendor\platform-tools\adb.exe)) {
    Invoke-WebRequest -UseBasicParsing https://dl.google.com/android/repository/platform-tools-latest-windows.zip -OutFile build-tmp\pt.zip
    Expand-Archive -Force build-tmp\pt.zip vendor
}
if ($UpdateIocs -or -not (Get-ChildItem assets\iocs\*.stix2 -ErrorAction SilentlyContinue)) {
    $env:MVT_DATA_FOLDER = "$PSScriptRoot\build-tmp\mvtdata"
    & $py -c "from mvt.common.updates import IndicatorsUpdates; IndicatorsUpdates().update()"
    New-Item -ItemType Directory -Force assets\iocs | Out-Null
    Copy-Item build-tmp\mvtdata\indicators\*.stix2 assets\iocs\ -Force
}
& $py tools\make_logo.py

& $py -m PyInstaller --noconfirm --clean --onefile --windowed `
    --name PhoneSentry --icon assets\logo.ico `
    --version-file version_info.txt `
    --add-data "assets\logo.ico;assets" --add-data "assets\logo.png;assets" --add-data "assets\logo-96.png;assets" `
    --add-data "assets\iocs;assets\iocs" `
    --add-binary "vendor\platform-tools\adb.exe;vendor\platform-tools" `
    --add-binary "vendor\platform-tools\AdbWinApi.dll;vendor\platform-tools" `
    --add-binary "vendor\platform-tools\AdbWinUsbApi.dll;vendor\platform-tools" `
    --collect-all mvt --copy-metadata mvt --collect-all pymobiledevice3 `
    --collect-data customtkinter --hidden-import ahocorasick `
    --workpath build-tmp\pyi `
    run_phonesentry.py
if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed" }
Get-Item dist\PhoneSentry.exe | Select-Object Name, @{n="MB";e={[math]::Round($_.Length/1MB,1)}}
