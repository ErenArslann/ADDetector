#Requires -Version 5.1
<#
.SYNOPSIS
    ADDetector build script - produces portable ADDetector.exe via ps2exe.
.DESCRIPTION
    Run from project root:
        .\Build.ps1
    Output: .\dist\ADDetector\  (portable folder + zip)
#>

param(
    [string]$OutDir,
    [string]$Version = '1.0.0'
)

$ErrorActionPreference = 'Stop'

function Write-Step { param([string]$Msg) Write-Host ("==> " + $Msg) -ForegroundColor Cyan }
function Write-OK   { param([string]$Msg) Write-Host ("OK   " + $Msg) -ForegroundColor Green }
function Write-Warn2{ param([string]$Msg) Write-Host ("WARN " + $Msg) -ForegroundColor Yellow }
function Write-Err2 { param([string]$Msg) Write-Host ("ERR  " + $Msg) -ForegroundColor Red }

# ---------- 1) Resolve paths ----------
$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }
if (-not $OutDir) { $OutDir = Join-Path $root 'dist\ADDetector' }

Write-Step "ADDetector build v$Version"
Write-Host "    root  : $root"
Write-Host "    out   : $OutDir"

# ---------- 2) Validate required source files ----------
$required = @(
    'Launcher.ps1',
    'MainForm.ps1',
    'DomainDiscovery.ps1',
    'modules\DetectionConfig.ps1',
    'config\detection-groups.json'
)
$missing = @()
foreach ($f in $required) {
    if (-not (Test-Path (Join-Path $root $f))) { $missing += $f }
}
if ($missing.Count -gt 0) {
    Write-Err2 "Missing source files:"
    $missing | ForEach-Object { Write-Host "       - $_" }
    exit 1
}
Write-OK "Source files present."

# ---------- 3) ps2exe (HARD requirement) ----------
Write-Step "Checking ps2exe..."
if (-not (Get-Module -ListAvailable -Name ps2exe)) {
    Write-Warn2 "ps2exe not installed - attempting Install-Module ps2exe -Scope CurrentUser..."
    try {
        Install-Module ps2exe -Scope CurrentUser -Force -AllowClobber -ErrorAction Stop
        Write-OK "ps2exe installed."
    } catch {
        Write-Err2 "ps2exe install failed: $_"
        Write-Host ""
        Write-Host "Resolve manually:"
        Write-Host "  Install-Module ps2exe -Scope CurrentUser -Force"
        Write-Host "Or download from PowerShell Gallery: https://www.powershellgallery.com/packages/ps2exe"
        exit 1
    }
}
try { Import-Module ps2exe -ErrorAction Stop } catch {
    Write-Err2 "Import-Module ps2exe failed: $_"; exit 1
}
Write-OK "ps2exe ready."

# ---------- 4) ImportExcel (SOFT - warning only) ----------
Write-Step "Checking ImportExcel (optional, for XLSX export)..."
if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
    Write-Warn2 "ImportExcel not installed. XLSX export will fall back to CSV at runtime."
    Write-Warn2 "Install on target machine: Install-Module ImportExcel -Scope CurrentUser"
} else {
    Write-OK "ImportExcel available."
}

# ---------- 5) Prepare output ----------
Write-Step "Preparing output directory..."
$outParent = Split-Path -Parent $OutDir
if (-not (Test-Path $outParent)) {
    try { New-Item -ItemType Directory -Path $outParent -Force | Out-Null }
    catch { Write-Err2 "Cannot create output parent dir: $outParent"; exit 1 }
}
if (Test-Path $OutDir) {
    try { Remove-Item $OutDir -Recurse -Force }
    catch { Write-Err2 "Cannot clean existing OutDir: $OutDir`n$_"; exit 1 }
}
New-Item -ItemType Directory -Path $OutDir | Out-Null
foreach ($d in @('config','modules','logs','exports')) {
    New-Item -ItemType Directory -Path (Join-Path $OutDir $d) -Force | Out-Null
}
Write-OK "Output dir ready."

# ---------- 6) Copy runtime files ----------
Write-Step "Copying runtime files..."
Copy-Item (Join-Path $root 'MainForm.ps1')                  $OutDir -Force
Copy-Item (Join-Path $root 'DomainDiscovery.ps1')           $OutDir -Force
Copy-Item (Join-Path $root 'modules\DetectionConfig.ps1')   (Join-Path $OutDir 'modules') -Force
Copy-Item (Join-Path $root 'config\detection-groups.json')  (Join-Path $OutDir 'config')  -Force
Write-OK "Files copied."

# ---------- 7) Compile EXE ----------
$launcher = Join-Path $root 'Launcher.ps1'
$exePath  = Join-Path $OutDir 'ADDetector.exe'

Write-Step "Compiling Launcher.ps1 -> ADDetector.exe (noConsole)..."
$ps2exeLog = Join-Path $outParent 'ps2exe-build.log'
try {
    # Capture ps2exe verbose output to log file, do NOT pipe (avoids stdout corruption).
    Invoke-ps2exe `
        -inputFile  $launcher `
        -outputFile $exePath `
        -noConsole `
        -title       'ADDetector' `
        -description 'AD Hygiene & Exposure Visibility' `
        -company     'ADDetector' `
        -product     'ADDetector' `
        -version     $Version `
        -STA `
        -verbose `
        -ErrorAction Stop *> $ps2exeLog
} catch {
    Write-Err2 "ps2exe compile failed: $_"
    Write-Host "    Log: $ps2exeLog"
    exit 1
}
if (-not (Test-Path $exePath)) {
    Write-Err2 "EXE not produced: $exePath"
    Write-Host "    Check log: $ps2exeLog"
    exit 1
}
Write-OK "EXE built: $exePath"

# ---------- 8) Zip ----------
Write-Step "Creating distribution zip..."
$zipPath = Join-Path $outParent ("ADDetector-v$Version.zip")
try {
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    Compress-Archive -Path (Join-Path $OutDir '*') -DestinationPath $zipPath -Force
    Write-OK "Zip: $zipPath"
} catch {
    Write-Warn2 "Zip creation failed (non-fatal): $_"
}

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host " BUILD OK" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host "  Folder : $OutDir"
if (Test-Path $zipPath) { Write-Host "  Zip    : $zipPath" }
Write-Host "  Run    : $exePath"
Write-Host ""
