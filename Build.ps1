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
    [string]$Version = '1.1.0'
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

# ---------- 6b) Logo + ICO (soft-fail) ----------
Write-Step "Branding: logo + icon..."

# Audit flags
$logoFound  = $false
$icoBuilt   = $false
$icoEmbedded = $false

# Logo: prefer ADDetector.png, fallback MA_Cyber_Logo.png (legacy)
$logoCandidates = @(
    (Join-Path $root 'ADDetector.png'),
    (Join-Path $root 'MA_Cyber_Logo.png')
)
$logoSrc = $logoCandidates | Where-Object { $_ -and (Test-Path $_) } | Select-Object -First 1

if ($logoSrc) {
    try {
        Copy-Item $logoSrc (Join-Path $OutDir 'ADDetector.png') -Force
        $logoFound = $true
        Write-OK "Logo copied: $logoSrc -> ADDetector.png"
    } catch {
        Write-Warn2 "Logo copy failed (non-fatal): $_"
    }
} else {
    Write-Warn2 "No logo PNG found (ADDetector.png / MA_Cyber_Logo.png). Skipping."
}

# ICO: prefer ADDetector.ico, else generate from PNG via System.Drawing
$icoSrc  = Join-Path $root 'ADDetector.ico'
$icoDest = Join-Path $OutDir 'ADDetector.ico'

if (Test-Path $icoSrc) {
    try {
        Copy-Item $icoSrc $icoDest -Force
        $icoBuilt = $true
        Write-OK "ICO copied: ADDetector.ico"
    } catch {
        Write-Warn2 "ICO copy failed (non-fatal): $_"
    }
} elseif ($logoSrc) {
    Write-Step "ADDetector.ico not found - generating from PNG via System.Drawing..."
    try {
        Add-Type -AssemblyName System.Drawing -ErrorAction Stop
        $bmp    = New-Object System.Drawing.Bitmap($logoSrc)
        $resized = New-Object System.Drawing.Bitmap($bmp, (New-Object System.Drawing.Size(256, 256)))
        $hIcon  = $resized.GetHicon()
        $icon   = [System.Drawing.Icon]::FromHandle($hIcon)

        $fs = [System.IO.File]::Open($icoDest, [System.IO.FileMode]::Create)
        $icon.Save($fs)
        $fs.Close()
        $icon.Dispose()
        $resized.Dispose()
        $bmp.Dispose()

        $icoBuilt = $true
        Write-OK "ICO generated from PNG: $icoDest"
    } catch {
        Write-Warn2 "PNG->ICO generation failed (non-fatal): $_"
        Write-Warn2 "EXE will be built without embedded icon."
    }
} else {
    Write-Warn2 "No ICO source available. EXE will have no icon."
}

# ---------- 7) Compile EXE ----------
$launcher = Join-Path $root 'Launcher.ps1'
$exePath  = Join-Path $OutDir 'ADDetector.exe'

Write-Step "Compiling Launcher.ps1 -> ADDetector.exe (noConsole)..."
$ps2exeLog = Join-Path $outParent 'ps2exe-build.log'
try {
    $ps2exeParams = @{
        inputFile   = $launcher
        outputFile  = $exePath
        noConsole   = $true
        title       = 'ADDetector'
        description = 'AD Hygiene & Exposure Visibility'
        company     = 'Eren Arslan'
        product     = 'ADDetector'
        copyright   = "Copyright (c) $(Get-Date -Format yyyy) Eren Arslan"
        version     = $Version
        STA         = $true
        verbose     = $true
        ErrorAction = 'Stop'
    }

    # ICO embed: soft - only if file exists and is valid
    if ($icoBuilt -and (Test-Path $icoDest)) {
        $ps2exeParams['iconFile'] = $icoDest
        $icoEmbedded = $true
    }

    Invoke-ps2exe @ps2exeParams *> $ps2exeLog
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

# ---------- 9) Release summary ----------
$distFiles = Get-ChildItem $OutDir -Recurse -File |
    Select-Object -ExpandProperty FullName |
    ForEach-Object { $_.Replace($OutDir, '').TrimStart('\') }

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host " BUILD OK  --  ADDetector v$Version"              -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host ""
Write-Host "  Release Audit:" -ForegroundColor Cyan
Write-Host ("  Logo found      : " + $(if ($logoFound)    { "YES" } else { "NO (warning)" })) -ForegroundColor $(if ($logoFound)    { 'Green' } else { 'Yellow' })
Write-Host ("  ICO built       : " + $(if ($icoBuilt)     { "YES" } else { "NO (warning)" })) -ForegroundColor $(if ($icoBuilt)     { 'Green' } else { 'Yellow' })
Write-Host ("  ICO embedded    : " + $(if ($icoEmbedded)  { "YES" } else { "NO (warning)" })) -ForegroundColor $(if ($icoEmbedded)  { 'Green' } else { 'Yellow' })
Write-Host ""
Write-Host "  Dist files:" -ForegroundColor Cyan
$distFiles | ForEach-Object { Write-Host "    $_" }
Write-Host ""
Write-Host "  Folder : $OutDir"
if (Test-Path $zipPath) { Write-Host "  Zip    : $zipPath" }
Write-Host "  Run    : $exePath"
Write-Host ""
