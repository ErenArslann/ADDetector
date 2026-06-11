#Requires -Version 5.1
param(
    [string]$ZipPath,
    [string]$InstallDir,
    [string]$ExePath
)

Start-Sleep -Seconds 2

$logFile = Join-Path $InstallDir 'logs\ADDetector.log'

function Write-Log {
    param([string]$Msg)
    $line = "$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') [INFO] [Updater] $Msg"
    try { Add-Content -Path $logFile -Value $line -Encoding UTF8 } catch { }
}

try {
    Write-Log "Starting update | zip=$ZipPath | dest=$InstallDir"

    if (-not (Test-Path $ZipPath)) { Write-Log "ZIP not found: $ZipPath"; exit 1 }

    Add-Type -AssemblyName System.IO.Compression.FileSystem

    # Extract all except ADDetector.exe first
    $zip = [System.IO.Compression.ZipFile]::OpenRead($ZipPath)
    foreach ($entry in $zip.Entries) {
        if ($entry.Name -eq '') { continue }
        $destPath = Join-Path $InstallDir $entry.FullName
        $destDir  = Split-Path $destPath -Parent
        if (-not (Test-Path $destDir)) { New-Item -ItemType Directory $destDir -Force | Out-Null }
        if ($entry.Name -ne 'ADDetector.exe') {
            [System.IO.Compression.ZipFileExtensions]::ExtractToFile($entry, $destPath, $true)
        }
    }

    # Extract new EXE to temp
    $newExeEntry = $zip.Entries | Where-Object { $_.Name -eq 'ADDetector.exe' } | Select-Object -First 1
    $tmpExe = Join-Path $env:TEMP 'ADDetector_new.exe'
    if ($newExeEntry) {
        [System.IO.Compression.ZipFileExtensions]::ExtractToFile($newExeEntry, $tmpExe, $true)
    }
    $zip.Dispose()

    # Replace EXE
    $oldExe = $ExePath + '.old'
    if (Test-Path $ExePath) { Move-Item $ExePath $oldExe -Force }
    if (Test-Path $tmpExe)  { Copy-Item $tmpExe $ExePath -Force }
    if (Test-Path $oldExe)  { Remove-Item $oldExe -Force -ErrorAction SilentlyContinue }
    if (Test-Path $tmpExe)  { Remove-Item $tmpExe -Force -ErrorAction SilentlyContinue }

    # Remove ZIP
    Remove-Item $ZipPath -Force -ErrorAction SilentlyContinue

    Write-Log "Update complete. Launching ADDetector..."
    Start-Process $ExePath
    Write-Log "Done."

} catch {
    Write-Log "Update failed: $_"
    # Fallback - just launch
    if (Test-Path $ExePath) { Start-Process $ExePath }
}
