#Requires -Version 5.1
<#
.SYNOPSIS
    ADDetector launcher - entry point for ps2exe packaging.
.DESCRIPTION
    This script is what gets compiled into ADDetector.exe via ps2exe (with -noConsole).
    It locates MainForm.ps1 relative to itself and dot-sources it, so all .ps1/.psm1/
    .json files stay external (portable + transparent + editable).
#>

# Resolve our own directory whether running as .ps1 or as compiled .exe
$basePath = $null
if ($MyInvocation.MyCommand.Path) {
    $basePath = Split-Path -Parent $MyInvocation.MyCommand.Path
} elseif ($PSScriptRoot) {
    $basePath = $PSScriptRoot
} else {
    try {
        $basePath = Split-Path -Parent ([System.Reflection.Assembly]::GetEntryAssembly().Location)
    } catch {
        $basePath = (Get-Location).Path
    }
}

Set-Location -Path $basePath

$mainForm = Join-Path $basePath 'MainForm.ps1'
if (-not (Test-Path $mainForm)) {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(
        "MainForm.ps1 bulunamadi.`nAranan: $mainForm",
        'ADDetector - Launch Error','OK','Error') | Out-Null
    exit 1
}

try {
    . $mainForm
} catch {
    Add-Type -AssemblyName System.Windows.Forms
    [System.Windows.Forms.MessageBox]::Show(
        "ADDetector startup failed:`n`n$_`n`nLocation: $basePath",
        'ADDetector - Fatal Error','OK','Error') | Out-Null
    exit 1
}
