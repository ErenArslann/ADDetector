#Requires -Version 5.1
<#
.SYNOPSIS
    ADDetector v0.2 - SOC IAM Hygiene Dashboard
.DESCRIPTION
    DomainDiscovery.ps1 ile ayni klasorde olmali.
    Calistir: .\MainForm.ps1
    Gereksinim: RSAT (ActiveDirectory PS modulu)
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# ====================================================================
# PORTABLE PATHS + LOGGING
# ====================================================================
$script:BasePath = $null
if ($MyInvocation.MyCommand.Path) { $script:BasePath = Split-Path -Parent $MyInvocation.MyCommand.Path }
elseif ($PSScriptRoot)            { $script:BasePath = $PSScriptRoot }
else                              { $script:BasePath = (Get-Location).Path }

# Auto-create runtime directories (portable mode)
foreach ($d in @('config','modules','logs','exports')) {
    $p = Join-Path $script:BasePath $d
    if (-not (Test-Path $p)) { New-Item -ItemType Directory -Path $p -Force | Out-Null }
}

$script:LogFile = Join-Path $script:BasePath ("logs\addetector-{0}.log" -f (Get-Date -Format 'yyyyMMdd'))

function Write-AppLog {
    [CmdletBinding(DefaultParameterSetName='Default')]
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO','WARN','ERROR','DEBUG')][string]$Level = 'INFO',
        [Alias('Module')]                     # backward-compat with DomainDiscovery's Write-DDLog
        [string]$Component = 'App'
    )
    try {
        $line = "[{0}][{1}][{2}] {3}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $Level, $Component, $Message
        Add-Content -Path $script:LogFile -Value $line -Encoding UTF8 -ErrorAction SilentlyContinue
    } catch { }
}

# Global error trap: log + popup, never crash
trap {
    try {
        Write-AppLog -Level ERROR -Component 'Trap' -Message ($_ | Out-String)
        [System.Windows.Forms.MessageBox]::Show(
            "Unexpected error logged to:`n$script:LogFile`n`n$_",
            'ADDetector','OK','Error') | Out-Null
    } catch { }
    continue
}

Write-AppLog -Component 'Startup' -Message "ADDetector starting | BasePath=$script:BasePath"

# Parse threshold input. Returns:
#   [int] 0           -> "all users" (no inactivity filter)
#   [int] 1..3650     -> days threshold
#   $null             -> invalid (caller should show error)
# Empty/whitespace input -> defaults to 30 (does NOT error).
function Get-ThresholdDays {
    param([string]$Raw)
    if (-not $Raw -or $Raw.Trim() -eq '') { return 30 }
    $t = $Raw.Trim().ToLower()
    if ($t -in @('all','*','any')) { return 0 }
    $m = [regex]::Match($t, '^\s*(\d{1,5})')
    if (-not $m.Success) { return $null }
    $n = [int]$m.Groups[1].Value
    if ($n -lt 0 -or $n -gt 3650) { return $null }
    return $n
}

# ====================================================================
# PALETTE & FONTS
# ====================================================================
$script:C = @{
    BgDark      = [System.Drawing.Color]::FromArgb(18,  20,  26)
    BgMid       = [System.Drawing.Color]::FromArgb(26,  29,  38)
    BgCard      = [System.Drawing.Color]::FromArgb(34,  38,  52)
    BgGrid      = [System.Drawing.Color]::FromArgb(22,  25,  34)
    BgRowAlt    = [System.Drawing.Color]::FromArgb(28,  31,  43)
    BgDetail    = [System.Drawing.Color]::FromArgb(30,  34,  46)
    FgPrimary   = [System.Drawing.Color]::FromArgb(220, 225, 240)
    FgSecondary = [System.Drawing.Color]::FromArgb(130, 140, 165)
    FgMuted     = [System.Drawing.Color]::FromArgb(80,  90,  115)
    AccentBlue  = [System.Drawing.Color]::FromArgb(64,  156, 255)
    RiskCritical = [System.Drawing.Color]::FromArgb(255, 65,  65)
    RiskHigh     = [System.Drawing.Color]::FromArgb(255, 145, 30)
    RiskMedium   = [System.Drawing.Color]::FromArgb(255, 210, 50)
    RiskLow      = [System.Drawing.Color]::FromArgb(80,  200, 120)
    RiskSA       = [System.Drawing.Color]::FromArgb(100, 160, 255)
    RiskDisabled = [System.Drawing.Color]::FromArgb(70,  75,  95)
    RowCritical  = [System.Drawing.Color]::FromArgb(60,  20,  20)
    RowHigh      = [System.Drawing.Color]::FromArgb(55,  32,  10)
    RowMedium    = [System.Drawing.Color]::FromArgb(50,  44,  10)
    RowSA        = [System.Drawing.Color]::FromArgb(18,  36,  60)
    RowDisabled  = [System.Drawing.Color]::FromArgb(28,  28,  38)
    Border       = [System.Drawing.Color]::FromArgb(48,  54,  72)
    Splitter     = [System.Drawing.Color]::FromArgb(40,  45,  62)
    BgBadge      = [System.Drawing.Color]::FromArgb(44,  50,  68)
    BgSection    = [System.Drawing.Color]::FromArgb(38,  43,  60)
}

$script:F = @{
    UI      = New-Object System.Drawing.Font('Segoe UI', 9)
    UIBold  = New-Object System.Drawing.Font('Segoe UI', 9,   [System.Drawing.FontStyle]::Bold)
    UISm    = New-Object System.Drawing.Font('Segoe UI', 8)
    Mono    = New-Object System.Drawing.Font('Consolas', 8.5)
    CardVal = New-Object System.Drawing.Font('Segoe UI', 20,  [System.Drawing.FontStyle]::Bold)
    CardLbl = New-Object System.Drawing.Font('Segoe UI', 7.5, [System.Drawing.FontStyle]::Bold)
    Header  = New-Object System.Drawing.Font('Segoe UI', 10,  [System.Drawing.FontStyle]::Bold)
}

# ====================================================================
# RISK ENGINE
# ====================================================================
# Detection patterns are loaded from config/detection-groups.json
# via DetectionConfig.ps1 (dot-sourced below in module loader block).

function Test-IsServiceAccount {
    param($r)
    if ($r.SPNCount -gt 0)                                           { return $true }
    if ($r.Description -match 'service|automated|system account')    { return $true }
    # samAccountName regex from config (serviceAccount category)
    $cfg = Get-DetectionConfig
    $saCat = $cfg.patterns.serviceAccount
    if ($saCat -and $saCat.isEnabled -and $saCat.regex) {
        if ($r.SamAccountName -match $saCat.regex) { return $true }
    }
    return $false
}

function Test-IsPrivileged {
    param($r)
    if ($r.AdminCount -eq 1) { return $true }
    if ($r.MatchedGroups -and $r.MatchedGroups.privileged -and $r.MatchedGroups.privileged.Count -gt 0) {
        return $true
    }
    return $false
}

function Get-RiskScore {
    param($r)
    $s = 0
    if     ($r.InactiveDays -ge 90) { $s += 70 }
    elseif ($r.InactiveDays -ge 60) { $s += 55 }
    elseif ($r.InactiveDays -ge 30) { $s += 40 }
    if ($r.NeverLoggedIn)           { $s += 50 }
    if     ($r.PwdAgeDays -ge 365)  { $s += 20 }
    elseif ($r.PwdAgeDays -ge 180)  { $s += 10 }

    # VPN / Remote Access boosters (dormant + remote = SOC red flag)
    if ($r.HasVPNAccess)       { $s += 25 }
    if ($r.HasRemoteAccess)    { $s += 20 }
    if ($r.HasVPNAccess -and -not $r.HasMFA) { $s += 15 }   # VPN without MFA
    if ($r.HasVPNAccess -and $r.NeverLoggedIn) { $s += 20 } # provisioned but never used

    $mult = 1.0
    if ($r.AdminCount -eq 1) { $mult = [Math]::Max($mult, 2.0) }
    if ($r.IsPrivileged)     { $mult = [Math]::Max($mult, 2.5) }
    if ($r.IsPrivileged -and ($r.HasVPNAccess -or $r.HasRemoteAccess)) {
        $mult = [Math]::Max($mult, 3.0)                     # privileged + remote = CRITICAL
    }
    $s = [int]($s * $mult)
    if (-not $r.Enabled)         { $s = [int]($s * 0.3) }
    if ($r.IsServiceAccount)     { $s = [int]($s * 0.5) }
    return [Math]::Min($s, 100)
}

function Get-RiskLevel {
    param([int]$Score, [bool]$IsSA, [bool]$Disabled)
    if ($Disabled) { return 'DISABLED'  }
    if ($IsSA)     { return 'SVC-ACCT'  }
    if ($Score -ge 80) { return 'CRITICAL' }
    if ($Score -ge 55) { return 'HIGH'     }
    if ($Score -ge 30) { return 'MEDIUM'   }
    return 'LOW'
}

function Get-RiskOrder { param([string]$L)
    switch ($L) {
        'CRITICAL' { 0 } 'HIGH' { 1 } 'MEDIUM' { 2 }
        'LOW'      { 3 } 'SVC-ACCT' { 4 } 'DISABLED' { 5 } default { 9 }
    }
}

function Get-RiskColor { param([string]$L)
    switch ($L) {
        'CRITICAL' { $C.RiskCritical } 'HIGH'     { $C.RiskHigh    }
        'MEDIUM'   { $C.RiskMedium   } 'LOW'      { $C.RiskLow     }
        'SVC-ACCT' { $C.RiskSA       } 'DISABLED' { $C.RiskDisabled}
        default    { $C.FgSecondary  }
    }
}

function Get-RowBg { param([string]$L)
    switch ($L) {
        'CRITICAL' { $C.RowCritical } 'HIGH'     { $C.RowHigh    }
        'MEDIUM'   { $C.RowMedium   } 'SVC-ACCT' { $C.RowSA      }
        'DISABLED' { $C.RowDisabled } default    { $C.BgGrid     }
    }
}

# ====================================================================
# MODULE LOADERS (DomainDiscovery + DetectionConfig)
# ====================================================================
try {
    $ddPath = Join-Path $script:BasePath 'DomainDiscovery.ps1'
    if (-not (Test-Path $ddPath)) { throw "DomainDiscovery.ps1 not found: $ddPath" }
    . $ddPath *>&1 | Out-Null
    Write-AppLog -Component 'Loader' -Message "DomainDiscovery loaded"
} catch {
    Write-AppLog -Level ERROR -Component 'Loader' -Message "DomainDiscovery load failed: $_"
    [System.Windows.Forms.MessageBox]::Show("DomainDiscovery load failed:`n$_",'ADDetector','OK','Error') | Out-Null
    exit 1
}

try {
    $dcPath = Join-Path $script:BasePath 'modules\DetectionConfig.ps1'
    if (-not (Test-Path $dcPath)) { throw "DetectionConfig.ps1 not found: $dcPath" }
    . $dcPath
    $cfgPath = Join-Path $script:BasePath 'config\detection-groups.json'
    Initialize-DetectionConfig -Path $cfgPath | Out-Null
    Write-AppLog -Component 'Loader' -Message "DetectionConfig loaded | cfg=$cfgPath"
} catch {
    Write-AppLog -Level ERROR -Component 'Loader' -Message "DetectionConfig load failed: $_"
    [System.Windows.Forms.MessageBox]::Show("DetectionConfig load failed:`n$_",'ADDetector','OK','Error') | Out-Null
    exit 1
}

# ====================================================================
# FORM
# ====================================================================
$form               = New-Object System.Windows.Forms.Form
$form.Text          = 'ADDetector v1.1'
$form.Size          = New-Object System.Drawing.Size(1800, 880)
$form.MinimumSize   = New-Object System.Drawing.Size(1280, 700)
$form.AutoScaleMode = [System.Windows.Forms.AutoScaleMode]::Dpi
$form.StartPosition = 'CenterScreen'
$form.WindowState   = [System.Windows.Forms.FormWindowState]::Maximized
$form.BackColor     = $C.BgDark
$form.Font          = $F.UI
$form.ForeColor     = $C.FgPrimary

# Form DoubleBuffered - flicker/restore lag fix
try {
    $formType = $form.GetType()
    $prop = $formType.GetProperty('DoubleBuffered',
        [System.Reflection.BindingFlags]::Instance -bor
        [System.Reflection.BindingFlags]::NonPublic)
    if ($prop) { $prop.SetValue($form, $true, $null) }
} catch { }

# Windows 10/11 dark title bar - DWM API
try {
    if (-not ('Win32DwmHelper' -as [type])) {
        Add-Type -Namespace 'PInvoke' -Name 'Win32DwmHelper' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("dwmapi.dll", PreserveSig=true)]
public static extern int DwmSetWindowAttribute(System.IntPtr hwnd, int attr, ref int attrValue, int attrSize);
'@ -ErrorAction SilentlyContinue
    }
    if (-not ('Win32MsgHelper' -as [type])) {
        Add-Type -Namespace 'PInvoke' -Name 'Win32MsgHelper' -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("user32.dll", CharSet=System.Runtime.InteropServices.CharSet.Auto)]
public static extern System.IntPtr SendMessage(System.IntPtr hWnd, int Msg, int wParam, System.IntPtr lParam);
'@ -ErrorAction SilentlyContinue
    }
    $form.Add_HandleCreated({
        try {
            $useDark = 1
            # 20 = DWMWA_USE_IMMERSIVE_DARK_MODE (Win11), 19 = older Win10
            [PInvoke.Win32DwmHelper]::DwmSetWindowAttribute($form.Handle, 20, [ref]$useDark, 4) | Out-Null
            [PInvoke.Win32DwmHelper]::DwmSetWindowAttribute($form.Handle, 19, [ref]$useDark, 4) | Out-Null
        } catch { }
    })
} catch { }

# Window/taskbar icon - embedded Base64 + external file fallback
$script:EmbeddedICO = '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'
$script:IconCandidates = @(
    (Join-Path $script:BasePath 'ADDetector.ico'),
    (Join-Path $script:BasePath 'assets\ADDetector.ico'),
    (Join-Path (Split-Path $script:BasePath -Parent) 'ADDetector.ico'),
    (Join-Path (Get-Location).Path 'ADDetector.ico')
)
$iconLoaded = $false
foreach ($icoPath in $script:IconCandidates) {
    if ($icoPath -and (Test-Path -LiteralPath $icoPath)) {
        try {
            $form.Icon = New-Object System.Drawing.Icon($icoPath)
            $iconLoaded = $true
            Write-AppLog -Component 'Branding' -Message "Icon loaded: $icoPath"
            break
        } catch {
            Write-AppLog -Level WARN -Component 'Branding' -Message "Icon load failed: $icoPath | $_"
        }
    }
}
if (-not $iconLoaded) {
    try {
        $icoBytes = [System.Convert]::FromBase64String($script:EmbeddedICO)
        $icoMs = New-Object System.IO.MemoryStream(,$icoBytes)
        $form.Icon = New-Object System.Drawing.Icon($icoMs)
        Write-AppLog -Component 'Branding' -Message 'Icon loaded from embedded Base64'
    } catch {
        Write-AppLog -Level WARN -Component 'Branding' -Message "Embedded icon load failed: $_"
    }
}

# ?? TOP BAR ??????????????????????????????????????????????????????????????????
$topBar            = New-Object System.Windows.Forms.Panel
$topBar.Dock       = 'Top'
$topBar.Height     = 52
$topBar.BackColor  = $C.BgMid
$topBar.AutoScroll = $true   # narrow screens: horizontal scroll

$lblTitle         = New-Object System.Windows.Forms.Label
$lblTitle.Text    = 'ADDetector v1.1'
$lblTitle.Font    = New-Object System.Drawing.Font('Segoe UI Semibold', 13, [System.Drawing.FontStyle]::Regular)
$lblTitle.ForeColor = $C.AccentBlue
$lblTitle.AutoSize  = $true
$lblTitle.Location  = New-Object System.Drawing.Point(20, 16)

# Logo PictureBox - dosya bulunursa logo, yoksa text fallback
$picLogo          = New-Object System.Windows.Forms.PictureBox
$picLogo.Location = New-Object System.Drawing.Point(16, 6)
$picLogo.Size     = New-Object System.Drawing.Size(180, 40)
$picLogo.SizeMode = 'Zoom'
$picLogo.BackColor = $C.BgMid
$picLogo.Visible  = $false

# Logo path candidates - basePath + parent + CWD + dist/ADDetector subdir
# Embedded logo (Base64)
$script:EmbeddedLogoPNG = '/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAH4AABAAEAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDAAUDBAQEAwUEBAQFBQUGBwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUFBQcGBw4ICA4eFBEUHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh7/wAARCAJTCWADASIAAhEBAxEB/8QAHQABAAICAwEBAAAAAAAAAAAAAAYHBQgCAwQBCf/EAGAQAAEDAgMDBQkICRAKAgIDAQABAgMEBQYHERIhMRMiQVFhCBQycYGRobHRFRYjQlKTssFDU1ZicnOSlOEXGCQlMzQ3RlSCg6KzwtLwJzU2RFVjZHR1hCZlRfEoo+Ly/8QAGwEBAAEFAQAAAAAAAAAAAAAAAAUCAwQGBwH/xABAEQACAgEBBAUICAYCAgMBAAAAAQIDBBEFEiExBhNBUXEUIjJSYZGhsRYzNFOBwdHwFSM1QnLhQ/EkgiVikqL/2gAMAwEAAhEDEQA/ANMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA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AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB/9k='
$script:LogoCandidates = @(
    (Join-Path $script:BasePath 'ADDetector.png'),
    (Join-Path $script:BasePath 'assets\ADDetector.png'),
    (Join-Path (Split-Path $script:BasePath -Parent) 'ADDetector.png'),
    (Join-Path (Get-Location).Path 'ADDetector.png')
)
$script:LogoLoaded = $false
foreach ($logoPath in $script:LogoCandidates) {
    if ($logoPath -and (Test-Path -LiteralPath $logoPath)) {
        try {
            # File lock yememek icin stream ile yukle
            $bytes = [System.IO.File]::ReadAllBytes($logoPath)
            $ms = New-Object System.IO.MemoryStream(,$bytes)
            $picLogo.Image   = [System.Drawing.Image]::FromStream($ms)
            $picLogo.Visible = $true
            $lblTitle.Visible = $false
            $script:LogoLoaded = $true
            Write-AppLog -Component 'Branding' -Message "Logo loaded: $logoPath"
            break
        } catch {
            Write-AppLog -Level WARN -Component 'Branding' -Message "Logo load failed: $logoPath | $_"
        }
    }
}
if (-not $script:LogoLoaded) {
    try {
        $bytes = [System.Convert]::FromBase64String($script:EmbeddedLogoPNG)
        $ms = New-Object System.IO.MemoryStream(,$bytes)
        $picLogo.Image   = [System.Drawing.Image]::FromStream($ms)
        $picLogo.Visible = $true
        $lblTitle.Visible = $false
        $script:LogoLoaded = $true
        Write-AppLog -Component 'Branding' -Message 'Logo loaded from embedded Base64'
    } catch {
        Write-AppLog -Level WARN -Component 'Branding' -Message "Embedded logo load failed: $_"
    }
}

$lblSub           = New-Object System.Windows.Forms.Label
$lblSub.Text      = ''
$lblSub.Font      = $F.UISm
$lblSub.ForeColor = $C.FgSecondary
$lblSub.AutoSize  = $true
$lblSub.Location  = New-Object System.Drawing.Point(145, 18)
$lblSub.Visible   = $false

$lblDomLbl        = New-Object System.Windows.Forms.Label
$lblDomLbl.Text   = 'DOMAIN'
$lblDomLbl.Font   = $F.CardLbl
$lblDomLbl.ForeColor = $C.FgSecondary
$lblDomLbl.AutoSize  = $true
$lblDomLbl.Location  = New-Object System.Drawing.Point(315, 8)

# Logo ile kontroller arasi dikey ayirici - kurumsal navbar hissi
$topDivider       = New-Object System.Windows.Forms.Panel
$topDivider.Location = New-Object System.Drawing.Point(290, 12)
$topDivider.Size     = New-Object System.Drawing.Size(1, 28)
$topDivider.BackColor = $C.Border

$cboDomain             = New-Object System.Windows.Forms.ComboBox
$cboDomain.Location    = New-Object System.Drawing.Point(315, 24)
$cboDomain.Size        = New-Object System.Drawing.Size(240, 22)
$cboDomain.DropDownStyle = 'DropDownList'
$cboDomain.FlatStyle   = 'Flat'
$cboDomain.BackColor   = $C.BgCard
$cboDomain.ForeColor   = $C.FgPrimary

$lblManLbl        = New-Object System.Windows.Forms.Label
$lblManLbl.Text   = 'MANUAL'
$lblManLbl.Font   = $F.CardLbl
$lblManLbl.ForeColor = $C.FgSecondary
$lblManLbl.AutoSize  = $true
$lblManLbl.Location  = New-Object System.Drawing.Point(572, 8)

$txtManual        = New-Object System.Windows.Forms.TextBox
$txtManual.Location = New-Object System.Drawing.Point(572, 24)
$txtManual.Size     = New-Object System.Drawing.Size(155, 22)
$txtManual.BackColor = $C.BgCard
$txtManual.ForeColor = $C.FgPrimary
$txtManual.BorderStyle = 'FixedSingle'

$lblThrLbl        = New-Object System.Windows.Forms.Label
$lblThrLbl.Text   = 'INACTIVE >='
$lblThrLbl.Font   = $F.CardLbl
$lblThrLbl.ForeColor = $C.FgSecondary
$lblThrLbl.AutoSize  = $true
$lblThrLbl.Location  = New-Object System.Drawing.Point(744, 8)

$cboThreshold             = New-Object System.Windows.Forms.ComboBox
$cboThreshold.Location    = New-Object System.Drawing.Point(744, 24)
$cboThreshold.Size        = New-Object System.Drawing.Size(92, 22)
$cboThreshold.DropDownStyle = 'DropDown'   # editable for custom value
$cboThreshold.FlatStyle   = 'Flat'
$cboThreshold.BackColor   = $C.BgCard
$cboThreshold.ForeColor   = $C.FgPrimary
@('0 (All users)','7','15','30','60','90','180','365') | ForEach-Object { [void]$cboThreshold.Items.Add($_) }
$cboThreshold.SelectedIndex = 0  # default: All users — SOC workflow

function New-Btn {
    param([string]$Text, [int]$X, [System.Drawing.Color]$Bg, [int]$W = 92)
    $b = New-Object System.Windows.Forms.Button
    $b.Text = $Text; $b.Location = New-Object System.Drawing.Point($X, 13)
    $b.Size = New-Object System.Drawing.Size($W, 26)
    $b.FlatStyle = 'Flat'; $b.BackColor = $Bg
    $b.ForeColor = [System.Drawing.Color]::White; $b.Font = $F.UIBold
    $b.FlatAppearance.BorderSize = 0
    return $b
}

$btnDiscover = New-Btn 'DISCOVER' 850  ([System.Drawing.Color]::FromArgb(0,122,204))
$btnScan     = New-Btn 'SCAN'     950  ([System.Drawing.Color]::FromArgb(0,155,70))
$btnScan.Enabled = $false
$btnClear    = New-Btn 'CLEAR'    1050 ([System.Drawing.Color]::FromArgb(75,80,110)) 72
$btnCSV      = New-Btn 'CSV'      1130 ([System.Drawing.Color]::FromArgb(90, 110, 150)) 60
$btnXLSX     = New-Btn 'XLSX'     1198 ([System.Drawing.Color]::FromArgb(40, 130, 90))  68
$btnHTML      = New-Btn 'HTML'      1274 ([System.Drawing.Color]::FromArgb(120, 60, 160))  60
$btnSettings  = New-Btn ([char]0x2699) 1342 ([System.Drawing.Color]::FromArgb(40, 50, 80)) 28
$btnAbout    = New-Btn ([char]0x24D8) 1378 ([System.Drawing.Color]::FromArgb(30, 40, 70)) 28
$btnSettings.Font = New-Object System.Drawing.Font('Segoe UI', 11)
$btnCSV.Enabled  = $false
$btnXLSX.Enabled = $false
$btnHTML.Enabled = $false

$btnAbout.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$btnAbout.FlatAppearance.BorderSize = 1
$btnAbout.FlatAppearance.BorderColor = $C.Border

$topBar.Controls.AddRange(@($picLogo,$lblTitle,$lblSub,$topDivider,$lblDomLbl,$cboDomain,$lblManLbl,$txtManual,$lblThrLbl,$cboThreshold,$btnDiscover,$btnScan,$btnClear,$btnCSV,$btnXLSX,$btnHTML,$btnSettings,$btnAbout))

# ?? METRIC CARDS ?????????????????????????????????????????????????????????????
$cardBar           = New-Object System.Windows.Forms.Panel
$cardBar.Dock      = 'Top'
$cardBar.Height    = 92
$cardBar.BackColor = $C.BgDark
$cardBar.AutoScroll = $true   # narrow screens: horizontal scroll

$script:metricLabels = @{}
$script:ActiveCardFilter = $null

# Single source of truth: predicates - hem card count hem filter ayni
$script:CardPredicates = @{
    'Total'      = { param($r) $true }
    'Inactive'   = { param($r) $r.InactiveDays -ge 30 }
    'Critical'   = { param($r) $r.RiskLevel -eq 'CRITICAL' }
    'Privileged' = { param($r) $r.IsPrivileged -and $r.InactiveDays -ge 30 }
    'NeverLogon' = { param($r) $r.NeverLoggedIn }
    'SvcAcc'     = { param($r) $r.IsServiceAccount }
    'Disabled'   = { param($r) -not $r.Enabled }
    'RemoteAcc'  = { param($r) $r.HasVPNAccess -or $r.HasRemoteAccess }
    'DormantVPN' = { param($r) $r.HasVPNAccess -and $r.InactiveDays -ge 30 }
}

$cardDefs = @(
    @{Key='Total';      Lbl='Total Users';        Accent=$C.AccentBlue;    X=10  }
    @{Key='Inactive';   Lbl='Inactive / Stale';   Accent=$C.RiskMedium;    X=193 }
    @{Key='Critical';   Lbl='Critical Risk';       Accent=$C.RiskCritical;  X=376 }
    @{Key='Privileged'; Lbl='Privileged Inactive'; Accent=$C.RiskHigh;      X=559 }
    @{Key='NeverLogon'; Lbl='Never Logged In';     Accent=$C.RiskCritical;  X=742 }
    @{Key='SvcAcc';     Lbl='Service Accounts';    Accent=$C.RiskSA;        X=925 }
    @{Key='Disabled';   Lbl='Disabled Stale';      Accent=$C.RiskDisabled;  X=1108}
    @{Key='RemoteAcc';  Lbl='Remote Access';       Accent=$C.RiskHigh;      X=1291}
    @{Key='DormantVPN'; Lbl='Dormant VPN Users';   Accent=$C.RiskCritical;  X=1474}
)

foreach ($cd in $cardDefs) {
    $card           = New-Object System.Windows.Forms.Panel
    $card.Location  = New-Object System.Drawing.Point($cd.X, 8)
    $card.Size      = New-Object System.Drawing.Size(175, 76)
    $card.BackColor = $C.BgCard
    $card.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $card.Tag       = $cd.Key   # filter dispatch icin

    $accentBar      = New-Object System.Windows.Forms.Panel
    $accentBar.Location = New-Object System.Drawing.Point(0, 0)
    $accentBar.Size     = New-Object System.Drawing.Size(4, 76)
    $accentBar.BackColor = $cd.Accent

    $valLbl         = New-Object System.Windows.Forms.Label
    $valLbl.Text    = '-'
    $valLbl.Font    = $F.CardVal
    $valLbl.ForeColor = $C.FgPrimary
    $valLbl.AutoSize  = $true
    $valLbl.Location  = New-Object System.Drawing.Point(14, 11)
    $valLbl.Cursor    = [System.Windows.Forms.Cursors]::Hand

    $keyLbl         = New-Object System.Windows.Forms.Label
    $keyLbl.Text    = $cd.Lbl.ToUpper()
    $keyLbl.Font    = $F.CardLbl
    $keyLbl.ForeColor = $cd.Accent
    $keyLbl.AutoSize  = $true
    $keyLbl.Location  = New-Object System.Drawing.Point(14, 54)
    $keyLbl.Cursor    = [System.Windows.Forms.Cursors]::Hand

    $card.Controls.AddRange(@($accentBar, $valLbl, $keyLbl))
    $cardBar.Controls.Add($card)
    $script:metricLabels[$cd.Key] = $valLbl

    # Click handler - tum child'larda + card kendisinde
    $clickAction = {
        param($sender, $e)
        try {
            # Tag'i parent'tan al (label'a tiklanmis olabilir)
            $ctl = $sender
            while ($ctl -and -not $ctl.Tag) { $ctl = $ctl.Parent }
            if (-not $ctl -or -not $ctl.Tag) { return }
            if (-not $script:allRows -or $script:allRows.Count -eq 0) { return }
            Invoke-CardFilter -CardKey $ctl.Tag
        } catch {
            Write-AppLog -Level WARN -Component 'CardClick' -Message "Card click failed: $_"
        }
    }
    $card.Add_Click($clickAction)
    $valLbl.Add_Click($clickAction)
    $keyLbl.Add_Click($clickAction)
    $accentBar.Add_Click($clickAction)

    # Hover effect - aktif card'i ezme
    $hoverIn = {
        try {
            if ($this.Tag -ne $script:ActiveCardFilter) {
                $this.BackColor = $script:C.BgRowAlt
            }
        } catch { }
    }
    $hoverOut = {
        try {
            if ($this.Tag -ne $script:ActiveCardFilter) {
                $this.BackColor = $script:C.BgCard
            }
        } catch { }
    }
    $card.Add_MouseEnter($hoverIn)
    $card.Add_MouseLeave($hoverOut)
}

# Quick-filter dispatcher - card key -> filter state
function Invoke-CardFilter {
    param([string]$CardKey)
    if (-not $script:CardPredicates.ContainsKey($CardKey)) { return }

    # UI filter'lari sifirla (suspend events sonra restore - flicker yok)
    $cboRisk.SelectedIndex   = 0
    $chkPrivOnly.Checked     = $false
    $chkNeverOnly.Checked    = $false
    $chkHideSA.Checked       = $false
    $chkHideDis.Checked      = $false
    $script:VPNFilter = 'All'; $btnVPNFilter.Text = 'VPN: All'; $btnVPNFilter.Tag = 'All'; $btnVPNFilter.BackColor = $script:C.BgCard
    $script:MFAFilter = 'All'; $btnMFAFilter.Text = 'MFA: All'; $btnMFAFilter.Tag = 'All'; $btnMFAFilter.BackColor = $script:C.BgCard
    $script:RemoteFilter = 'All'; $btnRemoteFilter.Text = 'Remote: All'; $btnRemoteFilter.Tag = 'All'; $btnRemoteFilter.BackColor = $script:C.BgCard
    # Multi-select dropdown'ları da temizle
    $script:TypeFilter = @(); Update-MultiBtn $script:TypeDD 'Type'
    $script:DeptFilter = @(); Update-MultiBtn $script:DeptDD 'Dept'
    for ($i = 0; $i -lt $script:TypeDD.Clb.Items.Count; $i++) { $script:TypeDD.Clb.SetItemChecked($i, $false) }
    for ($i = 0; $i -lt $script:DeptDD.Clb.Items.Count; $i++) { $script:DeptDD.Clb.SetItemChecked($i, $false) }
    if ($txtSearch.Text -ne $script:SearchPlaceholder) {
        $txtSearch.Text = $script:SearchPlaceholder
        $txtSearch.ForeColor = $script:C.FgMuted
    }

    # Card filter aktifle - Apply-Filters predicate'i kullanacak
    if ($CardKey -eq 'Total') {
        $script:ActiveCardFilter = $null
        Set-Status 'Filter: ALL users (reset).'
    } else {
        $script:ActiveCardFilter = $CardKey
        $lbl = ($cardDefs | Where-Object { $_.Key -eq $CardKey } | Select-Object -First 1).Lbl
        Set-Status "Filter: $lbl"
    }

    # Aktif kart vurgulamasi
    Update-CardHighlight
    Apply-Filters
}

# Aktif card'a belirgin highlight: arkaplan + accent bar tam beyaz + label renk degisimi
function Update-CardHighlight {
    foreach ($ctl in $cardBar.Controls) {
        if (-not ($ctl -is [System.Windows.Forms.Panel] -and $ctl.Tag)) { continue }
        $cardDef = $cardDefs | Where-Object { $_.Key -eq $ctl.Tag } | Select-Object -First 1
        if ($ctl.Tag -eq $script:ActiveCardFilter) {
            # Secili: parlak bg + accent bar beyaz + value label accent renginde
            $ctl.BackColor = [System.Drawing.Color]::FromArgb(55, 65, 95)
            if ($ctl.Controls.Count -ge 1) { $ctl.Controls[0].BackColor = [System.Drawing.Color]::White }
            # Value label (index 1) ve key label (index 2) rengi
            if ($ctl.Controls.Count -ge 2) { $ctl.Controls[1].ForeColor = [System.Drawing.Color]::White }
        } else {
            $ctl.BackColor = $script:C.BgCard
            if ($cardDef) {
                if ($ctl.Controls.Count -ge 1) { $ctl.Controls[0].BackColor = $cardDef.Accent }
                if ($ctl.Controls.Count -ge 2) { $ctl.Controls[1].ForeColor = $script:C.FgPrimary }
            }
        }
    }
}

# ?? FILTER BAR ???????????????????????????????????????????????????????????????
$filterBar        = New-Object System.Windows.Forms.Panel
$filterBar.Dock   = 'Top'
$filterBar.Height = 36
$filterBar.BackColor = $C.BgMid

$cboRisk          = New-Object System.Windows.Forms.ComboBox
$cboRisk.Location = New-Object System.Drawing.Point(12, 7)
$cboRisk.Size     = New-Object System.Drawing.Size(128, 22)
$cboRisk.DropDownStyle = 'DropDownList'
$cboRisk.FlatStyle     = 'Flat'
$cboRisk.BackColor     = $C.BgCard
$cboRisk.ForeColor     = $C.FgPrimary
@('All Risk Levels','CRITICAL','HIGH','MEDIUM','LOW','SVC-ACCT','DISABLED') |
    ForEach-Object { [void]$cboRisk.Items.Add($_) }
$cboRisk.SelectedIndex = 0

function New-Chk {
    param([string]$Text, [int]$X)
    $c = New-Object System.Windows.Forms.CheckBox
    $c.Text = $Text; $c.Font = $script:F.UISm
    $c.ForeColor = $script:C.FgSecondary
    $c.BackColor = [System.Drawing.Color]::Transparent
    $c.AutoSize  = $true
    $c.Location  = New-Object System.Drawing.Point($X, 9)
    return $c
}

$chkPrivOnly  = New-Chk 'Privileged only' 152
$chkNeverOnly = New-Chk 'Never logged in' 272
$chkHideSA    = New-Chk 'Hide svc accts'  388
$chkHideDis   = New-Chk 'Hide disabled'   496
# VPN/MFA/Remote dropdown filters (replaces checkboxes)
$script:VPNFilter    = 'All'   # All / Yes / No
$script:MFAFilter    = 'All'
$script:RemoteFilter = 'All'

function New-TriStateBtn {
    param([string]$Label, [int]$X)
    $btn = New-Object System.Windows.Forms.Button
    $btn.Text     = "${Label}: All"
    $btn.Location = New-Object System.Drawing.Point($X, 7)
    $btn.Size     = New-Object System.Drawing.Size(90, 22)
    $btn.FlatStyle = 'Flat'
    $btn.BackColor = $C.BgCard
    $btn.ForeColor = $C.FgSecondary
    $btn.Font      = $F.UISm
    $btn.FlatAppearance.BorderSize  = 1
    $btn.FlatAppearance.BorderColor = $C.Border
    $btn.Tag = 'All'
    return $btn
}

$btnVPNFilter    = New-TriStateBtn 'VPN'    600
$btnMFAFilter    = New-TriStateBtn 'MFA'    692
$btnRemoteFilter = New-TriStateBtn 'Remote' 784

$lblSrch      = New-Object System.Windows.Forms.Label
$lblSrch.Text = ''
$lblSrch.AutoSize  = $true
$lblSrch.Location  = New-Object System.Drawing.Point(-100, -100)
$lblSrch.Visible = $false

$txtSearch         = New-Object System.Windows.Forms.TextBox
$txtSearch.Location = New-Object System.Drawing.Point(1108, 7)
$txtSearch.Size     = New-Object System.Drawing.Size(210, 22)
$txtSearch.BackColor = $C.BgCard
$txtSearch.ForeColor = $C.FgMuted
$txtSearch.BorderStyle = 'FixedSingle'
$txtSearch.Font     = New-Object System.Drawing.Font('Segoe UI', 9.25)

# Placeholder behavior
$script:SearchPlaceholder = '   Search users, mail, department...'
$txtSearch.Text = $script:SearchPlaceholder
$txtSearch.Add_GotFocus({
    if ($txtSearch.Text -eq $script:SearchPlaceholder) {
        $txtSearch.Text = ''
        $txtSearch.ForeColor = $script:C.FgPrimary
    }
})
$txtSearch.Add_LostFocus({
    if ([string]::IsNullOrWhiteSpace($txtSearch.Text)) {
        $txtSearch.Text = $script:SearchPlaceholder
        $txtSearch.ForeColor = $script:C.FgMuted
    }
})

$btnDetail        = New-Object System.Windows.Forms.Button
$btnDetail.Text   = 'Details <'
$btnDetail.Size   = New-Object System.Drawing.Size(80, 22)
$btnDetail.Location = New-Object System.Drawing.Point(1326, 7)
$btnDetail.FlatStyle = 'Flat'
$btnDetail.BackColor = $C.BgCard
$btnDetail.ForeColor = $C.FgSecondary
$btnDetail.Font   = $F.UISm
$btnDetail.FlatAppearance.BorderSize = 1
$btnDetail.FlatAppearance.BorderColor = $C.Border

$filterBar.Controls.AddRange(@($cboRisk,$chkPrivOnly,$chkNeverOnly,$chkHideSA,$chkHideDis,$btnVPNFilter,$btnMFAFilter,$btnRemoteFilter,$lblSrch,$txtSearch,$btnDetail))

# ── Multi-select dropdown: Type ve Department ─────────────────────────────────
# Floating panel (Toplevel=false, form'a eklenir, filterBar'a degil)
# Butona basinca asagida acilir, disari tiklaninca kapanir.

$script:TypeFilter = @()        # secili types (bos = tumu)
$script:DeptFilter = @()        # secili departments (bos = tumu)

function New-MultiDropdown {
    param([string]$Title, [int]$BtnX)

    $btn = New-Object System.Windows.Forms.Button
    $btn.Text     = "$Title  ▾"
    $btn.Location = New-Object System.Drawing.Point($BtnX, 7)
    $btn.Size     = New-Object System.Drawing.Size(110, 22)
    $btn.FlatStyle = 'Flat'
    $btn.BackColor = $C.BgCard
    $btn.ForeColor = $C.FgSecondary
    $btn.Font      = $F.UISm
    $btn.FlatAppearance.BorderSize  = 1
    $btn.FlatAppearance.BorderColor = $C.Border
    $btn.Tag = $Title  # 'Type' or 'Department'
    $filterBar.Controls.Add($btn)

    $popup = New-Object System.Windows.Forms.Panel
    $popup.BackColor   = $C.BgCard
    $popup.BorderStyle = 'FixedSingle'
    $popup.Size        = New-Object System.Drawing.Size(180, 160)
    $popup.Visible     = $false
    $popup.BringToFront()

    $clb = New-Object System.Windows.Forms.CheckedListBox
    $clb.Dock          = 'Fill'
    $clb.BackColor     = $C.BgCard
    $clb.ForeColor     = $C.FgPrimary
    $clb.Font          = $F.UISm
    $clb.BorderStyle   = 'None'
    $clb.CheckOnClick  = $true

    $popup.Controls.Add($clb)

    return @{ Btn=$btn; Popup=$popup; Clb=$clb }
}

$script:TypeDD = New-MultiDropdown 'Type' 880
$script:DeptDD = New-MultiDropdown 'Dept' 992

# Popup'ları form'a ekle (filterBar'a değil — z-order için)
$form.Controls.Add($script:TypeDD.Popup)
$form.Controls.Add($script:DeptDD.Popup)

function Show-MultiDropdown {
    param($dd, [string]$Key)

    # Diger popup'u kapat
    $other = if ($Key -eq 'Type') { $script:DeptDD } else { $script:TypeDD }
    $other.Popup.Visible = $false

    if ($dd.Popup.Visible) { $dd.Popup.Visible = $false; return }

    # Konumlandır: butonun alt-sol kosesi
    $btnScreen = $dd.Btn.PointToScreen([System.Drawing.Point]::Empty)
    $formScreen = $form.PointToScreen([System.Drawing.Point]::Empty)
    $x = $btnScreen.X - $formScreen.X
    $y = $btnScreen.Y - $formScreen.Y + $dd.Btn.Height + 2
    $dd.Popup.Location = New-Object System.Drawing.Point($x, $y)
    $dd.Popup.BringToFront()
    $dd.Popup.Visible = $true
}

# Populate Type dropdown (static - AccountType values)
@('User','Privileged','Svc Acct') | ForEach-Object { [void]$script:TypeDD.Clb.Items.Add($_, $false) }

# Populate Department dropdown - scan sonrası doldurulur
function Populate-DeptDropdown {
    $depts = @($script:allRows | Where-Object { $_.Department } |
        Select-Object -ExpandProperty Department | Sort-Object -Unique)
    $script:DeptDD.Clb.Items.Clear()
    foreach ($d in $depts) { [void]$script:DeptDD.Clb.Items.Add($d, $false) }
}

# Button label güncelle (seçim varsa badge göster)
function Update-MultiBtn {
    param($dd, [string]$Key)
    $checked = @($dd.Clb.CheckedItems)
    if ($checked.Count -eq 0) {
        $dd.Btn.Text      = "$Key  ▾"
        $dd.Btn.ForeColor = $script:C.FgSecondary
        $dd.Btn.BackColor = $script:C.BgCard
    } else {
        $dd.Btn.Text      = "$Key ($($checked.Count))  ▾"
        $dd.Btn.ForeColor = $script:C.AccentBlue
        $dd.Btn.BackColor = $script:C.BgSection
    }
}

# CheckedListBox change -> filter
$script:TypeDD.Clb.Add_ItemCheck({
    if ($script:TypeFilterTimer) { try { $script:TypeFilterTimer.Stop(); $script:TypeFilterTimer.Dispose() } catch { }; $script:TypeFilterTimer = $null }
    $script:TypeFilterTimer = New-Object System.Windows.Forms.Timer
    $script:TypeFilterTimer.Interval = 30
    $script:TypeFilterTimer.Add_Tick({
        $tmr = $script:TypeFilterTimer
        if ($tmr) { try { $tmr.Stop(); $tmr.Dispose() } catch { } }
        $script:TypeFilterTimer = $null
        try {
            $script:TypeFilter = @($script:TypeDD.Clb.CheckedItems | ForEach-Object { "$_" })
            Update-MultiBtn $script:TypeDD 'Type'
            if ($script:allRows -and $script:allRows.Count) { Apply-Filters }
        } catch { }
    })
    $script:TypeFilterTimer.Start()
})

$script:DeptDD.Clb.Add_ItemCheck({
    if ($script:DeptFilterTimer) { try { $script:DeptFilterTimer.Stop(); $script:DeptFilterTimer.Dispose() } catch { }; $script:DeptFilterTimer = $null }
    $script:DeptFilterTimer = New-Object System.Windows.Forms.Timer
    $script:DeptFilterTimer.Interval = 30
    $script:DeptFilterTimer.Add_Tick({
        $tmr = $script:DeptFilterTimer
        if ($tmr) { try { $tmr.Stop(); $tmr.Dispose() } catch { } }
        $script:DeptFilterTimer = $null
        try {
            $script:DeptFilter = @($script:DeptDD.Clb.CheckedItems | ForEach-Object { "$_" })
            Update-MultiBtn $script:DeptDD 'Dept'
            if ($script:allRows -and $script:allRows.Count) { Apply-Filters }
        } catch { }
    })
    $script:DeptFilterTimer.Start()
})

# Button clicks
$script:TypeDD.Btn.Add_Click({ Show-MultiDropdown $script:TypeDD 'Type' })
$script:DeptDD.Btn.Add_Click({ Show-MultiDropdown $script:DeptDD 'Dept' })

# Form click -> popup kapat (dışarı tıklayınca)
$form.Add_Click({
    $script:TypeDD.Popup.Visible = $false
    $script:DeptDD.Popup.Visible = $false
})

# ?? STATUS BAR ???????????????????????????????????????????????????????????????
$statusBar        = New-Object System.Windows.Forms.StatusStrip
$statusBar.BackColor  = $C.BgMid
$statusBar.SizingGrip = $false
$statusBar.AutoSize   = $false
$statusBar.Height     = 24
$statusBar.Dock       = 'Bottom'
$statusLabel      = New-Object System.Windows.Forms.ToolStripStatusLabel
$statusLabel.Text     = 'Ready  -  Click DISCOVER to load domains.'
$statusLabel.Spring   = $true
$statusLabel.TextAlign = 'MiddleLeft'
$statusLabel.ForeColor = $C.FgSecondary
$progBar          = New-Object System.Windows.Forms.ToolStripProgressBar
$progBar.Width    = 150
$progBar.Visible  = $false
$statusBar.Items.AddRange(@($statusLabel,$progBar))

# ?? MAIN SPLIT ???????????????????????????????????????????????????????????????
# SplitterDistance + MinSize'lar form Add_Load + Resize'da runtime ayarlanir.
# Burada minimum guvenli default'lar. Property atamalari try icinde.
$mainSplit                  = New-Object System.Windows.Forms.SplitContainer
$mainSplit.Dock             = 'Fill'
try { $mainSplit.Panel1MinSize = 50  } catch { }
try { $mainSplit.Panel2MinSize = 260 } catch { }
try { $mainSplit.IsSplitterFixed = $false } catch { }
try { $mainSplit.Panel2Collapsed = $false } catch { }   # detail visible by default
$mainSplit.BackColor        = $script:C.Splitter

# Grid
$grid                              = New-Object System.Windows.Forms.DataGridView
$grid.Dock                         = 'Fill'
$grid.ReadOnly                     = $true
$grid.AllowUserToAddRows           = $false
$grid.AllowUserToDeleteRows        = $false
$grid.MultiSelect                  = $false
$grid.SelectionMode                = 'FullRowSelect'
$grid.BackgroundColor              = $C.BgGrid
$grid.GridColor                    = $C.Border
$grid.BorderStyle                  = 'None'
$grid.RowHeadersVisible            = $false
$grid.AutoSizeColumnsMode          = 'None'
$grid.AutoSizeRowsMode             = 'None'
$grid.AllowUserToResizeRows        = $false
$grid.ScrollBars                   = 'Both'
$grid.EnableHeadersVisualStyles    = $false
$grid.ColumnHeadersHeight          = 30
$grid.RowTemplate.Height           = 24
$grid.Font                         = $F.UISm
$grid.ForeColor                    = $C.FgPrimary
$grid.DefaultCellStyle.BackColor   = $C.BgGrid
$grid.DefaultCellStyle.ForeColor   = $C.FgPrimary
$grid.DefaultCellStyle.SelectionBackColor = [System.Drawing.Color]::FromArgb(50,90,160)
$grid.DefaultCellStyle.SelectionForeColor = [System.Drawing.Color]::White
$grid.AlternatingRowsDefaultCellStyle.BackColor = $C.BgRowAlt
$grid.ColumnHeadersDefaultCellStyle.BackColor   = $C.BgMid
$grid.ColumnHeadersDefaultCellStyle.ForeColor   = $C.FgSecondary
$grid.ColumnHeadersDefaultCellStyle.Font        = $F.UIBold
$grid.ColumnHeadersDefaultCellStyle.SelectionBackColor = $C.BgMid

# DoubleBuffered via reflection - flicker/lag fix
try {
    $dgvType = $grid.GetType()
    $prop = $dgvType.GetProperty('DoubleBuffered',
        [System.Reflection.BindingFlags]::Instance -bor
        [System.Reflection.BindingFlags]::NonPublic)
    if ($prop) { $prop.SetValue($grid, $true, $null) }
} catch { }

$lblEmpty         = New-Object System.Windows.Forms.Label
$lblEmpty.Text    = "No data - Run a scan first."
$lblEmpty.Dock    = 'Fill'
$lblEmpty.TextAlign = 'MiddleCenter'
$lblEmpty.Font    = New-Object System.Drawing.Font('Segoe UI', 13)
$lblEmpty.ForeColor = $C.FgMuted
$lblEmpty.BackColor = $C.BgGrid
$lblEmpty.Visible   = $true

$mainSplit.Panel1.BackColor = $C.BgGrid
$mainSplit.Panel1.Controls.AddRange(@($grid, $lblEmpty))

# Detail Panel
$detailOuter      = New-Object System.Windows.Forms.Panel
$detailOuter.Dock = 'Fill'
$detailOuter.BackColor = $C.BgDetail
$detailOuter.Padding   = New-Object System.Windows.Forms.Padding(0)

# Rich header panel - username + risk badge (SOC side-panel hissi)
$detailHdrPanel   = New-Object System.Windows.Forms.Panel
$detailHdrPanel.Dock   = 'Top'
$detailHdrPanel.Height = 64
$detailHdrPanel.BackColor = $C.BgMid

# Sol accent bar - risk rengini yansitir
$detailHdrAccent  = New-Object System.Windows.Forms.Panel
$detailHdrAccent.Location = New-Object System.Drawing.Point(0, 0)
$detailHdrAccent.Size     = New-Object System.Drawing.Size(4, 64)
$detailHdrAccent.BackColor = $C.AccentBlue

# Username (buyuk)
$lblDetailUser    = New-Object System.Windows.Forms.Label
$lblDetailUser.Text = 'ACCOUNT DETAIL'
$lblDetailUser.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 12, [System.Drawing.FontStyle]::Bold)
$lblDetailUser.ForeColor = $C.FgPrimary
$lblDetailUser.AutoSize  = $false
$lblDetailUser.Location  = New-Object System.Drawing.Point(16, 10)
$lblDetailUser.Size      = New-Object System.Drawing.Size(220, 24)
$lblDetailUser.AutoEllipsis = $true

# Alt satir - display name / department
$lblDetailMeta    = New-Object System.Windows.Forms.Label
$lblDetailMeta.Text = 'Select a user from the grid'
$lblDetailMeta.Font = New-Object System.Drawing.Font('Segoe UI', 8.5)
$lblDetailMeta.ForeColor = $C.FgSecondary
$lblDetailMeta.AutoSize  = $false
$lblDetailMeta.Location  = New-Object System.Drawing.Point(16, 36)
$lblDetailMeta.Size      = New-Object System.Drawing.Size(240, 20)
$lblDetailMeta.AutoEllipsis = $true

# Risk badge (sag ust)
$lblDetailRisk    = New-Object System.Windows.Forms.Label
$lblDetailRisk.Text = ''
$lblDetailRisk.Font = New-Object System.Drawing.Font('Segoe UI Semibold', 8.5, [System.Drawing.FontStyle]::Bold)
$lblDetailRisk.ForeColor = $C.FgPrimary
$lblDetailRisk.BackColor = $C.BgCard
$lblDetailRisk.TextAlign = 'MiddleCenter'
$lblDetailRisk.Size      = New-Object System.Drawing.Size(74, 22)
$lblDetailRisk.Location  = New-Object System.Drawing.Point(180, 11)
$lblDetailRisk.Anchor    = [System.Windows.Forms.AnchorStyles]::Top -bor [System.Windows.Forms.AnchorStyles]::Right
$lblDetailRisk.Visible   = $false

$detailHdrPanel.Controls.AddRange(@($detailHdrAccent, $lblDetailUser, $lblDetailMeta, $lblDetailRisk))

$txtDetail        = New-Object System.Windows.Forms.RichTextBox
$txtDetail.Dock   = 'Fill'
$txtDetail.ReadOnly = $true
$txtDetail.BackColor = $C.BgDetail
$txtDetail.ForeColor = $C.FgPrimary
$txtDetail.Font   = $F.UI
$txtDetail.BorderStyle = 'None'
$txtDetail.Text   = ""
$txtDetail.ScrollBars = 'Vertical'
$txtDetail.DetectUrls = $false
$txtDetail.WordWrap   = $true

$detailOuter.Controls.AddRange(@($txtDetail, $detailHdrPanel))
$mainSplit.Panel2.Controls.Add($detailOuter)

# ?? FORM ASSEMBLY ????????????????????????????????????????????????????????????
# WinForms dock rule: Controls.Add'te SON eklenen kontrol z-order'da en USTTE.
# Top/Bottom dock'lar onceki ekleyenlerin "icine" doner. Fill kontrol EN SON eklenmeli
# ki Top/Bottom dock'lardan ARTAN alani alsin (yoksa Fill statusBar/topBar uzerine taspar).
$form.Controls.Add($mainSplit)    # Fill - last to claim remaining area visually
$form.Controls.Add($statusBar)    # Bottom

# Update notification button
$btnUpdateNotify             = New-Object System.Windows.Forms.Button
$btnUpdateNotify.Text        = ''
$btnUpdateNotify.Font        = New-Object System.Drawing.Font('Segoe UI', 8, [System.Drawing.FontStyle]::Bold)
$btnUpdateNotify.ForeColor   = [System.Drawing.Color]::FromArgb(255, 210, 60)
$btnUpdateNotify.BackColor   = [System.Drawing.Color]::FromArgb(80, 55, 0)
$btnUpdateNotify.FlatStyle   = 'Flat'
$btnUpdateNotify.FlatAppearance.BorderSize = 0
$btnUpdateNotify.Dock        = 'Bottom'
$btnUpdateNotify.Height      = 22
$btnUpdateNotify.TextAlign   = 'MiddleCenter'
$btnUpdateNotify.Visible     = $false
$btnUpdateNotify.Cursor      = [System.Windows.Forms.Cursors]::Hand
$form.Controls.Add($btnUpdateNotify)
$form.Controls.Add($filterBar)    # Top (added last among Tops -> nearest to grid)
$form.Controls.Add($cardBar)      # Top
$form.Controls.Add($topBar)       # Top (added last -> topmost visually)

# ====================================================================
# STATE
# ====================================================================
$script:domains      = @()
$script:allRows      = @()
$script:filteredRows = @()

# ====================================================================
# HELPERS
# ====================================================================
function Set-Status {
    param([string]$Text, [bool]$Progress = $false)
    $statusLabel.Text = $Text
    $progBar.Visible  = $Progress
    [System.Windows.Forms.Application]::DoEvents()
}

function Set-Card { param([string]$Key, [int]$Val)
    if ($script:metricLabels.ContainsKey($Key)) { $script:metricLabels[$Key].Text = $Val.ToString() }
}

function Reset-Cards {
    foreach ($k in $script:metricLabels.Keys) { $script:metricLabels[$k].Text = '-' }
}

# ====================================================================
# GRID COLUMNS
# ====================================================================
function Initialize-Columns {
    $grid.Columns.Clear()
    $defs = @(
        @{N='RiskLevel';       H='Risk';         W=72  }
        @{N='RiskScore';       H='Score';        W=55  }
        @{N='SamAccountName';  H='Username';     W=130 }
        @{N='DisplayName';     H='Display Name'; W=148 }
        @{N='AccountType';     H='Type';         W=82  }
        @{N='InactiveDays';    H='Inactive Days';W=100 }
        @{N='LastLogon';       H='Last Logon';   W=105 }
        @{N='VPN';             H='VPN';          W=50  }
        @{N='MFA';             H='MFA';          W=50  }
        @{N='RemoteAcc';       H='RemoteAcc';    W=78  }
        @{N='VPNRisk';         H='VPN Risk';     W=78  }
        @{N='PwdAgeDays';      H='Pwd Age (d)';  W=90  }
        @{N='Department';      H='Department';   W=115 }
        @{N='Enabled';         H='Enabled';      W=62  }
        @{N='AdminCount';      H='AdminCnt';     W=72  }
        @{N='WhenCreated';     H='Created';      W=98  }
        @{N='Mail';            H='Mail';         W=160 }
    )
    foreach ($d in $defs) {
        $col = New-Object System.Windows.Forms.DataGridViewTextBoxColumn
        $col.Name = $d.N; $col.HeaderText = $d.H; $col.Width = $d.W
        $col.SortMode = 'Automatic'
        $col.DefaultCellStyle.Padding = New-Object System.Windows.Forms.Padding(4,0,4,0)
        [void]$grid.Columns.Add($col)
    }
}

# ====================================================================
# BUILD ROW OBJECT
# ====================================================================
function New-UserRow {
    param($u, [datetime]$Now)
    $neverLogon  = ($u.LastLogonDate -eq $null)
    $inactiveDays = if ($neverLogon) { [int]($Now - $u.WhenCreated).TotalDays }
                    else             { [int]($Now - $u.LastLogonDate).TotalDays }
    $pwdAge = if ($u.PasswordLastSet) { [int]($Now - $u.PasswordLastSet).TotalDays } else { 9999 }

    $memberOfFlat = @()
    if ($u.MemberOf) {
        $memberOfFlat = @($u.MemberOf | ForEach-Object {
            if ($_ -match '^CN=([^,]+)') { $Matches[1] } else { $_ }
        })
    }

    $spnCount = if ($u.ServicePrincipalName) { $u.ServicePrincipalName.Count } else { 0 }

    $r = [PSCustomObject]@{
        SamAccountName    = $u.SamAccountName
        DisplayName       = $u.DisplayName
        Enabled           = $u.Enabled
        Department        = $u.Department
        Mail              = $u.Mail
        Description       = $u.Description
        DistinguishedName = $u.DistinguishedName
        AdminCount        = $u.AdminCount
        SPNCount          = $spnCount
        WhenCreated       = if ($u.WhenCreated)    { $u.WhenCreated.ToString('yyyy-MM-dd')    } else { '-' }
        LastLogon         = if ($neverLogon)        { 'NEVER' }
                            else                    { $u.LastLogonDate.ToString('yyyy-MM-dd') }
        PwdLastSet        = if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'NEVER SET' }
        PwdAgeDays        = $pwdAge
        InactiveDays      = $inactiveDays
        NeverLoggedIn     = $neverLogon
        MemberOfFlat      = $memberOfFlat
        MatchedGroups     = @{ vpn=@(); mfa=@(); remoteAccess=@(); privileged=@(); serviceAccount=@() }
        IsServiceAccount  = $false
        IsPrivileged      = $false
        AccountType       = 'User'
        RiskScore         = 0
        RiskLevel         = 'LOW'
        HasVPNAccess      = $false
        HasMFA            = $false
        HasRemoteAccess   = $false
        VPNGroups         = @()
        MFAGroups         = @()
        RAGroups          = @()
        VPNRisk           = 'NONE'
    }

    # Config-driven group matching (groups exact > regex fallback, isEnabled gated)
    $matched = $null
    try { $matched = Get-MatchedGroupsByCategory -MemberOfFlat $memberOfFlat } catch { }
    if (-not $matched) {
        $matched = @{ vpn=@(); mfa=@(); remoteAccess=@(); privileged=@(); serviceAccount=@() }
    }
    $r.MatchedGroups   = $matched
    $r.VPNGroups       = @(if ($matched.vpn)          { $matched.vpn          } else { @() })
    $r.MFAGroups       = @(if ($matched.mfa)          { $matched.mfa          } else { @() })
    $r.RAGroups        = @(if ($matched.remoteAccess) { $matched.remoteAccess } else { @() })
    $r.HasVPNAccess    = ($r.VPNGroups.Count -gt 0)
    $r.HasMFA          = ($r.MFAGroups.Count -gt 0)
    $r.HasRemoteAccess = ($r.RAGroups.Count  -gt 0)

    $r.IsServiceAccount = Test-IsServiceAccount $r
    $r.IsPrivileged     = Test-IsPrivileged     $r
    $r.AccountType      = if ($r.IsServiceAccount) { 'Svc Acct' }
                          elseif ($r.IsPrivileged)  { 'Privileged' }
                          else                      { 'User' }

    # VPNRisk: dormant + remote access capability classification
    $r.VPNRisk = if ($r.HasVPNAccess -and $r.NeverLoggedIn)              { 'CRITICAL' }
                 elseif ($r.HasVPNAccess -and -not $r.HasMFA)            { 'HIGH'     }
                 elseif ($r.HasVPNAccess -and $r.InactiveDays -ge 60)    { 'HIGH'     }
                 elseif ($r.HasVPNAccess -or $r.HasRemoteAccess)         { 'MEDIUM'   }
                 else                                                    { 'NONE'     }

    $r.RiskScore = Get-RiskScore $r
    $r.RiskLevel = Get-RiskLevel -Score $r.RiskScore -IsSA $r.IsServiceAccount -Disabled (-not $r.Enabled)
    return $r
}

# ====================================================================
# POPULATE GRID
# ====================================================================
function Update-Grid {
    # WM_SETREDRAW = 0x000B - native repaint disable (StrongerFlickerSuppression)
    try { [PInvoke.Win32MsgHelper]::SendMessage($grid.Handle, 0x000B, 0, [System.IntPtr]::Zero) | Out-Null } catch { }
    $grid.SuspendLayout()

    # Preserve current sort state (so filter changes don't reset user's column sort)
    $sortCol = $null
    $sortDir = 'Descending'
    if ($grid.SortedColumn) {
        $sortCol = $grid.SortedColumn.Name
        $sortDir = $grid.SortOrder
    }

    $grid.Rows.Clear()

    # Default sort: InactiveDays ASC (en dusuk sayi ustte, 0'dan baslar).
    # Risk header'a tiklanirsa SortCompare devreye girer (CRITICAL>...>DISABLED).
    $sorted = $script:filteredRows | Sort-Object InactiveDays

    foreach ($r in $sorted) {
        $vpnTxt = if ($r.HasVPNAccess)    { 'YES' } else { '-' }
        $mfaTxt = if ($r.HasMFA)          { 'YES' } else { '-' }
        $raTxt  = if ($r.HasRemoteAccess) { 'YES' } else { '-' }

        $idx = $grid.Rows.Add(
            $r.RiskLevel, $r.RiskScore, $r.SamAccountName, $r.DisplayName,
            $r.AccountType, $r.InactiveDays, $r.LastLogon,
            $vpnTxt, $mfaTxt, $raTxt, $r.VPNRisk,
            $r.PwdAgeDays, $r.Department, $(if ($r.Enabled) {'Yes'} else {'No'}),
            $r.AdminCount, $r.WhenCreated, $r.Mail
        )
        $row = $grid.Rows[$idx]
        $row.DefaultCellStyle.BackColor = Get-RowBg $r.RiskLevel
        $row.DefaultCellStyle.ForeColor = $C.FgPrimary
        $row.Cells['RiskLevel'].Style.ForeColor = Get-RiskColor $r.RiskLevel
        $row.Cells['RiskLevel'].Style.Font      = $F.UIBold
        $scoreColor = if ($r.RiskScore -ge 80) { $C.RiskCritical }
                      elseif ($r.RiskScore -ge 55) { $C.RiskHigh }
                      elseif ($r.RiskScore -ge 30) { $C.RiskMedium }
                      else { $C.RiskLow }
        $row.Cells['RiskScore'].Style.ForeColor = $scoreColor

        # VPN / MFA / RemoteAcc badge colors
        if ($r.HasVPNAccess) {
            $row.Cells['VPN'].Style.ForeColor = $C.RiskHigh
            $row.Cells['VPN'].Style.Font      = $F.UIBold
        } else { $row.Cells['VPN'].Style.ForeColor = $C.FgMuted }

        if ($r.HasMFA) {
            $row.Cells['MFA'].Style.ForeColor = $C.RiskLow
            $row.Cells['MFA'].Style.Font      = $F.UIBold
        } elseif ($r.HasVPNAccess) {
            $row.Cells['MFA'].Style.ForeColor = $C.RiskCritical  # VPN without MFA
            $row.Cells['MFA'].Style.Font      = $F.UIBold
        } else { $row.Cells['MFA'].Style.ForeColor = $C.FgMuted }

        if ($r.HasRemoteAccess) {
            $row.Cells['RemoteAcc'].Style.ForeColor = $C.RiskHigh
            $row.Cells['RemoteAcc'].Style.Font      = $F.UIBold
        } else { $row.Cells['RemoteAcc'].Style.ForeColor = $C.FgMuted }

        $vpnRiskColor = switch ($r.VPNRisk) {
            'CRITICAL' { $C.RiskCritical }
            'HIGH'     { $C.RiskHigh     }
            'MEDIUM'   { $C.RiskMedium   }
            default    { $C.FgMuted      }
        }
        $row.Cells['VPNRisk'].Style.ForeColor = $vpnRiskColor
        if ($r.VPNRisk -ne 'NONE') { $row.Cells['VPNRisk'].Style.Font = $F.UIBold }

        $row.Tag = $r
    }

    $lblEmpty.Visible = ($grid.Rows.Count -eq 0)

    # Re-apply user's column sort if any (preserves header click sorting across filter changes)
    if ($sortCol -and $grid.Columns[$sortCol]) {
        try {
            $direction = if ($sortDir -eq 'Ascending') {
                [System.ComponentModel.ListSortDirection]::Ascending
            } else {
                [System.ComponentModel.ListSortDirection]::Descending
            }
            $grid.Sort($grid.Columns[$sortCol], $direction)
        } catch { }
    }

    $grid.ResumeLayout()
    try {
        [PInvoke.Win32MsgHelper]::SendMessage($grid.Handle, 0x000B, 1, [System.IntPtr]::Zero) | Out-Null
        $grid.Refresh()
    } catch { }

    # Tek satir kaldiysa otomatik sec
    if (Get-Command Select-FirstRowIfSingle -ErrorAction SilentlyContinue) {
        Select-FirstRowIfSingle
    }
}

# ====================================================================
# FILTER
# ====================================================================
function Apply-Filters {
    $rf     = $cboRisk.SelectedItem
    $srch   = $txtSearch.Text.Trim().ToLower()
    # Placeholder text'i search olarak alma
    if ($srch -eq $script:SearchPlaceholder.Trim().ToLower()) { $srch = '' }

    # Card filter aktifse predicate'i BASE olarak kullan,
    # üstüne checkbox/risk/search AND olarak eklenir (exclusive değil)
    $script:filteredRows = @($script:allRows | Where-Object {
        $r = $_

        # Card predicate (base scope)
        if ($script:ActiveCardFilter -and $script:CardPredicates.ContainsKey($script:ActiveCardFilter)) {
            $pred = $script:CardPredicates[$script:ActiveCardFilter]
            if (-not (& $pred $r)) { return $false }
        }

        # Type multi-select
        if ($script:TypeFilter -and $script:TypeFilter.Count -gt 0) {
            if ($r.AccountType -notin $script:TypeFilter) { return $false }
        }
        # Department multi-select
        if ($script:DeptFilter -and $script:DeptFilter.Count -gt 0) {
            if ($r.Department -notin $script:DeptFilter) { return $false }
        }
        if ($rf -ne 'All Risk Levels' -and $r.RiskLevel -ne $rf) { return $false }
        if ($chkPrivOnly.Checked  -and -not $r.IsPrivileged)     { return $false }
        if ($chkNeverOnly.Checked -and -not $r.NeverLoggedIn)    { return $false }
        if ($chkHideSA.Checked    -and $r.IsServiceAccount)      { return $false }
        if ($chkHideDis.Checked   -and -not $r.Enabled)          { return $false }
        if ($script:VPNFilter    -eq 'Yes' -and -not $r.HasVPNAccess)    { return $false }
        if ($script:VPNFilter    -eq 'No'  -and $r.HasVPNAccess)         { return $false }
        if ($script:MFAFilter    -eq 'Yes' -and -not $r.HasMFA)          { return $false }
        if ($script:MFAFilter    -eq 'No'  -and $r.HasMFA)               { return $false }
        if ($script:RemoteFilter -eq 'Yes' -and -not $r.HasRemoteAccess) { return $false }
        if ($script:RemoteFilter -eq 'No'  -and $r.HasRemoteAccess)      { return $false }
        if ($srch) {
            $hay = "$($r.SamAccountName) $($r.DisplayName) $($r.Department) $($r.Mail) $($r.DistinguishedName)".ToLower()
            if ($hay -notlike "*$srch*") { return $false }
        }
        return $true
    })
    Update-Grid
    $tag = if ($script:ActiveCardFilter) { " [card: $($script:ActiveCardFilter)]" } else { '' }
    Set-Status "Showing $($script:filteredRows.Count) of $($script:allRows.Count) accounts$tag"
}

# ====================================================================
# EXPORT
# ====================================================================
function Get-WhyFlagged {
    param($r)
    $w = @()
    if ($r.NeverLoggedIn)            { $w += 'NeverLogon' }
    if ($r.InactiveDays -ge 90)      { $w += "Inactive$($r.InactiveDays)d" }
    elseif ($r.InactiveDays -ge 60)  { $w += "Inactive$($r.InactiveDays)d" }
    elseif ($r.InactiveDays -ge 30)  { $w += "Inactive$($r.InactiveDays)d" }
    if ($r.PwdAgeDays -ge 365)       { $w += "PwdAge$($r.PwdAgeDays)d" }
    elseif ($r.PwdAgeDays -ge 180)   { $w += "PwdAge$($r.PwdAgeDays)d" }
    if ($r.IsPrivileged)             { $w += 'Privileged' }
    if ($r.AdminCount -eq 1)         { $w += 'AdminCount=1' }
    if ($r.HasVPNAccess)             { $w += 'VPN' }
    if ($r.HasRemoteAccess)          { $w += 'RemoteAcc' }
    if ($r.HasVPNAccess -and -not $r.HasMFA) { $w += 'VPN-NoMFA' }
    if ($r.IsServiceAccount)         { $w += 'SvcAcct' }
    if (-not $r.Enabled)             { $w += 'Disabled' }
    if ($w.Count -eq 0) { return 'LowRisk' }
    return ($w -join '; ')
}

function ConvertTo-ExportRow {
    param($r)
    return [PSCustomObject][ordered]@{
        RiskLevel    = $r.RiskLevel
        RiskScore    = $r.RiskScore
        Username     = $r.SamAccountName
        DisplayName  = $r.DisplayName
        AccountType  = $r.AccountType
        InactiveDays = $r.InactiveDays
        LastLogon    = $r.LastLogon
        VPN          = if ($r.HasVPNAccess)    { 'YES' } else { 'NO' }
        MFA          = if ($r.HasMFA)          { 'YES' } else { 'NO' }
        RemoteAccess = if ($r.HasRemoteAccess) { 'YES' } else { 'NO' }
        VPNRisk      = $r.VPNRisk
        PwdAgeDays   = $r.PwdAgeDays
        Department   = $r.Department
        Enabled      = if ($r.Enabled) { 'Yes' } else { 'No' }
        AdminCount   = $r.AdminCount
        Mail         = $r.Mail
        WhyFlagged   = Get-WhyFlagged $r
    }
}

function Get-CurrentFilteredView {
    # Grid sort order: RiskOrder asc, RiskScore desc
    $sorted = $script:filteredRows | Sort-Object { Get-RiskOrder $_.RiskLevel }, { -[int]$_.RiskScore }
    return @($sorted | ForEach-Object { ConvertTo-ExportRow $_ })
}

function Get-ExportPath {
    param([string]$Ext, [string]$Filter)
    $dom = if ($cboDomain.SelectedItem) { ($cboDomain.SelectedItem -replace '[^\w\.-]','_') } else { 'export' }
    $ts  = Get-Date -Format 'yyyyMMdd_HHmmss'
    $exportDir = Join-Path $script:BasePath 'exports'
    if (-not (Test-Path $exportDir)) { New-Item -ItemType Directory -Path $exportDir -Force | Out-Null }
    $sfd = New-Object System.Windows.Forms.SaveFileDialog
    $sfd.Filter           = $Filter
    $sfd.FileName         = "ADDetector_${dom}_${ts}.$Ext"
    $sfd.Title            = "Export $($Ext.ToUpper())"
    $sfd.InitialDirectory = $exportDir
    if ($sfd.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) { return $null }
    return $sfd.FileName
}

function Export-HTML-Report {
    if (-not $script:allRows -or $script:allRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('No data to export.','ADDetector','OK','Information') | Out-Null; return
    }
    $path = Get-ExportPath 'html' 'HTML Report|*.html'
    if (-not $path) { return }
    try {
        Set-Status "Generating HTML report..." $true
        Write-AppLog -Component 'Export' -Message "HTML report start | path=$path"
        $domain    = if ($cboDomain.SelectedItem) { $cboDomain.SelectedItem } else { 'Unknown' }
        $scanDate  = Get-Date -Format 'dd.MM.yyyy HH:mm'
        $allRows   = $script:allRows
        $total     = $allRows.Count
        $enabled   = @($allRows | Where-Object { $_.Enabled }).Count
        $disabled  = $total - $enabled
        $critical  = @($allRows | Where-Object { $_.RiskLevel -eq 'CRITICAL' }).Count
        $high      = @($allRows | Where-Object { $_.RiskLevel -eq 'HIGH' }).Count
        $medium    = @($allRows | Where-Object { $_.RiskLevel -eq 'MEDIUM' }).Count
        $low       = @($allRows | Where-Object { $_.RiskLevel -eq 'LOW' }).Count
        $inactive  = @($allRows | Where-Object { $_.InactiveDays -ge 30 }).Count
        $neverLogin= @($allRows | Where-Object { $_.NeverLoggedIn }).Count
        $privInact = @($allRows | Where-Object { $_.IsPrivileged -and $_.InactiveDays -ge 30 }).Count
        $vpnNoMFA  = @($allRows | Where-Object { $_.HasVPNAccess -and -not $_.HasMFA }).Count
        $dormantVPN= @($allRows | Where-Object { $_.HasVPNAccess -and $_.InactiveDays -ge 30 }).Count
        $svcAcc    = @($allRows | Where-Object { $_.IsServiceAccount }).Count
        $i0_30  = @($allRows | Where-Object { $_.InactiveDays -ge 0   -and $_.InactiveDays -lt 30  }).Count
        $i30_90 = @($allRows | Where-Object { $_.InactiveDays -ge 30  -and $_.InactiveDays -lt 90  }).Count
        $i90_180= @($allRows | Where-Object { $_.InactiveDays -ge 90  -and $_.InactiveDays -lt 180 }).Count
        $i180p  = @($allRows | Where-Object { $_.InactiveDays -ge 180 }).Count
        $top20 = $allRows | Sort-Object { Get-RiskOrder $_.RiskLevel }, { -[int]$_.RiskScore } | Select-Object -First 20
        $top20Rows = ''
        foreach ($r in $top20) {
            $riskColor = switch ($r.RiskLevel) { 'CRITICAL' { '#e74c3c' } 'HIGH' { '#e67e22' } 'MEDIUM' { '#f1c40f' } default { '#2ecc71' } }
            $vpnTd = if ($r.HasVPNAccess) { '<span class="yes">YES</span>' } else { '<span class="no">-</span>' }
            $mfaTd = if ($r.HasMFA)       { '<span class="yes">YES</span>' } else { '<span class="no">NO</span>' }
            $why = (Get-WhyFlagged $r) -replace '<','&lt;' -replace '>','&gt;'
            $top20Rows += "<tr><td><span class='badge' style='background:$riskColor'>$($r.RiskLevel)</span></td><td><b>$($r.SamAccountName)</b></td><td>$($r.DisplayName)</td><td>$($r.AccountType)</td><td>$($r.InactiveDays)d</td><td>$vpnTd</td><td>$mfaTd</td><td>$($r.RiskScore)</td><td style='font-size:11px;color:#aaa'>$why</td></tr>"
        }
        $maxBar = [Math]::Max(1, [Math]::Max($critical, [Math]::Max($high, [Math]::Max($medium, $low))))
        $wCrit = [int](($critical / $maxBar) * 300)
        $wHigh = [int](($high    / $maxBar) * 300)
        $wMed  = [int](($medium  / $maxBar) * 300)
        $wLow  = [int](($low     / $maxBar) * 300)
        $maxInact = [Math]::Max(1, [Math]::Max($i0_30, [Math]::Max($i30_90, [Math]::Max($i90_180, $i180p))))
        $wi0  = [int](($i0_30   / $maxInact) * 300)
        $wi1  = [int](($i30_90  / $maxInact) * 300)
        $wi2  = [int](($i90_180 / $maxInact) * 300)
        $wi3  = [int](($i180p   / $maxInact) * 300)
        $logoB64 = '/9j/4AAQSkZJRgABAQAAAQABAAD/4gHYSUNDX1BST0ZJTEUAAQEAAAHIAAAAAAQwAABtbnRyUkdCIFhZWiAH4AABAAEAAAAAAABhY3NwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAA9tYAAQAAAADTLQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAlkZXNjAAAA8AAAACRyWFlaAAABFAAAABRnWFlaAAABKAAAABRiWFlaAAABPAAAABR3dHB0AAABUAAAABRyVFJDAAABZAAAAChnVFJDAAABZAAAAChiVFJDAAABZAAAAChjcHJ0AAABjAAAADxtbHVjAAAAAAAAAAEAAAAMZW5VUwAAAAgAAAAcAHMAUgBHAEJYWVogAAAAAAAAb6IAADj1AAADkFhZWiAAAAAAAABimQAAt4UAABjaWFlaIAAAAAAAACSgAAAPhAAAts9YWVogAAAAAAAA9tYAAQAAAADTLXBhcmEAAAAAAAQAAAACZmYAAPKnAAANWQAAE9AAAApbAAAAAAAAAABtbHVjAAAAAAAAAAEAAAAMZW5VUwAAACAAAAAcAEcAbwBvAGcAbABlACAASQBuAGMALgAgADIAMAAxADb/2wBDAAUDBAQEAwUEBAQFBQUGBwwIBwcHBw8LCwkMEQ8SEhEPERETFhwXExQaFRERGCEYGh0dHx8fExciJCIeJBweHx7/2wBDAQUFBQcGBw4ICA4eFBEUHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh7/wAARCAJTCWADASIAAhEBAxEB/8QAHQABAAICAwEBAAAAAAAAAAAAAAYHBQgCAwQBCf/EAGAQAAEDAgMDBQkICRAKAgIDAQABAgMEBQYHERIhMRMiQVFhCBQycYGRobHRFRYjQlKTssFDU1ZicnOSlOEXGCQlMzQ3RlSCg6KzwtLwJzU2RFVjZHR1hCZlRfEoo+Ly/8QAGwEBAAEFAQAAAAAAAAAAAAAAAAUCAwQGBwH/xABAEQACAgEBBAUICAYCAgMBAAAAAQIDBBEFEiExBhNBUXEUIjJSYZGhsRYzNFOBwdHwFSM1QnLhQ/EkgiVikqL/2gAMAwEAAhEDEQA/ANMgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD6iarogB8BKcFZf4rxjVtp7DaKiq1XnSI3Rje1XLuQ2Oy47lOhp0jrscXflnJzlo6VdGeJz/YXYUznyRh5O0MfG9OXHu7TUnZds7Wyuz16bj4fofj/AAdlvYsDW6kksFtgtjpeT2uQRVXVF3q7wujiUdizuf8ADt2hdcMI3Pvbb3tic/biXxO4oZMdn2zjrDj7O0j1t/HjLS1OKfJ9hrCCZYwy2xRhiZzbhb5Ej15srU2mO8qbiIzQSxO0exUUxJ1zg9JLQl6r67o71ck0dYAKC6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAfURV4Hoo6Kpq5mxQRPke5dEa1NVUHjaXM8x3RUs8ngRuXyF0Za9z1jPEqxVNVSe5dE7RVmqubu7G8VNlMBZF4Gwk2Oor4ku1a1E51QnMRexnt1MivGnMisvbGPj8E9X7DUDL/J3G+M52e5tqkjplXnVM/MjTyrx8hsllz3MuFrEkdbiqqW7VLUR3JN5kKL29LvQXotXHFEkNJCyKNqaNRG6IniROB45pFkXV7lcvapKUbPiuMjVs3b+Rdwg91ez9RRpbrRRNorPQQU1OxNGsiYjGJ5E4njrKieZFWSRXJ1a7jsk0U80yc1dCRjTGK4Gu2WTk9WzBZ3t5bK+2Ncmqcu3X8lSlbRWVtq2paCpkgXdqiLzV39KcC8s3W7eWdBu10mZ6lKOkZs0zl06vWRcG1ZqjZa2pUaS4kpo8bxTQLS32jjljfuc5jNpFTtapgcSZYYOxXE+rsk8VJUO3qke9mva3ihgqk8kVXUUtQktPK+JycHNdopIO+M1u3LVGJXjzqlv48nF/D3EDxnlRf7Cr5H0jpqdOE0KbTfLpw8pXtZQzU71R7FTyG01px5WRNSG4MbVR8FXg7T1KfLvhnA+M43OjbHR1juKx6Ndr2t4L5DCt2bXZxpf4Ml8fb19HDKhw70angtnG2TN9tiPqLY1twgTfrF4SJ2oVfWUNXRyuiqaeSJ7V0VHN00Iq7Gtpek1obLi51GVHeqkmeYDQFgywAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD2W+21ldM2Kmgklc7gjGqqlu4C7njG+JWRzy0PubSu0XlavmbuxvFSuMJS5IsXZNVK1nLQpZN5n8K4PxFierbTWW01VY9y6fBxqqJ41NxsD9zTgbDzI6m/yvu9Um/ZeuxFr+DxUtm3QWizUiUllttNRwt3I2KNGJ5kMyrBnPmQWX0hrrWlS1ftNXsvO5buVSyOqxbXsoI+KwQ6Pk8SrwQv7BeXeBcFxNS0WeB9S1N9RK1JJFXr1XcnkJBPPJKvPeqp1dB0q5U3IS1OBCBquZtjJyeEpcO5GQkr5XbmrsJ2cTyyTarqqrqedXHBXdZmxqjEi3bJnesmvScVenSfIKeoqP3Ni7Pyl3Iee/XLD+GaRau/3WCBqJqjFdzneJvFSmy2EFxZXVVZY9Ej1RxvndpE1z9Orgh9ua2mzUTq6/XKno4GpvV79lF7OtfIUvjHP9+y+kwjQNgjTclTUt3r2ozgnlKUxTiW7X+rfVXevmrJV6ZHKqJ4k4IR1ua3wiTuLsaUuNnA2IxBnXl/cnph58VU+hRdEqHxfB6p1b9fKYquw1bbvROrMM3OGpidv5PbRU8/FPKa0LMm0u5NNeoyVlvtfa6ls9vqpaaRF3OjcqFirKS4TWpIX7J7aZNP28iybzQVtumWKsppYnffN3L4lMPJx4KZzD+a6VMLaLFNBHWQruWVjE2k7VTp8mhJG4ew5iOnWqw1cotpU1WF6708nFDIThZ6LI+U7MfhdHT2riitpE366KcGyvjdtIqpou5UJFfMP3C2SKlVTOanQ9N7V8pgZo9NU0KXrEyq7YWLhxM9ZMZ3OhRrJH98xJ8WTj5FM1WSYLxfDyV2oo4Z3JptuRGu17HJx8pXcrVTXQ4JNJH1qXoZktN2XFe0szwISlv1vdl3rgezFeSG0x1Rh+sbOxd6RyKiL5F4KVLiLCl6sc7oq+hmiVOlW7lLitOJLhbnJ3vUPYnSxd7V8hLaXG1ruVP3rfbeyVi7lcjEc3zKWp4mNf6L3X8DMp2ln4nCxdZH3M1TVFRdFTRT4bI3/ACwwdiSN1TY6ptLMu/ZYurfNxQqvFWVmJbJtyMp++4E+PDzt3anEj79m30rXTVd6JrE25iZD3dd2Xc+BAgdtRBNA9WTRuY5OKKmh1GAS6evIAAHoAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB30lHVVciR00Ekr14I1uqqWTgrIrMPE+xJDZ30dM77NVLybdPLvUqjCUuSLNuRVStbJJFXndT00879mGJ716mpqbdYM7lOy0jWVGKr4+ocm90NMmy38pd/oLlwrgbLnCkbYrVYaNHcFlfFyjvynfUZUMKyXMhr+kONDhDifnE+jqGOVr43NVOhUL07mvKTCGP6eeovF5nbV0ztX0EaI1yt+VqvR4id585XU1mvy3q20rFtda7a3JuhfxVviXihBsMy1uFL5TXmzIkNTA7VURd0jelq9aKewx3GWrWqF20fKKP5Ut1s2lwtgzBWDImx2SxU8czdyyqzakVe1y/UZqou1S/msVIm/e8fOYfDN+osX4ehvVu5r1TZqIdd8b04tX/ADvQ7ntUnceqprVI0TJuvU2pt6nc6oc5dVcqqvSqnzlteKqeZdpDnDFPMukUTn+LgnlMzSMUYm9KR3baKvE5pqu5NVVehD5Uw0dspVrLzcIKOBu9VfIjU86/UQDE+eWFLIjoMP0sl1qUXTbTmR/lLvXzGJblwhyM7HwbrnwRZdPbaiXe5vJt63cfMYDE2MsGYWRzay4Mq6xvCCFUe7Xybk8pr/ijNXF+JldHPXLRUjv93pV2G6dSrxXykXjjqJ5ERjZHveumiaqq+0wJ5c58iZr2XXX6ZY2OM8MQ1zX09ggjtMC6okmu3MqePgnkKgrqu5XSsdUV9VPVTOXVXyPVyr5y1sI5NYjvz2VVa33LouKy1KaO07G8fPoWph7BOXuD2tlSnS93Bv2WVEViL2JwT0mK42WMkI3Y+LHgtChsE5XYqxU5j6agfT0i8amo5jETs6V8hbdoyXwnZ7Hc31tQl1ucFI9yqq8yNdldFRE+slt4xLW1kfIxObSwJuSOHdu8Zxw01vuRiFUVdVoncfwXFzqd1cTAltF2z3Y8jTustWy+TTdo5S0LXlxh254DtdwkrFoK+dHJtuemw9yOVE3KRG4Qavk0+UpNb0x78oLK1q6K2Z6f1nFuqKTeq1JHMtm4wUJaPUguJcE3ywK574FqKdOE0XOaqetDB0NfU0VQ2annlglau5zHKioTexYnu9rjSJKjviDgsU3OTTsXoPdWR4SxGirUQe5da747NEaq+oq3Iy4weha8pnDzbo6rvX5o67Bmlc4Ym093jjuMHBVdufp6l8pIInYNxMmtFVtoKp/2Ny7O/wAS7vMV7e8F3Kg1mpVbWU/FHxLv08RGpXTwv0cj2OavTuVD3rZR4SLXkOPd59D0fs/QtO9YNuVE1ZI2JURJ8aNdfQRaogVjlRzVRU46njsOO79Z1RkdY6eBPsUy7SadnUSyHGuG761GXii70nX7IzennTeVqdcuXAtOGVR6S3l3rn7iJytTU6XK5q6oqkvq8NQ1UfL2etjqY14JtJ6yO3G21dG9W1ED2L2puKXqi/Vk1z4a8TyQV89PJtxvcxycFauikktWPrjTIjKpG1Uf36aO85FpIlXU64qd0siRtarlVdNELld9kH5rLluPRcvPRYiR4FxqqU9bbWxVT9yLs6O17HJ9ZVeceBsP4SWJbdc5JJ5l1Smdoqtb16oWdSxUGCMOvu9wai1j26RRqu/Xq9pSGIKuqv8AdZrjWvV0kjtdF6E6kLmdOHVKM4rffwGx67Oucq5vql2Pjq/Z7CLxQyyv2ImOe5ehE1U+SxyROVsjHMcnQqaGync34Ao6Gknx1iKJjaaJq96skbuXTi/RfMnaTesosnsdK5tdRQUVU7dtuZyLtevVN3nMGvAc4KTlo32Gfft+FNzrUHKK5tdjNMQbPYn7mKmqYlqsKX5HNdvbHPoqL4nNKkxbk3jzDiPkqrNLNA37NBz2+dCxZiXV80ZuNtnDyeEJrXufBleA7qmlqKd6snhfG5OKOTQ6TGJNNPkAAD0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA91is90vtxjt1noJ66rk8CKFiucpdeCe5gxxd2tnvstNY4F3qyVduVU/Bbw8qlcK5T9FGPkZdOOtbZJFDGRs9jvF4nbBbLbVVcjl0RsUSu9RubhLufMtsNbEt2WW81LePLu5mv4LfrUsq2zWWyU6U1ks1NRxtTREjjaxPQSFOzLZ8zX8rpRj18K1r48DT7CHc35h3xGS1dJFaYHcXVT9HIn4PEuTCXcvYRtKMnxLdp7jIm9Y2fBM19KqW7UXyql3LIkadTE0/SeJ1btLqq7S9aqSVWyIx9IgMnpLk28Iy0XsOeHsNYIwvG1tjsFLE9vCRIkV35Tt5l5rxUP1SNGRN7N6mE74VV3H1JV6yRrxK4dhBW5M7Hq2e+SofI7akkc5etV1OCyrw1PMjlVOI366cVLjjFFpasySspLza57FdGJLT1DFamvR4u1OKGs+PcO3PCeIJrbVx7cO91PN0SM6F9psjTUdXI5qoxWIi6o527T6yN5zzYPr8LSUV7vVHDc4EV9M5q7UiP04bKarovSROXCKesWTOy75xlutaopTLbHFVgzEjahI3PoKhUZVwo7inyk7UNn4G0t0oobnQVcK0U7NtJF4adZpRUPesuvRr5zsq7zeVtbbY26VbaFiqradsrkYirx3GFXkSr10JvL2fDIknroza3EeYOX+GNW193jrqlPsNN8Kuvk3J5VK7xHn5cKxjoMN26G3xaaJLLz3+ROCekoGioqieZGRRSSPcu5ERVVSxsJ5ZYluaNkngS30+mvKVG7d+DxKXdZa+J68XGxY6v4mKvl2ul/nWouddU1kq79ZZFdp4k4Iddiwnd75UJFbrdPUO101YxVanjXghcdjwRg+woktyldd6hPifERfEn1qSV+KHwQpT2ukhoYUTREY1NU+ouxxXIw57WjDhDiQrDWSawxMqMTXOGjj4rFEqK9eza4ebUnNppsJ4Xbs2G0xyTtTTvmdNp3nXf6jDVFxnqX7c0rnuXpcup1NkV7tE1VV6EMiOIkYFm0LJmZuN9r67VKioc5vQxNzU8hjnTuVOJ6KS0XGp02aZzWr0v5vrPe/D7KePbr7jTUze12iedVQvqMYowJSnN95hOV3LqZ7C8qe5V+TronepxiayowZRqqVWJ6fVOKMlavq1PK7HOA7ZbrhFTXpZJaindGnMeuq6Lp8XtMaxxfaZOPXcpLzX7ihqydvKyfhKTSrla/Km2J1VD/WpW9VO18r1RdUVVVCSxYktnvNpbRK96SxSOc7mrpvVTBra46mzZFbajp3mLm02N3WeR8jmruU7311uc3RJV8qKdSupZF5kzfOND3R68Ud9Dea6i/cZ3tb8lV1RfIeue5225s2blRtR6/ZGJv9pin02qc1yKh0Phe3iinvEp6qDeq4M763DDJ2rLbKpkrfkOXenlMBVW+to37M8L2dqpu85mYZpIXbTHK1U6UU97Lw9zNioa2Zv3yFO5Fl2NtsOHNEdt9fW0EqSUtRLC5OlrtCZWfMGZrEgvVHFWxcFcmiO9imEqaa3VnOi+Af1dBiqu11MWqxokretoTlDkJ10ZHCa4/vtLIjZhC/tX3Prkoqh32KXcmvl9p77PYKLD0c94u8sXJwJrHouqL2+PqKXdysb9+01UPRPcLjUUjaSarmfA1dUjc9Vai+IyK8tRerjxMeezJNbsbHuvn3+892N75UYnuz6iRVZTR82GLXgntMrlRgOoxbiKOFWqyggVH1UvQjepO1SKQM0lajl0brvXqNlMEVeHYsDe4uE7vSR18jPhZJdWvc9U3rpx7ELdS66zemy9nXvDx1Clezw9pg83MTRMiiwtZVbFQ0iIx6M4LpwTxJ6yvqGoRvhIhmr9g7EFDUPlqKV0zNdeVjXbRe3dvMA6CSPVFRUVOgvTsk5atGFRGqNSjB6kksuJK+1S8pQV9RTL08m/RF8acFJ7YM37lCiR3Smp6+Phqnwb/Ru9BS8iuanE+Nne1U5ylauLdmFXZxaL+q6/KbGjNm92mGlqH7lfJDsrr+G36yK4i7mzCN7hfVYVv3I672orklZ504Fa09Y5FTVymYtd4qaWVslNVzU704Ojfsr6A4V2eki3GOTi/U2NezmiJ4v7nvH9iR8tPRsucDfjUztpdPweJV1ztNytkzoa+hqKZ7V0VJI1bp5zbuw5m4gpURtRUx10afFnamv5SaL6yRPxhhDEcXe2JMPxua5N7nRpK31bSFuezIyWsHoZlPSTKqel1aku9cH7jRUG415yRyrxZtSWC4e5lQ7g2GTci/gO3lZYx7mLGdsa+exVFNeYU3oxi7EmniXj5FMCzCth2ak1jdIcK/g5br7nwKGB7LxbK+z3Ga3XOlkpaqF2zJFImitU8ZiNaE2mmtUAAD0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAvzuG2tXNyocrddm3SKnZvQ3Qqlp7gj6ZkixTM15uu5xpj3Daf6Vaxeq2yfSabV3GdzLjMqOVqtfuVOgm9nVb8OBoHSS3dzNPYjhcIJKeRY3x7CoYyVV1M/DcaaujSluSIi/EmTdoeG4WaqikTkU5eN3guZ9fUTlF2nmz4M1e2OvGPFGGfqqHDnamYSzyRxLNWVENLG3ernO3J9XpI9ecb5d2FVZV3plbO3jHT/CfR3J5VPbcuuHaVVYltr0hE9sW052yjXOd1Impk6SgqpN7mcmn3/sKmxFn5TQRuiw5YWt+TLUu0T8lvtKtxVmbjLEG1HVXeWGF32Gn+DZp1buPlMG3akVwiiWx9gXz4y4I2ivF/wfh9FS9X6ljkbxiSTV/wCS3VSCYhz2sVE1YsN2Z9W9N3K1C8m3zJqq+g1sj74nk10fI5eldVVSVYfwLim9I1aS1ztjX7JKnJs86kdLLttfAl47KxcZa2S18eBlsWZqYxvzXxzXR9LA7X4Gl+Dbp1Kqb18qkOp5JZ5dXbT3OXiu9VLYsWTTGvjW+3ZjXuVESnpk1c5erVfYTaPDVmwbKlNBY4++GoipPK5Hqvair+gpjj2Tesjye08aqO7UtfAqPD+CMQ3ljXU1ulbEvCWTmN868fITi0ZV2qiRsuIbqj38Vgp04+Xj6CT1N4rJU05RY29TNx4HyOdvVd5lxxF2kXZtG2fJ6GSt62KyM5Kx2ingVN3Kubq9fLx9J1VlzqqnXlp3OT5Kbk8xjl1Xee622yqrpNIWc3Xe5eCFzcUeBgy1k9ZM83Kqu7Q99uttbXaLDC5GL8dy6NPt2umGsKs1uE3ftYnCCNEVUXtTgnlK9xVmdiC5K6C3qlrpV3bMP7oqdrvZoUu+EC7VhW3PzVou9lmXD3t4fiR9/u8TZNNUhR29fEib19BF7rm1baLWPD9lR+iaJLOqM9Cb18qlQyJU1EyyySSSPcuquc7VV8p3RW6pmcjWRvc53BETVVMaeTOXLgSlOy6o+l5zJLesz8WXBrme6TqVi/EpmpHp5U3+kiVZdK2skV9TUzTPXi6R6uX0k3w/lJjW97L6ay1EcS/ZKj4Jun87TXyE6s/c43eRqOud4oqX72NrpVT1IY7m3zJGNEK1oloUK50jt+qnQ+KRy79VNqbf3PeGqZutxvdZOqfa2tjT06mSjyey1pt0q1Eyp8us9iIeqLlyRTK+EObNQ1p36cDpkpn/ACfQbkfqc5WQpottjcv31RIv1nnny/yrk3e50LfFPKn1lXUTfYUrPqXaabPgkReo4KyRpt1V5TZZVWvIufCv3lb/AItTCXPIPDtSiutd5qYvw2NlTzpoUOia7C9HaFL7TWFk08fgvcniU9UVznZufo/xlyXzIS+wauttZR1zerb5N3mdu9JXeIsAYjsr3JX2mqha34/JqrPyk3FtxnEyIW028mYZtwppd0jNhes5OgbI3ahkRyeMx09HLFrqi7jqY+SJ2rXOavZuPN/vLvU+qz3PZLGuipofY6iWPg5UOEVz3bNQxJE604naiQ1CK6neir8leKHuq7Clxa9JHYs8M6aVETXdum8881DA9FWnk0XqU6ZmOjXRUVDq23IuqBy7z2MNOTPPVQTxKqqxdOtN6HmjqpYno5jla5OlF0UyrKh6bl3p2nx1JHVouzCqKiaqqbtChruLylp6RmcO5kYmtOyxtc6ohT7HPzk9pM6TMjCl5akWI7G2CVeM0Ka+XoX1lTxWeqqahsNMrXOcuiI5dPSfbjh+929VSpopWonxkbq3zoVRtsiY1uDi2vjwfs4MumDC+EsQxq/D2I4eVXekMqpr7fWYi75d4kotXMo++o0+NAu16OJTjXz079pqvjcnSiqikrw5mdi2xK1kF0kmiThHPz2+kuRvg/SRjT2bk18aZ6ruf6oyNRRVNPIscsL43Jxa5qop1MdK12m9CbWvOu0XGNsOK8PQza7lliRF9C+0ztJT5V4pRVtV5S21LuEcj0aiL4n/AFKZNe5L0ZGHZO+r66tr2riivKSolTQzNBUSuVE085KKrKu7ws5W2z01xh4orHo1yp4l3L5FMtgvLuole+vxEjrZb4NVeki7L36epO0zYRlFGDbfTJa6nHAWG6/EVRswQoyFqpylQ5Oa3xda9hcVhuFis1xgwxSVctZWK1Vkc5+1s6Jrv37vEhU+M8zKako/cLCCNpKONFYszE0c78Hq8fFTDZNXJ82YdK58jnq5j9VVddeapS570tDEljSdbsktEuRU/dZUrGZyXRzWabaMcvlahTapoqoXT3WMm1m3XKn2uP6CFLv3uUgMlaWM6HsqTliVv2I4gAsEiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAbA9wx/CjXr/APWv+k02fvL2pcaj8NTV7uHF0zOuC/8A1r/pNNkb5Ppc6lNfsimwbM4VanPOkb1zmvYj46ZNdNeJ6blcK+hy+v1bRVCsqKWme+ByprsKjdU3KYXldXt8Zkby9Fy0xMn/AEcv0FM6/V0tkLSoq6KfeahYoxPiy9yNnvV6rKvVfBWRdlPEnBDoomPkj0ZG9zlTq11PcsET4Ildpv001NqsNYHpocG0dbhu3W9K5KeOR6Sx6ue5WIqqjl4LqpB0U9a25SN1zc2OLCKjDn+BrdYcv8U3tUWnt0sUS/ZZuY308SeWXKKyW/ZkxHe+Uf8Aaab2qmvoM/frxfYqiSmuLZopGLo6JOZp5DEtuTNeeyRPSSlOJQn5z1NfyNo5k+EfNXs/Uk9thwjYmo2zWKDban7tKm05e3VdfqO+rvVfVKukyxsXg2PcRdlwpl+Pp40M9henjvNzgoYZ40V685deDekklGmEfNIibsb1nq/EmGAbTySyXytaqpHqkCO6V6V+o9N/p23WB7ZV0kVdpj+lq+wy9zeyCOOigajYYW7KIhi3vanFzE8bkLNKi9XLtMO2yTl5vYV1VxzUtU6nqG7L2r5+0+wo+RzWRornOXRERNVUl15t1Pdo9iOWJKiNNWORdVTsXToIziHEllwDRK2Rza28SN5sLfi9q/Jb6VE3GtayfAyqlO5qMF53cZV1Hb7NQJccQ1UcETU3MVeK9XavYhB8UZmVdwY+iscLrdRoit2+Er0/up4iu79frrie5rW3OpdI5V5jEXRkadTU6D1Wm11FTUxU9PBJNLI5GtYxNXOXsQirMjffDkbBRs1VLWzjL4I4PSSoe5Ua5zl3qqrqqmUwxhO9YgrO9bZbp6mTVNdhuqN8a8E8pcWXmSavRlxxXI6nj01SjjfzlT793R4kLdoqi02Kibb7HRQQxMTRGxt0b41XiqljclY9IozHfVQtZsq/BuQMUcbKjE1yRvBVp6binYr1+pC0bJY8G4XYjbTaqZkrU020btvX+cvtPNPW1VU7WWRyp8lNyeY4MYq9Bejh9s2YFu2eyqJl6m9Sv3QxtYnWu9THT11VJqjp3+Td6jshoKiVebEunWu5D1JaWMbt1E7I2px09ql1dTWYkpZeRxZg5le7VVVV7VPJM128yVyvuCbXqlwv1BG5OKOqE18yGArM1sr6JVRbtBKqfa4HP9aFSzIR7Cn+GXTE7HdB4KiN+inTPntlnEqo2Sodp0tpE9p1LntlpLuc6pRF66Nq/WVraMe49/g1y/6OudHpqeN00kbtWqrV60XQyDc18qa9dl9xp4VX7bTOZ6UQ99LVYBva6Wu90Uj3cEiq01/JdvL0cyuZZng31c0zCxX65U6IjKuVUToeu0np1MnTYyk2UjrKVkjFTRVZ0+RdynbcMI6ptUlYxyL0St09KEduVluNGjnS0zlYnx2c5voLqrpsLHWWRPTe8MYBxa1ySUcVJVv+yQfBP18XBSqsbZIXegZJVWKdl0gbv5NE2ZkTxcF8hMpNpq66cD32vEFxoX6JKssSfEkXXTxLxQxb8GD5GfjbSvqfB6+JrJcrZVUU74amCSGVu5zHsVqp5FMaqyMfq1VRU6UNvLtR4UxvTchd6NkdVwZJqjZEXsd0+JSn8wsm7tZEkrbVtXKgbq5VYnwkadrelO1CJsx5Q5GyYu06ruE+DKxpbltJydU3VPlaHolpdtnKQqjmqeCekdG9UVqoqHOjqpqR25NW9LV4FpPsZmzj2xPTR0NVVVCRRsXtXoROtT3yx8nH3rCukaeE7pevX4j02vFjqGldFBbqVXv125HoqqvYdEd4ppZdZ6NrEVd6xO008ilaUTElK1vjHgKdrmNRnKaJrrp2kxt9bUrRsqY52yNTmyxuTXRf0kdihpqtdaKojkcvCNyox/mXcvkU9lnqpLdWKyeJ3Jv5k0btyq32pxL8Ipc2Yd7c1y4mcmpcOXVuzc7Sxr14yRc1fQYeuy0s1Zq+1XnkXLwZO3VPOia+gzVVTuhkTZ50bkR0b04OavBTnHG7RF3oZSoqnzRjQybquMZNFY4iwLiCztdI+l74gT7LAu23Tyb08pCq2WeBV022KnXuU2Utb6x9VHT0iSSyyO0ZG3erlMrmpgGzNyvvFzr6Omddqen5RHxJpybt27VOPlLFuz1uuUHyM7H26o2RruXN6cP0NZcO46xXZamP3MvlbTt2k5rZV08xsnnVii7e92ys74ckVRTNklam5Hu2U3r5zUiBPh2fhIbO51IqYVsLtN6UzE/qNLOHKTqs48kjM2tRV5TQ91cW/kV1HcXPfzlLEyNqNrHlHv8AiP8AoqVBTSPVzlXVN5Z2QaquPaLX5L/oqXsWTc0jE2nTFY89O4iHdWP1zZrd/wBij+ghUC8S3e6o/hYrU6oo/oIVE7iR2V9bInNkfYqvBHwAGOSQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABf3cPrpmXcF/+ud9JpsLf5P20qd/2RTXnuIt2ZFxX/wCud9JpfuIZP20qtPtrvWbFsxfyDnfSHjtF+CPO2Tns39J779Ls5YYldr/ukn0TDseqvZ4zIYhXXKjEy6/7tJ9FCRs+zyIeC/nw8V8zUaeuXvak2H79pE08purga8rQJYKaV2kNXRxxL2P2G7K+tPKaLvRESjVF+yIip5Tbq4zOis1gkY7ZVkMbkXxMYRWzYb6sXsRs3SGKj1Wney3MVYetl/pljrIkbMifBztTnt9qdhS+L8IVlmma2ZjHROVeTmYnMf7F7C5bBe4L1ZILhE5FVybMiJ8V6cUPlWsE8L6epiZNA/c6N6aopfqg1xNYnlbj3ZGuNRSKx+iomuh6cPtWK8U6tVW6vRNU7dxYWK8FKxXVdpa6eBE1dD9kZ4vlJ6SExw9710T9lUVkiKvZopmpRa1RV1imnoYu6VFby72Oqpl2XKm969Z12qhuV0r2UlO573vXfqq6InWvYZe52ySoxFPSU7FfI+ZUaidq6mQxNd6LAdmW22+RJr3Ut1kl48knX7E8pizjo9W+BfrlKWkYLVs8mL8SUeBLWtos6sqLxI34aZU1SPtXt6kKWqlqq+qkrKqV000rlc97t6qplZ4J62Z88sz5ZHrtPc52qqvWS7K3Lq5YtuXJs2obfE/9k1S8ET5LetxgXSlNk7h1V40W+182YfLnA94xXckprfAqRs0WaoeipHEnavSvYbO4QwthzAVCjoY++bi5uj6h6ayPXs+Sn+d564Y7VhK0xWWy0zGcm3TRN+/5Tl6VUwiyTTyrJM9z3u4qpfx8Ry4vkRu0NrtPdgZuru9RXO0e7Zj6GN4eXrOykY6RURqaqvBE3nRZ7bLVaO8GNOLl+rrMfjfMjC2A4XU/Kd/XPTdTQqiv1++Xg1PSZNttdK0iRuNjXZctZkzpbW5rOUqZEiYiarqvR9RF8TZpYKwy59PBM65Vbd2xTJtJr2v4J5CgcX5jYrxlULHU1TqOgXe2kp3K1un3y8XeU8dkw/W3GRIqeCR7nLuRqamClZeydVdGIvO5k6xJnriWu22WinpbbEvBdnlJPOu70Fc3nEOJb69XXC7V1TqvgukXZTycCf0WXFPSNSW93GCjam9Y9dp/mQzFLFgq0wvkpre+4PjTVXTLonmQqWN3lie04r0EUuyx3CsXRkEr1XqapkKbLbENamsduqHIv/LUth+O1p02bda6Klb0bMaanRcsb3xYYJEq3RpI1VVG7ulULixa+0tPaeR2FcxZLYpn8G2vT8JNDoqsmcU0+qOtsq6dSalp4DxBd7niiOnmrZXsdDKuiru12F09JF7hifENPOqMudQmjlTw1KVj1M9W0cvlqV5X5Z4gpkVZLfM1O1imAq8K3Wjfq6CZqp1aoXa7HWIaS308q1jpFe96Lt7+GntMxhHFa4iu8Ftulsop0l1RXLEiLuTXoEsankXYbVzIrea1RRthxJi+wPRKC9V8CN+xq9XM/JXcWRhvOu8U+zHf7dDWM6Zaf4N/lTei+gy1xiwPcauWGopJbdKjlbtR6PZ5l3mDu2XjZon1Fkqoa+JN/wAC7nIna1d4jjyj6EhPOov4XQ0LDs+JME4yTk6WoZDWL9ikTkZdezXc46LzhqqpUc+n/ZEacURujk8nT5CgbtaquhnXlGSMcxeKblRSUYMzWv1jcyjufKXahbuRsq/CsT7131KXYZcoebYjyWz4yjvUPX2Mmj3KxFaqeRUM3YMU1VAjIanWop+Girzmp2L1dh6KKsw3jegWrtVRs1KN1exU0lj7HN6U7SK3qgrLZOsc7FRvxXp4LjJluzWqMHXR7klo+4yWPcubBjCjfdrA6KkuLk1VG7o5V6nJ8V3aa8YhtFXZ66Wir6aSCoiXRzXJ6U60Ltt15qrfVNlp5XNXVEc1eDk6lMxiWz2bMSzKx+kFxib8HLpzo16l62kbfj68Y8yUxNoyoajbxj39xrBI9G8Nx8bKq8DI4uw/dMO3aW3XKBY5GLzXfFenQqL0oYXRzXcSO4p6G0R3ZxUlyPcyeRE3LwMpS3+siYkcjkqIk3bEqbWidi8UMRCm2h3JFq5ERFVfEVLUsyjF8GWVhS6W+70DrdC98NZF8JBDK7VHJ8ZrXdPWiKSXD1ouN6qkpLbT8o/47l3NjTrcvQYHKzLKpuj471eJpbZbYlR6PVdmST8Hq8ZcrLvbqa3y22xwpTU0Omqp4UiL0qvHoJTFU5R4mqbTuqqm1U9X8j5bLfQYXpXR0qsqK96fDVSpw7G9SGDx1UJU5SYsXVV0gdvXyHGurXyO0RypuMPied6ZP4t1X7Cqeoy7IOMH4MjcSuUr4Tk+O8vmajUqJ3zH+GnrNps5Go7C9lTThAz6DTVanXSeP8JPWbQZw1TWYasyuXd3uz6DSJ2fp1Vvgjedsp+UUad7+RUUO9z004KpZOQrVTHVEv3j/oqVnSVEb9tUXipZ+RbmpjSicnyH/RUvYi1mjE2pqsefgQjuo9HZtV/4uP6CFSPTeWr3Sz+UzauW/g1if1UKskTepG5X1svEmtlfY6vBHWADGJIAGRw/Y7viC4NoLNb566pdwZE3VfL1HqTfBFMpKK1k9EY4EyxFlfjvD9vdcLph2qhpmpq+Ruj0b49lV0IaeyjKL0ktCiq6u5b1ck17HqAAUl0AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAvvuJl0zGuX/jnfSaXpiGTS61f413rKH7it2mYtx/8AHO+k0u/Eb9LxVp/zXes2PZv2c53t/wDqT8EdMcnOZ4zK4hd/olxMv/TSfRQj0b9JGb+kzWIH/wCiXE3/AG0n0UM+T1okRcVpfDxXzNNXSIrqRE11SRPWba36RW4esip/JmfQYahNeivp06pE9ZttfpE97lkX/pmfQaR2x39Z4I2fpGvqvFmcyovbqa9zWiV3wNY3bjRV4SIn1p6kLInfuKAoq1KO5U1ZG7SSCRJEXxKXqs7aqljq4FRYZY0kR2u5EVNeJIapTZpG0KWtJLtObZlRdUXeYPElhorvrM3SnrE3pKxNzl++T6+J5bviyxWxVbLW98Sp9jpk2/63AxVJi6eupqu4LBHQWunYqq9y7T3aJv3+wb9cnoWaaMmK3ktDGYyvttwVR1FzcqS3SoY2Njdypto1EXTs13qvkKJkr57vcZaurqJZJpXK9znLxU8+PMR1OJsQyVcqqlOxdiBnyW6nswDYLliPEdLaLaiLLOvOeqbo2dLl7EInIyt+ekeRvODs5Y9O/P0nz/QnuVWCKzF92Wnie6OhhVFqqhU12E+S375TZOBKGx0cOGsO07GPjZ4LdOYnS5y9LlMJGltwDhWmstpanLqmiOVOc93TI4xFmuUlJcGVqqsi6ryqrxei8SqMG3qyMycyOu6uCMrPBKyoe2ZHJJrq7a46mXtloibCtbcHJFAxNvRy6bk4qq9CHu5SgnhbdqxUghij2ldLzURqb9p3UhRWZmZE+LKia12eRYrLGqortVR1SqdK9TepC/O+TSguBj4+DGUnOXFGbzOzRnniktOEZFggTmSVyJoq9kfV4ynKSw1FwrdWrLNLI7Vyrq5zlJdhTDdwvlU2np42qiJqq/FanWqk1mr7Jg6B1HapIqu56aS1Spq2NepvtPJY0Y8ZPiZMsxwThUjC2rBdrsNG2uxNVJBu1bTt3yO8fUK7HMMDO8rHCyhp+GrGavd41MZWyPu8FTNV1jnvWRq7StVVXiSLB+V9VceTq6ubvSlciLq9uj3J2N6PKW7LN1JRLdWK7m5WPVkbuk9RVViudPM5Va1d7ewzVgw7c6yiqHR0VbI10aIjkiXRechcVqwlYLVIj4aWKWZET4SZdp25PMhnWbCRuRHs3InBSz1r11M2Oz1u6M14qrM2jk5OsZVwO6nxafWdtRR2x9JSI6WfcxdOanyl7S7b5S0VwpX01YkUkbk03rvTtRegpa/U0FJLFClZCrY0e1FVV36PXsMiqSlzMXIxnXpoWPk1hrD6bdzbMs1W3ViMcqJsIqcdE6yIZn4dw/bb7NHT1Emi6P2GaLsKvFOJ48uat8WLYUgrWaLFJq1rl38xewid1rXz1Mkk1dE97nKqqrl19R7CKUm9eBjyscoqG7x7ztuNPQe5dMnLSoiSyaasTXg3tMzlhBQ++2jdHK9z029ys0+KvaRe4qz3Kpl75hX4STpX73sM3lO9q4wo0SaNyqrm6IvSrVKbX53AuQi+rbI/iTvZtxqefJryjuDU6zF0lzlpIZJoJZWKyVujkXRek9mMoX097rIZnIx7ZnIqLr1mDakS2+oRZ42ryjV369vYUxsabMiNUXBakrixfSXGNKe/0baxipokzURsze3a+N5TGX3CdJPFJWWao76hamrkRuksaffN+tNUI7FyKKn7Ii9PsPey5yUNzWemrOSkYu5zVVF4FXWKXCR6qHW9am0YFktxstayroqqamqI11ZJG5UUtvAOZdtxNGljxM2Gnr381ki7o5/8LjB8na8VQNa59NR3Jybt6NimX+6voXsIHirDtRbqh8M8fJyxu7UVFKdJUveg9UXk6stdXctJd5b2L8Nz2xVqqdFkpdd69LOxeztMbhaO6z1/L2yNyyQpq5UXdp1L4zzZQZlJIsWFsWSMe1ycnS1ci7lTgjH6+hegsS5JFhC3zup6N0sEz1c1WrojVVPBd2dRfW7ct9Ph2mDbCzHfVTWr7H2MxOJbJace2F9HWNbT3CBF2Hr4UL+petqmsmK7JccO3me2XKHkponadjk6FRelFLso79Wx319z2mtke7VzdOa5OokePMNW7MXCjaik5Nlygaq071469MbuxegxLKldFuPNfEz8LLeHNQn6D+DNYoVem9FQvLKPA9sZZI8W3t8VXHptQU7d6IqLpq7t16ClaylkoqqSlqEdHLE5WvYqaK1U6CfZPYw9zKx9guUyrba/mb3bo3rwUxsdR39JErtONk6G6n/0WXibFUtV8GmzHE3cyNvBEMdhysfNcnxKqIk0bmp403p6U08pGsY0dTa7jJTSPcrddWP18JvQpi7fcZqSqimbK5HMejmrr0opKQscZaGvww4OvVdpYu05ZtHbl0PFi9VblDilOuL2HJs7H1SSxvVzJE227+CLv0OrGb/9EmJE14s+tpn3L+TLwZYojpdX4r5mp0P7sz8JDY3OVVdh2yt/5LNfyGmutM3WojTrenrNkM3IHPstoanRAz6KGv4Cbqt8F8zcNqtLIo8X8ip7fT+En3xa+SkXJ4qo39TH/RUrygpnNV25eJaWT8SpiGmXTgx/qUy8GGk0Rm2LNaJ+BU3dDSK/NW6r1Oan9VCuJOKlhZ+LtZo3df8AmInoQr2Qicr62XibDsz7JX/ivkdYAMYkAbN5R1TMD9zrc8Y2mmikus0jkWVzddnRURNexOOhQWBsJ3jGN/hs9mp1kleur3r4Ebelzl6ENqnV2XeVWDaPAGI65apla13fTdhX+Fxc5E3tTcmnT0mfhVvjN8Fpz9prfSDIi1DHinKTabiu2K56kN7nnNTFOLcZyYaxLLHcqSshkciuianJqia6bk3tXhoUxnLZaXD+Zd6tdE1G08VQqxtT4qKmunk1L3t+KclMrqaru2EZH3O61Matjaj3PVqL0aqiI1PSa14ovNXiHEFbeq521UVcqyP7Neg9yZaVKEpay18eBVsqrXLndVW4VtJaNaavv0MaACPNiAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPui9R8AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAL07jBdMx7h225/0ml1YmfpfKxFX7KpSPcau0zKrE67e/wBaFyYwkVmIq1P+YpsWz3pjfic926tdqP8AxR5WSpyjE2td5nb0u1lRiZP+lk+iRWKRFex3aSetXlMscTN/6OVf6imVGWtUl7CNktLYeK+ZphqqSQ9SP+s2tvku1hayLr/uzPoNNVHom1H+H9ZtSlM+vwxZdXtigipGvmldwY1Gt3/oMDZH/J4I2jpAl/Kb738jDUsHLOdJI9Y4WJrI9eCJ1ePsPRU3msqYGUnfVQlHCmzDC566NT2mGu13ZUyJTUbFjool5iKu96/Kd2r6BTSJs9Blymm9CEdD01Zk6KKSrq46aNu0+RyNRDszivDLdbafCVA5qI1qPqnJ0r0N+vzGewVHT262VeJq5rUip2O5LXpXp9nlKevVdLdrrU3Co0dJNIr3L4yzfNQhoubK8Ol23bz5R+Z4G0D1ci8m1VVdyJ0qbSZL4PhwJg2S93WJrblWRpJJ8qNnxY07V6f0FW5BYUZiLFzayrbt0Fu0mkReD3/Fb9fkLrx1dErK5KCKRORp11eiLxf+gxKIP0mZW08rRdWn4kaulbPX176qoVeUfwToa3oRCRYMtnfS991CL3tEvNReD19hibVbXXG4R00e7aXV7vkt6VOnO7FfvfskeFrE9rK+qi0e5F/cIuGu74zvavUZGu7xZC1Uu+SSIHnzmTNfLk/Cdgn/AGvgfpVSsX92enxU+9T0+YxOXWHqi61MdPExdlU1e5U3Mb0qpiMG4VfV3COKONZJZH6InFVVS28UxxYPwxDarY9iT1SL3zO1d66blanZqU1RafWTJHLujGKx6OZ58Q36htFtfYLA5zGK1Wz1DU50y6dC9CECw/T1l4r0o6WGWaV67k+tepDsoZa6ruEUEUUUsj12WorEXVVLZwlbY8P0XJNZC6skROXlRiJqvyU7ELd1u++DK8XHVK85cTKYMwhbrHTctUtZV1uqKrlTVjF+9T6yWsm2tNVI/HcJOQf4OuqdBwS7SM3q9u7jqhjtvUkYJJakomVOUXf0J6j41yJDKqL8VPWhXeJcx46J74aRI5pUTjspspu9JFpMfXqqo6ty1eymwio1rURPCQrim3oUTvUVqWHiq+0tupnpto+oVNGRouq69pUOIXOfFSPdtK5zHqvj21OiTE1dI/V0kaqvSsbfYZCe8SLRUTpFgVXRu11iZ8t3YZW7FR5kfO6cpcjLZO4cutfiJLhDA5KWGN7XSO3Iqq1URE85CMWWS42a7TUddC6OVjl6Nyp0KimyeT96s9XhaGmhmp46mHXlY00aqr16EFz2xBanXaGCjkppZ4mK2V2y12m/cm8tQlx0Z5OprSS5lMXFH+4tKmi/ur/U06rBX1FrusFXTvdHLHIitci9pnLvd3JaKVWrBqs0n2JnU3sMK27VD6iNEWLe5OETU6fEX9IN8yhb6i1oTyvx7brrLJT4lw/RVzEereUZzJU0XjqeOswJa7/aKirwbWpO7c99DPulZx3IvSQW6XeqjrZ9HRr8I7jG1enxHbbMQVsEL6qKZYZonsVj40Rqou/qKHGOvMrhGainEwdbbp6GrfBPGscsbtHMcmitXtQ8dwTW4vjTjr9RcVuvtBjumWjuEFHT4ia3SlqnRN2anT4jupepStr9NWU16ljmp4o5IpNmRixJqipxTgWnXotdTMqvcm01xRmcD4clrdutrZu9bZTJtT1Dl3InUnW5TLYhxFZsRuZbHUTaZkLUipqlz9XuROCSKvHX0DHOOaGswpSW+3QRxbEaPlYjEa1H7k4dPSVU2713fTHNka1UdqmjUL0pqvRa6mPTRPIbsktH2HtxBaFpapzFRzVa7cvUWzk5jiO8UXvQxFI2SdGbFNLJ9lb8hfvk6CD0FW7E9JJTVTmvuUaKsUirvlRPir29XmIPcu+7dXtmhcsU0T9prkXRUVCmT6qXWQ5MylX5VB02+kv3qXHjGyyWS5uj3uhfzon6cU6vGh8wjfn2m4Ir11ppV2ZU14ffeQzOEr5T5j4IVkzo23SmRGyp0o9E3O8SkEq45aaqkgnTYkjcrXN6lLslu6ThyZHRi571Nq4rme7ugcItqIG4utkbF1RErEZwVF8GTy8FKNWR7E2mqiObvRdTaXAFdS3W2T2C46SsdGrUa740a8W+Tia/Zk4Xkwviiqtb9ViR21C9U8Ni72qYuXVytjyfzJfY+VzxrHxjy9qLCw1dExtgBWyKx11tabLvlPZpx/z1dpFpFdyjWpprroR/K6+rhrGdNPI79iVC8jOnRsr0+TiWriHDLaPE7pGMTvR7eXjVF3adXnL1T66CfauDKMiHktzj/a+K/NHG2ufBFDE52uy3zHdjao0ynvu/wt3paYttQvfTl7TnjyXTKm5/fSInpQz3ZrTJexmBCv8An1v2r5mvNAzaroE/5ies2UzKTbordH1QN+ihrfbU0uNP+GnrNi8dyo51G1y+DAnqQjdm6dVZ+BO7Z43U/iRGgg3ruLIyohRt9jXRN0TvUQOjfHv3oWFlg9nuqrk03Qu+ozsZLf4EJtOTdMijc7WJLmbeXdU2hX1WxGqT/NydjsxLyqrxqHEDrVRztxAZPpy8Tbtn6qitexfI8Rm8F4YuuLb7DaLTA6SWRec74sbelzl6EQ+4MwvdsWX2G02iBZJZF5zl8GNvS5V6EQ2Iu1ywxkTg5LZa0jrsS1cernLxVflu6mp0J0lWNjdYnZPhFdv5ItbR2i6GqaFvWy5Lu9r9gvd6w7kTg1LLZEirMS1TNp8jk366eG/qanQ01ovd1r71dJ7nc6qSpqp3K6SR66qqi+XSuvV1qLncqh9RVTvV8j3LvVTxFORkO16LhFckXNnbOWKnOb3rJek/32AAGMSQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAO6hpaitq4qSkhfNPM9GRxsTVXKvBEOk2P7k/AsEdLNj+7sTZj2o6FHpuTTw5PqTymRi48si1VxI/am0IbPxpXz7OS732I9+XPc+2W3W2K64+qlkmciO7zZJsMj+9cqb3L2IWHTWHKy2tSOjwrb3o3gveqOXzv3nhxBd5blWOmkcqMRdI2fJT2mM5ZetTo+F0ax4VrfXE5NlbXzsyTlZY17E9EStvvCamjcLUSJ/wBlEdclvy0rU2KrC1v0XirqFn90jHKr1qfOWVOlTOewMVrl8jDjffF6qyXvZxxjkTgPFFvlqMJyNtNciatSNyuiVepzV3p40NWMWYeuuF77UWa8UzqeqgdoqLwcnQ5F6UU20tdxno6tlRA9WvavDocnUvYeTugsH02OcA++G3wJ7qW+NZWq1Oc+NPDYvXpxTxGqbb6PrHj1lRtPR/pJdVcqMqW9GXBN80/HuNQAfVRUXReJ8NNOmAAAAAAAAAAAAAzuAMOT4txhbsP08iROrJUYsiprsN4qvkRFMEWT3NC6ZyWVfxn0HF2iCnZGL7WYmfdKnGssjzSb+BsRRZR5T4cpoqS42ptbUbOrpalz3Od26N3Ien3lZMp/Fu3/ADUh6MxZXe7TU1+wt9akVWV2vFfOdLxOj+LZTGTXP2I49/E823znbLj7WSFcGZNIv+zlv+akPi4PycThhy3/ADMhH+UX/Kn1HqZP0bxO74IeW5n3sv8A9Mz6YQyd+5y3/MvPnvQyd+5y3/MvMDtqNtR9HMTu+CPPLMv76X/6Zn/ehk99ztv+ZkHvQye+523/ADMhgNtRtqefR3E7vgh5ZmffS/8A0yQe87J77nbf8zIPebk8q/7O2/5qQwHKL1jlP86j6O4nd8EPLMv76XvZIUwTk4v8Xrf81IH5f5MzJo6wUCeJJW/WYBJV7Tkky9ClL6N4r7Pgj1Z2Yv8Aml/+meyryXyer9eRY6lVftVY5v0tTBXTuZcK1jFfZcSVkC9CSIyVvo0Mj3wqdJzirJI3bTHuaqcFauhjW9FceS4GTXtvaVXo3P8AHj8yr8UdzVjK3Ruls9ZQ3hqfEY5Y5PM7d6SpsSYXxDhyoWC+WiroX6/ZY1RF8S8FNvaHFF3pV5lY+RvyZOcnp3mbZii1XildQYhtsM0D00cj2JIxfGi8PSQuX0Tsgta2S+L0zyqnpkQUl7OD/Q0PBtNmN3P1ivVLJdcC1UdHUOTaSlc/WCTsReLV86eI1rxHY7rh66y2u80UtHVxLo5kjdPKnWnaatk4duM9Jo3jZu2MXaUdaZce1PmjGgAxSUAAAAAALAyMy+XMHFbqOeZ0FvpY+Wqnt8JW66I1O1V+s2Vjy3yetiJRzWCllkj5rnSLI9yr2rrpqV/3EzGozE0um9OQbr+UTe+SqtxqV1+yu9ZufR3ZVGVXvWI5n0m2nlLPlTCxxjFLk9Oa1PYmB8mPucovyJfadjcFZMt/i5QfNyEeWV3Wp85Z3Wpsv0axO74IgPLsv72X/wCmSX3nZNJ/F23fMyH1MI5OJ/Fy3fMPIvyz+0cq8fRrE7vgjx5uX97L3slHvUyd+5y2/MPHvVyd+5y2/m7yLco7tHKO7T36N4nd8EeeW5f3sveyUrhbJ37nLb+bvOK4VyeX+Llt/N3kY5R/aFkd2j6N4nd8EeeWZf3sveySrhPJ5f4uW35h5wfg7Jx+5cO25PFFIhHeUd2n3lHdSj6N4nd8EPLMz76XvZmZ8u8l6pqtWy0kSr0sfKz6zFVeROVdxRe8q2qpXLw5OsRdPI5FODXqdjZNOgs2dGMWS4L4F2G1NoV+jdL36/Mit97l5yo6SwYoY5OLWVcWn9ZvsKrxhk9j7DKPlq7HLU0zONRS/Cs06929PKhsZQ3SrpHItPUzRfgvVE8xJrVjasiVG1kbKlnBVTmu9ikNl9E9FrUS2L0s2hQ/5uk17Vo/ejQ97XMcrXtVrk3KipoqHw3fxfl5l5mRBJItMy33RU174p2pHKi9bm8Hf53mr+a+VOI8AVSyVcaVlre7SKthRVZ2I75K9hqmXs67FfnLgbpsvpFibQe4nuz7n+XeQAAGAT4AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAByijfLK2KJjnveujWtTVVXqQzq4KxeiIq4Zu+i/wDSP9h9y235gWD/AMhD9NDebEV6ktM0TGQMl22qq7Sru3ktszZbz9Uno0av0g6QT2VOEIQUt7Xt0NF/eZi37mrt+aP9h9TBeLl4Yau35o/2G6Pv2nT/AHGL8pTk3Gkzv9yi/KUmfold3/L9SAfTm/7le9/oaP3ewXu0RskulpraJj10a6eFzEVfKhjTbDuvpUky5tr9hEWStavi5imp5rebjeTWuvXU3DYm0pbSxFkSjuttrTwAAMQlwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZK1WG93aJ0tstNbWMaujnQwueiL5EMabddycqQ5S1E6NRVbVyu8eiIZWHjeU2qvXQidtbSezcV3xjvPVLTxNY/ebi37mrt+aP8AYfPebiz7m7t+aP8AYbpLjKoaunecPncfW4zqFX95w/lKbL9E7u/5fqaf9OL/ALle/wD0aXNwVi9UVUwzd93/AEj/AGGDmjkhldFKxzJGLo5rk0VF6lP0Gw7eZLrLKySFkew1HatVV1NF8ytP1QL9pw7/AJvpKQu09mPBaTerZPdH+kFm1bJwnDd3Uu3UjwAIo2gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAuruPHbOZ86ddBInqLdx09UxPWb/jFM9yPJsZrNbr4dHKno1LezDerMVVW/iqepDYMH7J+JoO2l/8AK/8AqjH0z/hGb+kmEK8pgDEzP+il/s3EGppOezxk2tLuUwbiVn/RSf2TzMqXmS8COuWkov2r5mnUi6PROp/1mzcOzX4BtVvdX96unhjViO8CRUb4Kr0GsdSuk7kTok+s2ArV28urM/qjanoI7ZbS6zw/M2nbcd7qvH8jH3G3VdtqViqYHMXr03L4l6TlRpJUVEVPEiq+RyNRO1T2YbxM1GNtt6Z31Srua929zP0ekmOG8L0sd6iu9HVNlo2tVzU110XxmfGpT4wZB33OtNWLj2dzI9nFdm2uyUGFqNypzUfNovFE4eddVK4pmosbG7Kq5fSp2Y3u8l5xlXVm1qxJVZH+Cm5CW5M2Zt/x3QwSs2qem/ZEyKm5UbvRPKuiEddPrreBJUVLEx05d2r8S9sDW+nwHlvFtRoytnak0vWsrk3J5E09JhIqlrtZJFVXuXacvWqnuzIuST3SC3MVVbEm29E+UvD0HnwpQ9/3WGBzdY2c+XxJ0GTFJPdXYaza3Y999pJ4K+iwhhCrxFctypHtq1eK/JYnaqqn+UNfG3Ga/wB7qbtXyPfU1b1e9V4J1InYiaIS3umMRuqblRYTpH6sh0nqkavFy+C1fEm/ymIyvsff9xi5duzSwt5Wof8AJY3evs8pQmp26diJOut4+Lvvmye2eCDCuGUuSuY251rNmla9URY2dL9/oMZjCKWfDlkcskaq5kquV0ib12yM45xDUXTE0yqzZhjXk4Y04MYm5EJFWxtq7LhenfuYsL1X8sous320hj0OvdnLm+PwMrlxZI6XZuFQ6JZ5F0iTaRdlvX5SWrGiSuVXt4r8ZDCUE8TJ42tTREVETsPlbcIYle97ka1qqqqqljc1MxS7WZqoljp6WWWWaOONqIrnOcm4r/EN+fXSOhhqY4qdOhHb3eMxuJ7++4RPbGqtp2uTZbrxXfvUizp3K5dT1QPJSZl7mjH1DlWsp27k3K5epOw4U0cS0VU3v2m1WNPjL8pOww91k0qF39CepDrpnO70qV/5afSQucEzG3JOK1Z7eQYjv39Sflr7D11qRd60iLcKVNI1Tw1+UvYRdXP5Tp4nbcVd3rTcfAd9JQpFbp1a4knsMyR1qKy4weA/g9fkr2HgqY2PVVdcaVd/S9fYYWxyKlZvVfAf9FTyTSu29EU93+AWP574kkrqeB9spme6NKitkeq71+97DyQUtO2ePW4Uq85PjO6/EYirkclDDvXw3fUeejeqzs118JPWN9a8itY73eZmLpSwPq5nJXU3hrxcvX4jhHBA22zMSsp9VczTRV7ewxNwevfcqafHX1nOBV7xm3dLQ5pvkXI1aRWrPbakkiuDOSroGvRyK1zXKiopcONbdhqoqral+hqm3GqpI3T1VM5Ea1VTRHK1U39pQ0CuZUNfvTRdS04MyqBKGkhvFiiuFXRRtbTzuk03Im7aTp0LdaWnFFOXCe9Fw4kOxvhp1hvVda6iric6FE2X8Npq6Ki6dG5SJxUcLZW/siJdF+UZ/FWIKjEF0q7hVsa6afeunBOpE7EMHBSTyvTk4FXf0IW3HV8EZlUmoee+J6LU6OjuCSx1jWOa/VFRV3byTY3t9tulBFd6KZFmexFqI0aqbLuGqdi6ekifuRcUncvez+K/FJTSUtXDR0zZoHo17Va5FTo1MumG8nFmLkWKM42Qa1I1l9fpcHYtgrkc5aV68nUsTg5i8fNxLpzKtVLPBBf6LR8MzU23M4LqmrXeYonGNvnoaiWKSJzHIvBU0XsLZyExA3E2CazDNwciz0aK1uvFY14L5FGNopOiXby8RtCDlXHLh2c/Axliub7fcIqiHRHRORU7etDP582WLEmBIMRUMbXz0LUeqpxWJ3FPIq+lSFXfbtdxmpp02XxvVq6lk5YXSmu1jq7PU6Pja1Wq1V4xvTRU8/rL9UVYpUvt+ZiXSdEoZMez5Gpk8j9drgqL0GxGA73758ropXrtV1s+CkTpViJuXzfRKMx3bpMP4tuFnkT97zOai6eEmu5fMSzueb+lFiye0TP0prjEseyvDaTenn3p5SPwbOqv3JdvBmxbUoWTi9ZHs4okMc699uRd289eYEn+iupTXw50T0nC80b6W81ECoiLG9UTtToPPmC//Rske14VSnqUkWnGua9jImCUramu9FM22PW5034xPWbB4tgWeqhbx2YWlGWmFvuvSJ/zG+s2CxK6GOd80kscMEcbduaRdGt3elexDDwI/wAuf4Gdtib62vT2/kRRlNHC3nIqqvBETid8OYFnwcsrnNWsrFjVrYI3bm69LnfUQHGeNlkWSisr3MjXVH1C7nP8XUhX8j3vernuVyrvVV6S1bmdW9K/eXaNldfHW/l3GWxHeJL1eqq5zNRj6h6vVE4JqfcI4cumKb1DbLXA6SSRec74rE6VVehD7hDDt0xReYbZbIHSyPXnO6GJ0qq9Rfl2ueHckMJe59vSKtxJVM5yrxRflO6mp0J0liijrdbLHpFc2ZWZm+TbuPQtbHyXd7X7Dlc7th3I7CKW23MirMR1TNVVU36/Kd1NToTpNbr9drhfLrPdLpUvqKqdyue9y6+TxC+XWvvd0nuVzqX1FVO5XPe5dSysl8rJ8RuS/wB+Y6mscK7SbfNWo046dTetSqc55k1XWtIrku72sppop2XVLIvlrN832t9y/JEVw5lziy/WtLnQW9qUrl5r5ZWx7XaiKu9CY5fZQ1zrwtRimKKOjgTVImTI7lXdS6LuQ92Zmbj6WsSy4L5CGipfg1n5JFR+m7RiLuRqHiy4zVrZbwtFimpidTTpoybk0Zybu3ToUy6a8CF0YSbb+Gv6Fi67aduPKyMVFPs472n6kngq8tMQ3iXCtPbKdJk2mMe2mRiOVOKNcm/UprMPDi4XxPPbGvWSHRHwuXirF4a9pcVswjhDDuIJMWLe2ck1XSRMdI3ZYq9OqLq7jwKizNxFHibFlRcKdFSmaiRQ6poqtTp8p7tFLqE7UlPXhp3HmypPyhqlycNOOvrewjAAIM2MAAAAAAAAAAAAAAAAAAAAAAAAAAAyeFrPU4gxFQWajaqzVc7Yk0TXTVd6+RN5u1e4aTDeFLfhm3NSOKKFrNE6Wt6V7VXf5ymu5AwiySqrsZVsXNp9aekVybtpU57vIm7ylk4juC19ymn15qroxOpqbkN36LbP3n1skcy6X7Q6/KWNF8Ic/F/ojEyKquOBzVN59jiV6ojU1VVOg6pGq8kdflG/rJLFg65vpkl0ia5U12HO53q0MFVUslPM6KVitcxdFRehS1Vk1WvSD1PN9M6W6ou4mOAK1OWktk+jop2qrUXhrpvTyp6iIIh6rfO+mqI5410fG5HNXtQt5dKvqcCmce011z2wc7BeYVbQRtd3lOvfFI5emNy8PIuqeQgZt13UeHIsT5bwYlo4tqrtuknNTesLtEcnkXf5zUU49tHGePe4nX+j+0PLsKM36S4PxX6gAGCTYAAAAAAAAALI7mr+GSy/0n9m4rcsnuaP4ZLN/S/2bjIxPr4eKI/av2G7/F/I2UzE192k/FN9akWXiSvMJP26/om/WRdUTU7LgP8A8eJxan0TiiHY1qruRD4jd5KcG2qkniqLlX6LTUyKqovDcmqqviQuZORGiDnIuSehG2wPXoU+97P6lPFWd0VgKjqZKemsVyqI43K1JGQxNa7TpRFdrodK90ngnT/Zu7a/i4f8RrMulOPrz/fuJRbD2o1r1L+Bk1pndSnxadxin90ng1U5uGrp+RF/iOp3dJYRXhhi5L42xe0p+lOP3/P9D3+A7U+5fvX6mYWFf8qfORXtMKvdIYT+5e4eaL2hO6OwivHDFx/Ji9p6ulON3/P9B/Atq/cP3r9TMrCvacVhd2mKTuisFuXn4cuSf0US/wB49tDnhlncHbFXSVVFr8aWkRU87FVS7DpPit6aluextqQWrofwZ3LG5D5wTpJFabrl9iVUbZr9RuldwY2XZd+S7ed1xwtVQor4NKhn3vHzEvj7Vou9GRG2b9Ut22Li/atCMJ2HNu11nfLTOjVUVFRU4op16KhIqSfI94MyNkulVbZ+UppdEVecxd7XeNDO4vwvhjNTDrqOviSC4RNXkZ0T4SF3X983Xo9REk16FPdbq2ajqWTwyKyRi6oqEXtHZleXB6rie1Tnj2K2p6SXaasZh4NvOB8RS2a8Q6ObzopWpzJmdDmqRw3hzGwvbM1cDPpnoyG60yK6ml6YpNPBX7136eg0outBV2u5VFuroXQ1NPIscsbk3tci6KhyzaOBPDs3XyOrbB2zHadPncJx5r8zygAjyeAAANlu4q3UeJl+/g9TyX3lda+f8Y71kP7i7944l/GQep5Lbwn7Pn/GO9Z0jol9R++85D0l/q1n4fJHjG446LoGtcqm4vgROuh2NZqc0gcvQpIZamwYLwYuKMRNdIxURWtRm0vO8FrU4ar1kLXuj8ENXRuG7qqfi4v8RruZ0hoxrNxsycbZ+bmRc8etyS7TJpTu6lPqU7+pTGfrksFfc1dF/o4v8R8/XJ4NThhi5fkxe0wn0qx+/wCf6GUtgbV+5fvX6mWSmevQp971f1KYj9crg/owvcfNF7T4vdK4R6ML3HzRe08+lWP3/P8AQq/gG1Pufiv1MutM7qUd7O6lMP8Ark8HrxwxcU/mxe07I+6KwJKuk1gucevFeQid/eKo9KcZ9vz/AEKXsLai/wCF+9fqZNYHJ0KcVa5p6LbmvlVeURr66Oikd8WohdH6UTT0khZabVd6fvqyXKCeN29FZIj2+dCSxtt493KRH5FGRjP+fW4+KIrr2BH6cD3XO11VE7Znic1Oh3FF8pjnIrV3kvCcZrVMtRmpcjviqpI3texzmuauqORdFRSX2jEFLeKKSzYihiqYJ27CrK3Vr0XocnX2kIPrXKiljKw68iO7JFMovXWPBoqvP3KCXB07r7YWST2KV/ObxdSuXoXrb1L5CnDejDdyp7pQyWC8xsqaedixokqao9q/EX6jVvPTLufAWJ1bA177RWKr6ORd+idLFXrQ5htnZEsKblFcDo/Rnb7zF5NkPz1yfev1K7ABAm4gAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEiyzTXMKwJ/9hD9NDcrMNV76g/AX1mm2WCa5i4fT/wCwh+mhuNmOn7Lg/Fr6zcuiP1j8fyOb9OPtFPg/mRJXKdsCrqeVeJ206LqdFlpoafJcDG91omuWNpX/AKtn0FNVTavusU/0W2r/ALuP6DjVQ4/tv7U/A6f0O/pkfFgAEQbSAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADbfuWVVMnKn/ALmf6KGpBtv3LSf6Gqn/ALmf6KErsX7WjVumH9Nfij0TPXb6Ti2RUU4VCc5TrTXU7EktDmEV5pOsvpNayo/FJ6zS7MXfj2+/9/N9NTcnLtF79qN/2JPWaa5ibsd3z/v5fpKc46WrS1fvsNy6EfX3eCMCADTzowAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABancsy8nm7RJrptQTJ/UUubMldMWVC8NUav9VCiu5xm5HN20Lr4SvZ52qheWafMxU9V+Mxq+gn9n/ZH4mkbbj/8pF98fzMLC/4Rm/pJ3hReVw9iKPrpXJ543lfRO3sXXgpYOW3w8V5p/tkDU86OT6zPq5NEXlLRJ+HzNNq96pWyp1SL6zYBsiPyqtMi9DG/Wa+XXm3Opb1Su9Ze9DJt5M296b9lietxEbMfnWL2G17YjrCp/wD2RGo6pI6tNFLaw/VPseVN0vD3K10jHclqvXzE08q+goaWd7q+JjOL3I3Qt3O2qWyZUWm0xrsumcxHJ+C3VfS4v0T0jOfcvmR2bRv2VVes/kVNRTseqvcu9V1U2P7mi2R02G7hiGVqNWofybHKnBjE1X0r6DVOinftIxNecuiG49mi97eTdDStTZkdSNR34Um9fQpj4S3pOXcXNuPcqUFzk9DCzVLq66VNa5dVkkVU8XQTjByw2vDtZe6tdiNGukc7qYxF/SV9bl242Nam9yoieUkeeVxbYsqlt8TtiWrcylRE4qmm05fR6TMityLmzXFW7LY1rtKKqrlU3/E9XeKpqOkqpnP8SKu5PMWlDUNw5gSKNY2rV3h+qoq6K2FF+tSvsBWt9zuFHSRN1dJIjfSSTMeepqsVJFTwvWlpVbBDom7Zbu9K6qW6oqNevayRym7LlV2I8N5qqf3eqGrRxuXlF37a9ZLb/coqSyYfWOmYqtpFcnOXdz19hBbtHOt8qHLC/TlF36dpJsQw1E1js6she5GUPOXZ4c9xYak2y5JRW5r++BnbZiS1VCxvf8E/aTVqqvHsIvinEkVTO+CCBFiRy8Xrzt5HqZKhtWz4N+56dB452VDpXLybuI1k0XI1xjIzdLWQyU7kdSR+Enx17SUwYSmexXvbQN0gbPosy8F6PGRbB9vmr6zknoyNkfwj3SLomiJwLYrOZ358Fa/3kxdz+Cdhcgm1xMDLt3J6IjdVgl8s8mr7dqyFJV1ldvTTgY6/YeksMMjZ4KSRssLXNdG9ytXem7xk9e1OUrncjaNEoWfZOxeH+eo8uPaDv/DjmMht7ZKalbKiwy+Emuipp0r7C5utrUxq8jzlF8iopJqdjkTvKnXyu9ouVVA2mp0Whp15i6b3fKXtPDLBUJLvgcm/oQ+3OKZ1PTokT9zF6O1S0nLQlXCO8jttVVA6q5tDTouy7pd8le06kWKSRESipk1Xrd7TjZoJkq98Tk5juj71T7BBUJO3SF3EavQ93Y7zJkzL2pr6Whck1DHHUOVsekvBe06I8uamJ8Du+qBvKVCwt1l4KnSvYWJaqfYpbDt0Vsajna6vl3ru+MfO90kdbmpSWVdquk8KXiia7l7P0F+MYuRGPJsUeDK2ly+qZ3MmZU293LVLoU+G00cirv8AEGYDrI4HtWW3IjqlKddZl8Lr8RP6emj73p07xsa6XRzNVl7V3L97+g6n0zVVI20Fk1S66KvLdnD8Eu9Suwo8ss5NleLgO4Kukfue5VqVpkRJ18NPqI1iewXa01UiVdBsox2wrmu1bqicNS3mU/wmi0FlVFuytT4fh2fgn2so9qJsEtttMkLrorVb3yvO3LuXsKLMdacy9TtCcZedxRQ0c3JbWsDNdOlVMzZsX1lqaxlPT0ujH7XOjR3rJBjnCDGQ1tzt0FLEyOqdEtLHPtKna3rQrZ6OR+yrNFReGphvfrZMwVWVDUtFmb1Q1VR9mtbnIvHktNTpxFmhV3G3wcnb6GnVkiojoo9F4IVVIyV0z+YvFT1vim9zU0auvKdXYextkUvZ1CaehLMW11Rie0+6lQ5H1EekciommrdOb6tCJ5W35+F8y6OWRyspql3IT9Wy7dr5OJK8CUtRVtnt743K2phVibvjcW+lCv8AFlumpqlZdFa+N2pVemt25cy9hqL38aXJ/mW3n3bnU9wgucaqjJ02V04bSfo0MDlJfHUOKqZr5NIpvgX7+vh6dCcXyNMV5O0Vx15SZlO17l6dpvNd6tSobLRTU9YyVHKiscjkUvX6wvjZHk9GY2KlZiSonzWqM73VVo5DEFvvbI9G1UOxIqfLZu9WhUNmr5rfc6e4U6q2WB6PaqdaLqbKZ9UC3zKSG5tbtSwOjn1ToRyaO9OhrFTsdqqaGFtGHV5Da7eJL7Et67CUZf26pli3fM6e5VPfM9lpuVVERXNe5NfSYnEGOJ7vZW2t1DHAxsm2iteqrr5T0YXy6u2I7V7oUU0DI0crFR7tF1PdJlHiBq75qb8s8ay5x146M9U9nUz3dUmiDxVL2Oa9i6ObwU9NyvV1roGwVVZNLEze1jnqqITCPKXEH22m/LO9mUWIHJ+70qfzyiONkNaKLLj2jha6uaKxeqqu8zODMMXTFV6htltgc9715ztOaxOlVXqJxHkviCSVqOq6NjVXeu0u5PMWFc71hzJjCCUFrSKrv9VHvd06/Kd1N6k6S5XgTj59/mxRayNrwklXiefN8vZ7Wdl9uGGskMIpbrakVZiSqj3qqb0X5TupqdCdJrTernXXm5z3G5VD6iqncrnveuqqpyvt2r73dJ7lcqh9RUzuVz3uXVS4sgcokvSsxXitiU9lg+EjilXZ5fTfquvBiekosnPMmq61pFcl3e1lVVVOyqZX3y1m+b7W+5HmyNyhlv8AsYmxNGtPZIvhI2PXZWo06V6mdandnpmwy5RvwnhNzYLRCnJSzRJspKibtlunBiek7M/c30vW1hXCT+97LD8HLLGmzy+nQnUxPSUcLb40w6mn8X3/AOinEw7cu1ZeWv8AGPYva/aAAR5PHJXvVuyr3KnVqcQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAd1FTS1lZDSQMV8sz0YxqJvVVXRDpLo7lDCKXrGcl+q4dqktTUczVNyzL4Pm0VfMX8al32xgu0w9oZkcPGnfL+1f9F+Wq1xYJy0t9hgRGzcijZFTir13vX06EXkVVUz2M7j35dHta7WKLmN+tSP7W86/szGWPQkjirnK6crJ829T6mupJ8C0CVV2bK9usdOm2u7ivQn1+QjcOirv00JZerpFgfK24X6XRKjkVkYi8Ve7cxPUvnKdq5KooftKoVSumq4c29CucXZ1VVqzxgs0MzPe/SytpatuynOcu5z9exV9BZeP6FG1cdazRWTN2VVOGqcPR6jRetqpqutlrJ3q+aWRZHuVd6qq66m5OT199++UFKj5EkuFC3veXVd+2xOavlTT0mk7C2nLyl7z5/I2zpLsWvDx6raly82X6mMeiop8a7RTnUoqPXdpqdGp0fXVGpLSSJtg6aC52qssVa1JIZo3NVqr4THJo5PT6TTLMbDk+FMZ3KxzoulPMvJuVPCYu9q+ZUNp7HXPoLhDUtXcx3OTrb0oQ3uv8LtqaC24yo2IuyiU9QrU4tXexy+lDRelWB/yxXt/U2Poln+TZjok/Nn81yNaQAaIdSAAAAAAAAABZPc0fwyWX+l/s3FbFkdzV/DJZf6T+zcZGJ9fDxRH7V+w3f4v5GzGYP+uuP2Jv1kWXwiUZgr+3X9E36yLLxOy4P1ETi1Hoo+tXnEzsC/8AwS9on2qb+yIYzwiZ4e/2IvSf8qX+zMXbH2ZlxfWQ8V8zRd/hu8ZxOT/Dd4ziccO6oAAAAAAAAA5Mc5jkcxytcnBUXRSycu858W4TljgnqXXW3NVEWnqXKqtT713FPUVoC5VdOqW9B6Mx8nEoyobl0VJe03gwtiDC+ZVlWvss7Yq1iJysL9EkjXqcnSnaYW50ktJUPhmarHt4opqjhDEd1wtfILvaKl0NRE7VU15r06WuTpRTcbDt5tuZGCYL5bkRlWxNmWPpjkTixexeKG9bB267H1dvM5ht7YUtlyVtXGt/B9xGVf4xtO6znPGrHKioqeM69Td001qQSepmcN3SS3XBkuq8m7myp1t/RxK07rjBrY6qlxtb4U5Kp0hrVYm7b05jvKm7XsJmxyopLEoYsX5fXHDtUjXOfC6Jqu6F01Y7yKieY1zpFs9ZFDmlxMzZWc9nZsLux8H4M0bB33Clloq6ejnarZYZHRvRehUXQ6DlrWh2dNNaoAAHpsr3F37xxJ+Mg9TyYXlP2dP+Md6yIdxb+8MS/jIPU8l94X9nT/jHes6R0T+o/fech6Sf1a38Pkjwoh3QomvA6t52RcTbpciIlyOHdN6fqE0en26m+ipqMbb90yv+guk/HU3qU1IOQ7c+1Pw/NnSuh39Pf+T/ACAAIc2sAAAAAAGTw/f7zYKxtXZ7lU0UzemJ6oi9ipwVPGYwHqbi9UUzhGa3ZLVGy2VmetJd1ZZMcRwwyP0ZHWNbpG9fv0+KvahY+JMPrTxd+0K8tSOTa1TfsovBdelO00iNgO5qzVnpa6DBeIpuWoaheTo55V1WFy8GKq/FX0G0bH29bTNQseqNB2/0WhCLysNaacXH81+hOHRubxPqNJFiy1tt9Z8GnwEuqx9nWnkI85yIp0im5WwUo9ppMGpI76Z2y5FRdFTgqdBJMW2GjzHy7qrTVNYtdGxVgkVN7JUTmqnYvBSJo/RdxIcGXB1LdmMc7SObmL4+j0+swNqYiyaGmVRtlRZG2D0cXqaWV9LPQ1s9HUsVk0EixvavQqLop0Ft91Phv3GzHfcYY0bTXWNKhunDb4P9Ka+UqQ5HfU6bHB9h2nByo5ePC+PKS1AALJlgAAAAAAH1EVV0RNVMjQWC+V6olDZ6+p14clTud6kPUm+RTKcYrWT0MaCb2/KbMSuRFiwtXsReCys5P6WhmIshsy5E19xoGfhVcafWXVj2y5RfuMKe1MKvhK2K/FFYAtJ+QeZTU19yaZ3irI/aY+tyYzIpUVX4bmk0+1SMf6lPXjXLnF+48jtbBlwV0f8A9Ir0EjuWBMZW7VazDF2iROlaV6p50QwNRTVFO7YqIJYnJ0PYrV9JacZR5ozK7q7OMJJ+DOoAFJcAAAAAAAPqNcu9GqviQ+7D/kO8wGpIsrv4RsPf+Qh+khuLmP8AvuDT7WvrNO8sWvTMTD67Dt1whXh9+huDmPI1ayBE4pGvrNz6Ir+Y/wB9hzfpu/8AyafB/MiHSd1PpqefaO6ndzjocuRqEuR4O6yX/Rbav+7j+gpqmbXd1bG+bKy1LExz0SqZrsprpzFNVeQn+0yfkqch22n5UzpvQ5r+GLxZ1g7FgmTjDJ+Sp8WKVOMb/wAlSH0Np1RwBy5OT5DvMfFRUXRdwPT4AAAAAAAAADshgmnejIYZJHL0Maqr6DOWzBOL7kqJRYbusyL0pSv08+hUouXJFudtda1nJLxI+CxaHJTMmrajm4efEi/bpmM9amQbkBmSqarbaNPHWR+0urFufKD9xhS2vgxejuj70VUC0Z8hMy4mqqWeCTT5FXGv1mFr8psxKJFWXCte9E6Ymcp9HU8ePbHnF+4qhtTCn6NsX+KIQDKXDD1+t6qldZbhTaceVpnt9aGMVFRdFRUXtLTTXMzYzjNaxep8AB4VAAAAAAAAAAAAAA+oiquiIqr2AHwHupbRdqrTva2Vs2v2uBzvUhl6LAONaxNafC13enX3q9E9KFShJ8kWp31Q9KSX4kaBOIcpcxJU1bhWvT8JqN9Z3/qOZkaa+9iq/Kb7SvqLPVfuMd7RxF/yx96IACdSZRZjR8cK1y/goi/WeSfLLH8Kavwld9PvaZy+o8dNi5xZUs/Flysj70RAGdqMHYtp1VJ8M3iPTro5PYeCez3aDXl7XWxacduByetCjda7C/G6uXKS954QfVRUXRU0VD4eFwA+oiquiH3k5PkO8wBxNue5aT/QvUL/ANTUepDUjYf8h3mNt+5e2osmKhJGuai1M6pqmnQhLbF+1o1Xpg//AI7/ANkcpk5xwam875kRXdJwa1DsCZzOPGJLsvP37P0fBJ6zTTMb/b2+/wDfzfSU3Ny80SunRePJJ6zTjMmmqGY+vqOglT9nS8WL8pTnPS1fzV++w3DoTwvu8ERoHZyM32qT8lT5yUv2t/5Kmn6HRdUcAcuTf8h3mDmub4TVTxoD3U4gAAAAAAAAAGQt9kvNwVEobVXVOvDkoHO9SHqTfIplKMVq3oY8E3t2U+YdeiLDhavYi8FmZyf0tDMw5C5lSJqtop2fh1cafWXY49suUX7jCntTCrekrYr8UVeC1l7n/MlE1S3US9nfjPaeSqyMzKgRV9wmyafa6mN31nrxblzg/cUR2xgS5XR96K0BLrjlnj23tV1ThW6I1OLmQK9PRqRutt1wonK2soammcnRLE5vrQtShKPNGZXkVW+hJPwZ5QAUl4AAAAAAAAAAAAAAAAHfT0lVULs09NNMvUxiu9QPG0uZ0Az1Dg3FlaqJSYbu0uvyaR/sMmzK7MF6aphK6+WBUK1XN8kWJZdEPSml+KIcCZLlbmEn8UrqvigU6ZctsfRJq/CF507KR6+pD3qprsZSs3GfKyPvREweu62y42qpWludDU0U6Jryc8Ssdp4lPIW2tDJTUlqgAAegAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE2yLm5DNfD7uura3z7jYXN9uziKF3y4E9aoa0ZYTpTZg2KdV0RlbEv9ZDZ3OhqMu1BL1xKn9ZSd2c9caa9qNO24tNo1PviyGxv2Woi70RSwcmKhJMQVsKrqiwsX+tp9ZWrZNEdqqaEzyQqkdjCrai7+9vU5pmVS85Ijcyv+TJ9xqxiiPkcR3CLhs1D09JdWFXcvkkzp5NHJ5nfpKmzKp1pswL5AqabFbIn9YtHLF/L5Q10PFY3PT0IpGbO4Xzj7GbNtN72LVL2xITY4lqsaWumRdUfOzd5Scd1Dctq5Wi2tXmxwrIqIvSqr9SIRXLGDvnMi2LxSJ+0vkOfdDVSz5hvi13Qwsan5J7ru4c33tIo3d/aFa9WLZGMKwOrr/baVjVVZaljdPKhuDm1VNorNQ0Me5u3pp2NRET1mrWRVP33mpYYXJq1KlrlTxbzYnOSp2rrQU6rwjV3nX9BVhLSicvwI3bst7Lqh3Js+YGYtXfqKFU3baOXxJv+oxvdQXBZbrZrS1dUihfM5O1ztPU30mcyoVsl/c7T9zhVfPu+sr/PGvbWZrVUaLq2mjjiTf0oxNfTqXrNepS72R+FFPMb9VGSyietE+rubm7qKkklRep2mjfSqEXqq+WpubX85dX9faS3Ds0FJgC8zyuWNJ5Iqdrkbru3uX1IRGCqszatqrVzK7a4cj+k9lXpGKL9U962yWhIKPCl+v1zrZbbSSSsjkVXO2kRE1XhqvSefFTK+3ugt9RysMkMDY5I1XguqrovnLGwfmRhaxRVdtrnzQ/DLI2VI9drXTdu8RX+YuJbXiPEc1xpJJWwua1jNpmiu0Tiu89k4pNIsVO6dvnR81EetyPdWt1VfOfYvCemmq6nbbpKXvlipKv5B9tkcVTXJCx6aveiauTRELMo8DNUtG2ywsu6BKeyXCte+ha+WLZaydd+zrxQl1a1vL1unuLut7en/O/9Binoynp6qnbLZHsgomRsXXXX9J6quaOndcaiR9hc1lubzWprr2J2/oLlcdOBC5Fjslvd5kmJHJ38ipYl2bczTzLw7f0HvSGmWVGPbZNl1sciKi7kKsy3ur5ZrzRyd4o6eBzmrOm5unQnaTqSqkjqU0fYE0tq7k4FUXqtUW7q3XNxZUOK7f7nXmemR7Hta/muY/VrkXeioYqt/cotFXwV6e0nuaNI6ejtl1RaBU73ZFIlMvDiqKqecr6rdGjImufpoi9HaWZLRsmMezrIRYoHPSZd6+CvT2KIZX8s3cvHrPtCsHKrz/ir8XsOUC0/LN5yceopaeiL7a1fAuqORGxYY+Dtbubv239nxv8APE+Uior7ZpBYFVa6Vec9denj2dXkOhskarhxHJZ9hrVVNpd/D4xyoJYeUtvOw+3SrkXRUXVOPHs6vIZcE9812T839+0i1ZjKC2VstC+xW2VYK58223ejt67k7Dxsx9S8m5XYdt+ytb3wm7h974iPYsWP3drV/Y++Z37mvN49HYR+q2e9JE20TnIW5Wzi+ZMU4dU4ptcy1rBieyXKoSGWgtFJI+uSdFl1RqJ8nVOgz9bFTMqoJFpLE1H3PdsyqqabP0ek13cuy9NJEJJgTElVTXamtk7qaSkfUNf+yG6ta7hx4om8tPLb4SKrdkpLfrf4FnyTQsqonMZZG6XV6I5HKvQu78Eq7MawpC9t6ppadWz1EjJIoZNdhyLx06icVD9meJNbI7S6PXTgn/8AyfaWNK+gdSSusPJT1M7FVV0VurV369XV5CprrFussU2PHnvr8SjGq/lX85ePWZCRr0sz3bTtUkTp7DjNQx09fNDI7ex6pqiaouintelIlokR0j9Ntu/Y8faYsIvjqbBZYno0duDK+elutPI2R3Mka7j1KenNWm5C91rWpox0iuZ+Cu9PQp4rJLbmVUek0uv4v9JJM2YmTtt9YzhPRRrqqaaq1Nj+6Ze7rjswnPdzIvvRKe55q0ueXtdZ5V2lp5XM3/Je3d6UUhNXG6mrpoV3Kx6oZPuaKtYbve6DXc+JsiJ2oun1mJzDqH0eMK2JE0RZlVE8anspa40Jd3AtqGmdbBdujLUpE918nbhRuTaVtLKz8nnJ9RqnEqNkVq8UXQ2eykq1rML19K5NyvVun4TVT6jWCrTk7vUQruVsrk9JY2g96NcvYZWw04Tur7nr7zMUuI7tbKdYaKungYu9WseqIp5pca4jVf8AW1X84p7rBhS84mlfBaaZZpGN2nJqiaIZN2TmOVX/AFX53oYahfJeanoS0rMOEtLHFP26EdbjfEycLvVfOKckx3ilOF5q0/pFJEzJbHLv/wAexPHK07kyQxyqfvKL55p6qcvsTKXlbN7ZR+BGFx9i7ov1an9IpgbjXVlyq31ddUy1E7/CfI7VVLG/UMx6qc2hhX+maTHLHIyeir3XrHboKego/hOQ5RFR+m/Vy9DT1YuVa1GSf48iiW09nY8XOEo69y01Zi8icqGXViYsxYiU1mp/hI45F2eW036r1N9Z1Z65uPv6vwzhh3etig5jnx81ajT1M6kOvPXNd2IHLhvDarS2ODRiqzm8vp4uDepCnU3qe3XRqj1VP4vv/wBFGJh2ZNiy8tcf7Y+r/s+An2AMuqq+RpcrrItDa2ptLIu5z0Tjpr0dpYlNh3ItGpG+8tV7dzldO7ev5JRXg2TjvNpJ970MjI2tTTNwScmue6tdDX0GyMGGshl3reKfy1Dv8JkKfDeQKKirdqPy1Lv8Jd/h0vXj7zFe361/xT//ACav6KSLAWCsQY2u3udYqNZnJvkkcujI063KbGNsPc/o3fdqDT/uXewnuBafB1mwDe6jLd9NVSsY96uiftqsiN1ai6pqVQ2dx86Sa9hiZPSRqt9XVJPsclovxKDvPc1YxorY6qpbjba6djdpaeNXNcvYiuREUpWupaihrJaSrhfDPC5WSRvTRWqnFFLvyJxlj65ZuQ0tTcK6sgqJXJWQyuVWNbv1XTo0MN3WFJSUubM60rGMdLTRyTI35apvXxlq6mt1dbWmuOnEy8LLyoZfkuS1Jtapr5MqMAGCTwAAAAAAAAAAAAAAAAAAAAByY1z3tY1FVzl0RE6VN08rbEmA8pKWnkYjK+pZy03Xyj04eRPUa6dzphL305iUzqiPaorf+yZ925dF5qeVTZzHdw5atbSMXmQpv0+UptfRnB62zrGv32nP+mefq4YkX7X+RFqhyudvXedPiOTtVUMRVXQ6UjSuSMlhuhWvukFOrVViu2pPwU4/57Sv+7BxZtzW/B9JKmxEnfNUjV6V3Mavk3+UuDDC01kw/XYhr12IYonPV3Uxiarp4/qNK8ZXyqxJii4XuserpauZz+PBOhE7ETRDQulOdr/Li/Z+ptHRHB6/KeRJcIcvFmILj7lTF/uFjhbLUybNHdkSNNV3NlTwV8vDylOHfQVU1FWwVlO5WSwyI9ip0Ki6mm49zptjNdh0HPxI5mNOiX9y/wCjdLGVClLdZNlNI5fhGeXinnI+reolFtucOM8ubdiGn0WRYke9E4o5Nz08+8jsrUa469s3JV9CaOKuEqpuufNPQ4R7nEvo6KkxbgevwzcERzXxLEir0a72u8i+oiGuhmMK3HvC7RSOXSNy7EniX9JXtDHV9DR43KElOHNcUadYhtdTZL5W2msYrJ6WZ0T0XrRdDwF992BhZKPEdFimkh0guDOTqHNTdyrU3Kvjb6lKEOQZVDotcH2HaNmZsc7Fheu1cfHtAAMczwAAAAAAWP3Nf8Mlk8cn9m4rgsfua/4ZLJ45P7NxkYn18PFEftX7Dd/i/kbL5gL+3S/i2/WRd3HgSjMBP26d+Lb9ZFlXedkwvqInFqPQRyZvUmeHf9ir1+Kl/syGNXfxJnh1U95V6/FS/wBmYu1/szLn98PFfM0Xf4bvGcTk/wAN3jOJx07qgAAAAAAAAAAAAWv3M2MZMOY7itlRNs2+6LyMjVXc1/xHefd5SqDspppKapjqInK2SN6PaqdCouqF6i502Kcewxc3Fhl486Z8pI3XxtQpTXJ0jG6MnTbTTr6fb5SN6KSymrmYnyztN/bzpHwMkevbpsu9JF5E0cqHX9mXq7HTOJqEqpyrlzT09xwa3tJNgao5C7tjV3NmarVTt4p6l85G0Pba6haathn+1yI7zKZORDrKpRKbY6xKD7payts2bVyWNmzFWo2rZomiLtpzv6yKVobHd2ZaGaYfv7EXbeklLIvY3RzfpONcTju0KuryJRR2DYGS8nZ1U3z0093AAAwyYNle4uX9g4kT/mQep5MLx+/p/wAY71kO7i796YlT7+D1PJheP39P+Md6zpHRT6j995yHpJ/V7Pw+SPEdkfE60OcfE25kRLkdfdML/oLo/wAdTepTUk207pZf9BdH+OpvoqalnItu/an4fmzpXQ3+nf8As/yAAIY2sAAAAAAAAAHOGR8MrJY3K17FRzXJxRUOAAN1Mvr63HuVNLcHOR9fA3Ym6+VYm/8AKT1mGmbo5Suu5AxA6lxRcMOyP+CrYOWjaq/HZx9Cr5i18SUnetzqIUTmo7VviXeh07o1mddRut8Tje2sJYO0J1R9F8V4MxOuh3U8rmSI5q6OauqL2nTopzjTnGztJrQjZrVHn7qG1MveVdNfI49ZqCVkiuRN6MfzXJ59k1NN5KqjZfsq7zaHptK6kmYiffIm2306GjjkVrlavFF0OUdIaOqyte/8jonQrJc8OVL/ALH8GfAAQJuQAJLl1gy743xBHarVFu8KedycyFnSq+wqhCU5KMVqy3bbCmDsseiXNmGtFsuF3r4qC2Uc1XVSroyKJu0ql7YE7nGrnhjrsZXNtBGqarSwKiyJ+E7gnk1LUwphvC+WdrSktdO2ouL2py1Q/wDdHr2r8VOxDz3S8Vdc9VqJVVOhibmp5DcNmdGJWpTuOd7T6XXXSdeH5se/tfh3HfZsK5ZYSY1LbZKaqqGfZZGcs9V69p27zGWdjBIm7FHb4o2JwRV09CERWRVPnE22jY+LStFE1O+duRLetm5P2sk0mMbm5eYynZ4mqv1nSuLLwv2eNP6NDAbC9R9Rjuoy1iUL+1FnqYGfbiu8fb2L/RodseLroi85YHeOMjatXgcV1QPEof8Aah1NZM6fGtU3dLSUz07NUFdd8KXuJae+4dpp2O3Kr4myaeVd5ClV3WfNt3WWLdk41i0cSuCdb1g9H7DhijIjL/E0Uk+Fq11oq1TVI2uV8eva1d6eRTX7MjLLFOBalfdSj5WiV2kdZBzon+Xii9i6GxEFRLFI2SORzHN3oqLoqEqtmIKe40rrXfoYqqmmbsOWRqK1ydTk+s1vaPRaG65UmwYHSjNw5JWvfh7ef4P9TRgF35/ZOtw5G/EuF43yWdy6zwJzlptelOtnqKQNGvx50T3JridLwc+nOpV1L1T+HsYABZMw217neks1Pk5Bc6q0UtRJy8nKOdC1znc5ETeqEz918Np/Fyl+Yj9hEcik/wD4+w/jn/2iHokTRx0vYmDRdixc0cW2tKcs+7zn6T7WSRt4w9DKk1Ph6ljmbva9sMaKi+NEMFe62S51SzyaN3aNanQh5V1Pi9pP0YdOO9YIj93V6t6nRyS9aHJkbkXXU7DkZWpcZIrViFIaJtJXUsdVE3wdpEX0KetL/YkTfY4PmWewiaHxUXqMGez6LJatFvc05Nr8SX++CwLxsUC/0LPYfPdzDi8bBT/MR+wh66nzeW3snFf9o871n72Tm21uG6+tjpWWGla6RdEVaePThr1GqHdIUdJQ5tXSCip4qeLZjdsRtRrUVWpruQ2Nwkq+79J+Ev0VNeO6b/hgun4uL6CGodKMWvHjFQRtfQyU3nSTk2t3v9qKzABph04AF5ZF5NsvMEeJsWsdDbE58FMvNWdPlO6m+sv4+PZkT3ILiYWfn0YFLtuei+L9iIDl1lpinHE6La6JYqJHaSVk3Nib5eK+JNS+8M5D4Gw9EyfEta+61Kb3Mc7Yj17Gpzl85N67EFPRUjLbYoI6WlibsN5NqNRE6mp0eMjk1S+V6ve9znLxVV1VTeNn9F4JKV3FnONodJszMbVT3I+zn7/0JDR1WFbHGkFisFLA1u5Fjhaz08VPsuMKzXSKlgYnaqqRhXKvWNlV6zZatmY1a0UTXJwdj3ptt+16mffi27L4LoWeKP2nD313j+Us+bQwXJqo5JS8sWhf2op6mBn24uvCcZol8caHdHjK6t02mUz/ABsVPrI1ya9QVrk6Dx4dD/tR51MCXsxk6VNirt0MjV4ojuPkUxt2w9lnixrm3ewUtPM/dyrY+Sei9e0z6zApqh9SRU6TFv2PjXLRxL1MrKHvVTcX7GyF4+7m6ZlPJcMEXNK2NE2ko51RHr2Nem5fLoUDd7bcLRXy0Fzo5qSqiXR8UrVa5FNw7RfK22yo6nlVG9LF3tXyHuxnhnDGadldT3CBtNdIm/A1LETlI18fxm9imobU6MyqTnTyNs2V0uupkq8zzo+t2rx7zSMGfx5hK74MxDNZrxDsSM3xyJ4ErOhzV6UMAajKLi92XM6LXZC2CnB6pgAFJWAAADOYPwnf8W3FKGw26Wrk+O5E0YxOtzl3ISrJnK+vx1cUqKjbpbNC74afTe9fkM617eg2epKix4OtLbJhmiggZGmjnNTp63L8ZxM7M2NdnPXkjV9t9JatnvqalvWfBeP6FZ4T7nO1UMLKvGF6WZ+iK6CmXYYnYrl3r5EJ/a7Ll1hpqNtOHqN8jfj8jtu/KeY6tuVRVyrJPK6Ry9a8DzLIruk3nE6OY1C85as0DL2pnZj1ttencuC+BLFxbHEmzS22JjehNdPUh1OxhWr4MFO3yKv1kXXVT4qKS0cDHjyiRjoi+ZJ0xfcdeFOn8z9JyTGNw/5P5BFdlRsuKvIqPVPOpgiWtxlX/JgX+Z+k5txrWpxhp1/mr7SHaO1PujjzyHHf9o6qBNG44qkXfR06+JVQydixD7s1bqSWhjbzFdrrtIvkUrlNSUZfO0vW/T9xd60MTLwKIVSko8SiUFHijUvOinhpc1cSQQRNijZcJUaxqaInOXghECZ54rrm5idf/sZfpKQw5NetLJJd7O6YLbxq2/VXyLS7l6gpLhmvSxVlNFURsppnoyViObqjdy6KbQXCvw9RVklLJYKV7o10VUp49F3a9Xaa1dyUmub0H/Zz/RL3xan7e1eifZPqQ2/ovjV3wkpr98DnPTGUv4hGKbS3V2+1mUW8YaXjh2lX/wBeP2HVc8RQPoForfRMpYXJoqNRGpp2Im4jG8Lr2m5V7Mx65byXE1Zpy4Nt/ifXb111Cbuk+a6KNTPLmnAyVmuMtuqmzxKirporV4KhIVxJZ5l26mzxSSLxVY2O18qoQ1F6j6Yl+FTe9ZopceOqehMPd3D6/wD4OH5lnsHu3hxeNigX+gj9hDucfFcqdJj/AMJxu4aP1n72TH3Vw0q7sP035vH7CI90VbrLLk7W3GC10sEqLE6J7YWtc3V6JxROpVEUio4Z/Sa5CzprxWFP66ENtvBpoxpOK7GZuyZTW0KfOfpLtZqAADmx2oAGXwlh27YpvcFns1K6oqZV4JwanS5y9CJ1nsYuT0RTOcYRcpPRIxlNBPVVDKemifNLIuyxjG6q5epELqy97nu+3eKOuxPVJZqVd/I6bU7k8XBvl39hbeAcvcN5ZWyOpmjZXXyRvOnciKqL0ozXwW9vFfQd14vdfXuVHybEXRGxdE8vWbbsvozK9Kd3I59tXpfZKTrwlovWf5I5WDAmVmEGN5C1wXCrZxlqE5d6r5eanmJCuLqenZydBbIoo03Im5qeZCDI559RXG34+xMWlaJGoX33ZD3rpuT9rJbNjC4O12I6dniaq/WeZ+Kbsq6pURt8UaEdTaU5bLtDMWFQv7Sx1cDPJim8p/vTV/o2+w5Mxbd28ZYneONDAcm7qPitd1HvklD/ALUeOqBKoca3Fvh09M/yKn1ndLie2XCNYbtZYZ43blRzWyJ5nIQ7RUG0qFqezcaa0cT2Ne69YvQ9V8ytyqxW1VgpUtFW/g+mXk11/BXmr5Cn8xe59xRh6F9dYpG32ibqqtibpMxO1vT5NS10kVDNWTEdfb3I1siyxdMb19S9BA53RemxN1cGTWF0gz8JrSe9HufH48zSqaKSGV0Usbo5Gro5rk0VF7UOBuRmPlthnMu2S3C3sjt1+Y3VJmtRNt3VIicU++4mpWJ7FdMN3qe0XelfT1cDtHNXgqdCovSi9Zo2bs+3DnuzXA6LsfbdG04eZwkua/fNGMABgk0AAAAD34ftFwv13p7Va6d1RV1D9mNjfWvUnaepNvRFMpKKcpPRI8cMck0rYomOe9y6Na1NVVS4su+5/wAT4giZXXx7bHRO0VGyJtTPTsb0eXQtzLPLbDeXFuiuV0ZHX3tzdVlcmvJu+TGi8PwjM3nEtZXuVm3yMPRGxfWvSbTszo3ZfpO3kaDtTpfJydWFy9Z/kjE2PKvK/CrW8vStutU3i+pXlV1/BTmp5SSw3yzW9iRWuywQsbwRsbY08yIRZ0yu6TirlU3DG2Hi0rTdNPyb8jJe9dY5eLJU/GVT8Sjp2+NVU4e/O4dENMn81faRfRVCsUzlg46/tMTqYEqTGlx6YaZf5q+09trxbWVVbDTvpqdEkejVVNUVNfKQfZUyOHkVLvScf3VvrLduFQoNqJTKqKRWPdnsT3yWGTRNp1I9FXTjzygDYDuz1/8AkNgT/o3/AEzX85RtH7TM7B0a/pdPh+bAAMInQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD3WCZaa+UM6LorJ2O/rIbcZ1NR9FaKv4r2rv8iL9Zp5A7ZnjcnQ5F9Jt5ms99TlVYa+JqvdyUSrp2xp7CX2bL+VYvA1bb8P8AyceXtaK2bO1GuRN5Lcj6hExu9qr4cD08ya/UVsyapRF1if5iS5RXCWlx3R7cb2pIrmaqnW1UMjHk3ZExcyn/AMexewr7PWk72zYv6aaI+pdInl3/AFkvyRck2BL5T8dlyrp42L7DA90g3ZzQrZNNOUZG7+o0yfc/SK+lvVJvXbY1UT0fWWMZbuc4+JI5Et/ZcJeyP5HVkpFt5jLqngMk08ymDzn2pcyrkumuionmQnGUuH7vbcdTVVZb54oHMeiPczRN6ETzVRv6odzV274QW1yjhpNaecKLIyz3KL181Hr7nGDXNm1qqeAj3eZqly5uKrsV07ddzYG/WVV3Pb425q2/RE/c5E/qqWlmxIiYsj1+0tLuMtMZ+JF7Vblnx/xM/k7GnuhVyL0RInpKYzDn5bNi+87XSukTzOVC5Mn5m981nXsNX0lHYxkambF9V7dU7/k+kpdyOEIeJibOWuRb4E5ukUzcrqRsTFVZq6Ry6J8ljUT1qVk2mrkrmqsL97uo2DtGJ8MW/Lu3NuOHUrEbNK3fMqc7RqqvlRU8xiPf9gHldG4Ji11/lC+wruqUmtXoW8XLtq3lGvXiysHYfxBfMTT0Nrt81TLrro1NyJ1qvQey+4VxBhuKJLvb5Kfb1Virvaunam4vTL7MDBst9loorZT2eWdn7s6VNHqi+Cqqm48ufWIsPy2GK1wVVNU1XLJJoyRHcmiIvFU69eHYY8qYpN6l+vPvlZGt16Ioe3TvbVx81N69JOMsaRVnuV0dJQsSmhcjW1C+E52qbkIWtVCsjNhkSrtbi0sOJBa8K11L39Z9qWmZM5skaq9FdrzUXr4HlNW89e4ubQt3K9F2komXlGVv7Jsf7zYuqInmTtMTmjcI6e2R0LJLY59W2NX97N3ta1Nd6+NfQe+lq6aSeqZ7pWHXvBqN0gXRvHcnaVbjTEbLriWeVEptiNEiZsJst0ammqIXZaQXiReJB22L2cTstOxQ35tS3Y46KnQqLxLfuGws8r2VNiRFt6aJslDyVek+1zNdOOpauEby2vw7yktVaonQ0b6dyTR6uXRdUXzL6BDRJpF3Og3uzfgZetpYblZZKCWqs7Wvt7dHM3ORUXVNO3UpG8UT4J+SdpqxNF39OpdNJXQ8iid/WLRLdp+57/EQjM6mjju0NcjKLZq6aOXSFeai6aL6izYnJalzAsVct3TmQGl1bO5OpF9R1RTOSVvDwj1Mczvhyo2PpPDyzUlbzIvCKd3RLiS3NvgXvSyPSlws5ZrTFx5zkRVTd8Y9ttmVJbei3GxbquXcrE1Tj28P0GFhlaykwnI6eyRc1V1e1VVPwjtt9dGk9u0uOHUclbKuixLqnHevZ1eQzYrzzV5rWPv/ADK1xg1FxJcNXQO+GdvZ4K7+gjVUukEu5PDMpiyt0xFXfvR+sz+dH4K7+jsMPJPtQSKrI969Bjycd5myURahH8Dw6bTtNA1FiqGytVEcxUci+I5tkRHeAzzHORzXa81iGPKK7DM1ZasFatwtdquMtVaGvqK1ZHMc1Npir8rfwPfh+pjY+lZ35Y0Tv2XXaYm7jvXsMHYpoY8K2ONauztXvnaVskSq9u9fCXqMnZqunR9Gvfth1SukXnQr06717OryGVCOrRrlqSUl4/mVVjd6MxbcY41ieizv0dGnNdv4p2Hinoq11jme2J29yKm4z2IKugZjaqnmhp5mJO5VWNNGO39CdCFw0+ZeCmYV5Cow9SPjY1reQ3b/AC6FuvHU3LVkpdl2UQr3Ib3I1ttENWlazWN6b06CxcxIZfejh+ZyaKsEjF8kir9ZKIcw8v31CJDgOkR2u5e+FOOcl6tVzwlYZ6K1MoWObNpG16qic5OsrhWoVSSepbsybLcivehukF7nxXNzAq2bWiOpXa+hT1Zt07W4zmVfjI1fQh05EbK5hVD2ponezz35uN28YO0+Qz1IUrXyP8TIsf8A8lr/APVEoyW2WUdbHr8Zi+s11xJGkOKq9ifFqH+tTYzJ2JyR1nVoz1qa+Yzhd79Loifyl/0lMXKk3TD8TL2Vwy7vwO2yYwvGHJ3zWmpWCRzdlXInFOo9783sduXVLw9P5iGCpMO3i7SrDbaCaqk012Y2qq6Hc/L/ABm1dFw5cfmVMRW3JaRb0JeVWI5a2KOvt0MqmbuPE4Xp/wCQhyTN/H6cL4/8hvsMQ3L/ABo7hhq5fMqdjcuccu4YYuS/0SnvW5He/iUOnZ3aofAyn6sWYScL9In8xvsMdiLMnGl/tzrfc75PLTOXnRpo1HePQJlnj1eGFbl80ff1Msf66e9S5/MhzyJLRt/ERjs6DUluJrwIgTbBOG6Zsfu7iBeRt8XOax25ZP0E0wJk3eqViXbEVjrpVZzo6OOPVyr98eHHmEMysQ1+zBg25U9BHuhhbGmiJ1r2lyGPKpKco8exfqWbNpVXzdNc0l2y1XuRGMdY8rL2nufQbVJa4+a2Nu5XonXp6iFE6pMocxqirip/ercI+Uejdt7ERrdV4quvAtCt7mC4xWRZafEMUtybHtLCsSpG52ngo7j5dDx1ZGQ3Jpsq/iGz8GMa99LX8ffoa6g9Fxo6igrZqOpjVk0L1Y9q9Cop5zD5EsmmtUfdV6yeZOZl3PLq9vqqaPvqinRG1NM52iPTrTqXtIECqE3B70eZbvorvrddi1TNoa7uj8JUNFPU4ewesN1nbznuRjW7XWqtTV3oNcsVX644lv1VebrNytVUvVz16E7E7DFgu25Flq0kzEwtl42E3KpcX2viwACwSAAAAAAAAAAAAAAAAAAAAJXlNhiXF2PLbaGtVYXSJJUO+TG3e70JoVQg5yUVzZautjTXKyfJLU2R7nPDqYSyxfeayPYq7l8OqKmiozgxPLx8p31kr5pnyPdq5yqqr2kpxtVR08NPaqZEZFE1NWt4IiJo1PMQ9ztVOtbGxFj0LQ4pk5MszInfPnJ/9HHTeey10r6qqip4050jkah5WJqpM8v6FvKzXGbRI4UVGqvBF6V8iesz8q5U1ORYn3Ff91diOOwYGpMKUT9ma46coiLvSFnX43aeZTVAm2d2Kn4uzFuVxSRXUsciwUydCRt3J5+PlISch2hkO++UtTr+wcBYOFCvTi+L8WAAYRMGw3ciYsVKmuwbVv1imatRSoq9OnPb5t/kUsi/UTqKvlp1Tc12re1q70NSsEX2ow3iu3XumcqPpZ2vVEXwm685PKmqG6WJVprtZKK/ULkfDNE1yOTpY5NUXyfWbz0WzuHVS7P2jmHS7B8ny1kRXCfzX6kOU5Mfopxk1RynDVUXib3oazzRJsW2dmPcqq6zOa11Y2PWBV6JWJq1fLw8qmk1RFJBPJBK1WSRuVrmrxRU4m6+B7gtLc0he7SOfm/zuj2eU157pvCi4ezEmrYIdiiuid8Rqic1H/HTz7/Kc56T4HVz6xftG49DM/csnhy5PivzKqABqJ0QAAAAAAFj9zX/AAyWTxyf2biuCx+5s/hksn4Un9m4yMT6+HijA2r9iu/xfyNmMwP9dO/FtIq7iSrMH/XTvxbSKrxOx4X1EfA4tR6CPrNdSY4e195V6/Ey/wBmQ9ibyYYf/wBir3+Jl/szG2t9mZc/vj4r5mjT/Dd4zicn+G7xnE46d0QAAAAAAAAAAAAAABtp3LNe67ZSVlqkXaWjqJIm69COTaT06nrqG6OIr3FVZrBiS3KvTDMiflIv1ExubdiqlZ8l6p6TpnRi1yx0vYce2/X1W1LUu16+9HiO2Ljw4nXodsXE2gi5cjyd1HB39kxSV+mroKuB+vUjmq1fSqGpZuTnRElV3PNw1TVY44nJ2bMrUNNjkm3obuWzpHQyze2e490n+QABDG2myXcXfvfEiffQep5Mrx+/p/xjvWQzuLf3HEnjg/vk0vH7+qPxjvWdI6KfUfvvORdJP6tZ+HyR4E4HZHvU61OyLTU20iJcjo7pjdkbRp/zqb6Kmphtn3TH8BtF+OpvoqamHI9u/a34fmzpPQ7+nf8As/yAAIY2sAAAAAAAAAAAAluTt29xczbDXK5WsSsZHIv3r12V9Zt5j+n0q4ZkTc+PRfGi/pNHKKVaeshnauixyNcnkXU3sxg5KiwW2rTfyjWu17HN1Nu6KXONric76cUpW02rt1RB14n1vEPTRyhvE6MaeTTL53KMrKZeDkRdPHqimkuL6FbZiq629yaLT1csfmcqG6WXkmlzmb1w+pUNUM+qTvPN3EUWmm1VukT+dzvrOfdLK9JqXt/I2zoTbpk2196T93/ZBwAaYdIPZZbbWXi60troIVmqqqRsUTE6XKuiG5mDsP2zLPBsNso2xyXGdu1UTab3yab1/BTgiFUdyPg6Kpq63GdczVtIqwUm0m7aVNXv8iaJ5VLKxFXPrrhJPquzroxNeDU4e03PozstWPrpnNul21JXX+R1vzY8/a+78Dy1U7p5XPe9XOcuqqq9J0K3U4Iq9Z6aKOSaZkcbVe9y6NROlToGigvYanwijjBTySvRrGOc5V0RETVVJTasI1MkaS1j207NNVTiunb0IdGKMRYeyxw17q3ZUnrpEVsMDPDld1J1InSpq7mHmxi/GVVIlTcJKOgVeZR0zlYxE7dN7l8ZqW1ekcaHuV8yY2VsHJ2n58fNh3v8kbQ3a8ZaYeTZuuI6HlE4sSflHfks1MDNm5k5AqtSsfLp0sopF9aGn6qqrqqqq9anw1azpDlzeqZttXQzDiv5k5N/gjb1M4cnpF2Vnnb2rQu+oyNtxplJepGxU2IKSCR25ElV8PpciIaYg8h0gy4vmLOheDJebKSfj/o3omwvR1kHfNmuMNVEvBWvR7V/nNI3cLfU0Uqx1ETo3dvBfKaq4VxViDDFcyssl0qaSRq6q1r12Hdit4KhtPlJmXaszLa6z3aKOkvkLNpWt8GVE+Oz60Nj2X0m62artNX2t0ZydnRd1ct+C596PPpocmO0U9t4t8tBWPp5E3tXcvQqdZ4UQ3SMlNKS5ECmpImWEbhHWU8lluDWzQTMVrWvTVHNVN7V8hqZnbgxcE47qrdEjlopvh6Ry/a3Lw8nDyGxdDO+nqGTRro5jkcimK7qywxXvLqixRTsRZ6B7dpUTesUmiLr4l086ml9J9nxcOtivb+pP9F8+WJnKpvzZ8Px7DVAAGgHVzcTud6eKtyQoqNZ2t25ZFXRU1bz9fqJc7CcCr+/vUaKQ1lXCzYhqpo2fJbIqIc0uNwT/fqn513tNixOkNuNUq4x5GjZvQ2WTkTuV2m829NO/wDE3jlwpEjfg6zV3QmiEZuVK+jqHQy+EnT1oay5Y3CvXMOwtWtqVR1fE1UWVV1RXIbaY7jalbCqImqx7/ObXsLbE86TUkaptnZEtk2wg5728teWhG0VNeJzY3VTp4Kd1M7Vxs74Ijm+BIrPhuSsp0nlkSJjuG7foZD3owdNavoK97qeqqKPK+1tpZ5IduqYjuTcrdU2F6jVr3TuX8vqvnXe00XaPSK7HucEjYNkdGp7Sxlkdbu8WtNNeX4m8i4TpE43BE8aofFwtQ9NzZ+U32mjTq+udxrahfHKpxWsq141U3zikf8ASvI7viSv0Hfbf/8Az/s3wtdgoqGuiqm3GN6xqq6K5u/dp1mqndNSQy5vXJ0MrJG8lEiq12qaoxNSue+6r+UzflqdT3Oe5XPcrlXiqrqRm0dr2Z8UpomNi9G1su93dZvarTlp+Z8AOcET5pmQxNVz5HI1qJ0qvAiDaC0O53y+bjDEjrjc4VdZ7eqOlRdySv8Ais8W7Vezxmw2Kbu2VUoKPZjpYdG6N3I7T6kOvCVgjwDlhRWhmjayZm1O5OKyOTV6+TgYOTVXKp0vo5syNNXWSXFnINu7RltHLb18yPBfr+JxVyqu85NVVU+IxVM/haxrcJ9uXVtOxecvyl6jZrbYVRcpEPOW6jos1oqri/SCLmpxe7c1CQz2OxWenSe/XempW6a6yzNiRfFquqlT5x53ssUsuG8D8ly8PMmrdlFbGvSkadKp1r5Os11vV5ut6rH1d2uFTWzvXVXzSK5fSaLtHpNJTcKjadl9FcjLgrb5bkXyXb/o2+r8xMn7Y5zJb5BUObx5KKST0omhjn5zZPMXRHVTk60oHfWpqGCClt7Lk+ZsUOhuAl5zk/x/0bhU2bWTlW9GLWyQa9MlHI1PRqSO2z4AxExFsuI6KR7uDG1KI78l280aOTHvY5HMc5rk4Ki6KXKukOXB8XqWb+hWJJfy5yi/ebu3bCtbSor4FSoYm/cmjvMRqRjmOVHIqKnQpSOWmcmKMJVEdPV1Mt1tWuj6ad+0rU+8cu9PUbLU0lmxthqLEeH5WyI9ur2J4SKnFrk6HIbdsnpDDK8yzgzTtq7FytlyTn50H2r8+4inlPVb6mWlqGTQvVr2rqiocJIUY5UU4oiIbO0pLR8iMcVJGWzTwpR5mZfSLFE1t4omrJSuRN+2iaqzxO9ehphNG+GV8UjVa9jla5F4oqG7mCbitLdWROdpHPzFTXp6F+rymufdPYaZYMzaippokZS3ONKtiImiI5VVHp50VfKc36S7OVFnWRRuvQ3aMlKWHN8OcfzRVgANUOggluVOC6zHOLILTBtMp2/CVUyJujjTivjXgnjIkbedz5htmDMtFu9XGja+5ok7kVN6N+xt82/ykhs3DeXeodnaQm39qfw7Ec4+k+C8e/8AAklwWiwzZoMO2ONIIYI0bzeKJ4+teKqRaRyuceusmdPM6R6q5zlVVVelTz7Oq7jrmJjxx61GKOSJNtzk9WzrQ5sarl3Ip6KWjknlbFGxXPcuiInSZy/V+G8u7F7sYhqGunVPgoW73yO+SxPrUt5mdViQ3psqjCy2arqWsn2I6bXhy4ViI90aQxr8aTcq+TiZh+HrLbmbV2vEEHWskrIk/rKa1Y8z3xdfpZILPL7h0C7msgX4VyffP4+bQq6ur66umWatrJ6mRy6q6WRXKvnNJy+lc5PSpcDbMPoZkWJSyLN32LizdSsvWV1BuqcU21VTijarb+jqY9+OMn2LouJKZfEkq/3TTIEY+keY+TJWPQnE/usl8P0NzG44yefuTElMn82VPqPTTYgypq1RIcWW5qr8uo2PpIaVALpHmLtEuhOG+Vkvh+hvJHS4Iq/3piq2yKvBGV8TvrMtYrNRUNb31S3KOo5it0a9q8fEaCoqpwO6Grqof3Kpmj/BeqF36TZEo7slqjFn0Gh/be/xS/UlWdTmPzWxK6N6PatwlVFRdUXnKQ8+vc57lc9yucq6qqrqqnw12ct+Tl3m8UV9VXGvuSXuLZ7lGeGnzbgdNKyNHUkzUVy6ars8DaG52Gira2WpdXtasi6qm03duNB43vjcjmOc1ycFRdFO7v2s/lc/zikts7a88GLjBGtbZ6NfxLIV6s3eGnLX8zedcKUi+DcEXzGPvGHJKOBZ45EljTju3ohpSlfXJwrKj51TaruY6ioq8oq3vqZ82xUzI1Xu1VE2U6zYtndI7si9VyRqu2OjUtm4/X9bvcUtNNOf4nrkbop1qdsq844oqam9pmvJ6o9Fso5a2pbBEnOXpXoTrJLFhSBE0mrka7pTcnrGX8cbq6VyoiqkX1moealwrlzGxAnflRolfKiJyi7k2lNW27tqzBmowRJ7G2PLats4Ke7urXlqbge9Si0/1gieVB71KH/iTfO32mjK11avGsqPnFPnflX/ACqf5xTXvpXkd3xNi+g8vv8A/wDn/ZvOmFrem9bmz8ppEu6JbR0+S9dSNrIXuY6FGJtoqu56dBqItVUrxqJvy1OD5pXpo+V7k6lcqmLl9Ibcmp1zXMycPod5NkQud2u609NO78TgADXjdznBFJPMyGJjnyPcjWtRNVVV4IbkZQYSoctMEMqKuFjr5WtR1Q5fCRV3pGnY3p7fIUv3LGD479jN97rYkfR2pEe1HJudKvg+bepeWLbj35cX7DtYouYzfu7VNt6NbMV8+tmuBz3pftSUprCrfDnL8l+Z5blXS1lS+aaTbe5d6niVUXjodOqqpzi1VdNDosYqK0RpmiSOxseqmYtGHK+4Ij449iL7Y/cnk6zJWG20NFbn3u+SR09JCxZFWVdGo1PjO7OwpbNXuhrjWSy2rBDVt9G1VYta5qcrInW1Pip6fEa9tXb0MTzY8zN2dsvI2lPdpXBc2+SLrrLLh6yw8pfb3TUu7X4adsSL4kVdVI5V4/yht71ZLf4JnJx5NksnpRNDUK53K4XOpdU3GtqKuZ66ufNIrlXznkNQu6S5U35vA3GjoTjpfzrG37OH6m4Dc18nddFuDvH3nL7DIW7HGUd1ekVPiGlie7hyqvi9Lk0NLwWY9IMxPmX5dCsFrzZyX4r9De9MPWm5QrNZrtBUs46slbK3ztUwN2slbQKqzQrsfLbvQ08tF3uloqW1NruFVRzNXVHwyq1fQXnlbn/VMlitOOWpV0z1RiVzWpts/DTg5O3j4yawOlMt5RuILaHRDKx4uePLfS7OT/2TtW6HzgSi+2imko23a0vZNRytR6KxdU2V4OTsIvJzVN3x8iF8N6DNVjLXg+Z7rVXT0VS2aB6tcnmVOpew+5yYHosycGLcbdA1t8omK6BU8J+m9Y169ej9Jj2vVF3EhwbdXUVybG9+kM2jH6ruRehTA2ts+GVS9VxLtGRZh3RvqejX70NJ54pIZnwyscyRjla5rk0VFToOBcvdWYOSw43bfaSJGUV3RZF0Tc2ZPDTy6ovlUpo5NfS6bHB9h2fBy4ZmPC+HKSAALRlhE1XRDbjuf8DUeC8FpiW5xNW618SSaqm+ONfBYnau5VNe8k8NNxVmPa7ZMxXUySctUfgM3qnl00NtsdVrWzRW+LRscLUVWpw103J5E9ZsvR3AWRbvvsNG6ZbSlCMcSD9Li/DsRHbvXT11U6eZ2rl4J0NTqQ8GmqnNztV3hu9TpkIKC3UaGoqKOCIeqho6iqlSOCJ8jupEMnh2yvuc+m9sLfDdp6E7TAZo5w4fwEr7Hh2lhuV1Ymki7XwULvvlTe53YnnIvaW16sKPHmXsXEyM2zqseOr+XiTKgwhUPbt1c8cLelE5yp5eBznpMFUGrbhiWghcnFJK2Ji+bU1CxdmTjPFErnXS+VPIqu6nhdycTU6tlPrIk9znqrnOVyr0quppmR0pvm/MRt2N0Jk1rfdx7kvzZvCtflii6Li606/+QYem31OX3fMc1Li20OexyOanulFxTs1NEwYv0jyu0yn0Ix2vrZfAvfuw7hQV2I7GlDXU1WkdI/bWCVr0TV/WilEAELfc7rHY+02rZ2EsHGhjxeqj2gAFkzQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD61dHIvUpsJh3P6z0OErdZq3D01TJSQtjc5ZG7LtOC6Khr0cmse7wWOd4k1MjHybMdt1sws3AozYqNy1SNhnZ8YWfxwj6Wf4Tg3PfDUcjZIsKbL2rqjkcxFT+qUA2lqXeDTyr4mKdrLZcX+DQ1K+KJTLW1srsfwRHvo/s/tj8WSzNfGNJjLESXWmonUvwTWKxztrXTp10Qw+G8R3GwSSSWydYHSN2XKicUMdNaLnBDy09BURRp8Z8aoh5445HvRjGOc5y6IiJvUw5XWOzrG+JJ149MalVFeavxJgzMTFsciPju0zVMPX3SuulwfXV0zpZ5F1c9eKqdEdivSuREtdWq/inHdWW6utqxpXUstO56atSRqtVU8pVKds157ehRGuiD8xJP2ExyLq3QZqWhyr4Uis86Kha+c1TJFiGnk03Ohb6FUo7Lqq7zx1aarXRGVDPWXnnjTKslDUJw5zF8i6/WSGM9cWXsaNd2nFLaFbfamj15LXJ0l0q4l6YdfM5CsMxoZIc07wqppt1Lnp4lXX6yZZOyLDidiOXRJWOZ6NUMXnnRpT5hNqeCVFPG/Xr0TZX0oXrG5Y0ZdzMfGjGvPnHviZWhtdffsC960bodunqtpeUmaxNHN63KifFMdbMuLzPVMjfXWiJznaJt3CPevkVTuw5I2TC1yh11VqRzJv6l0/vGGgqNK6JW6t0enBe0uSgpqMmWoSsrc4w7zhj7B96w5fpKOpkhWVER3wcmqaKm7tMbTUlY6lRXpqu0nEsDP+Tax9LxXagiX+qQRki96poieEWnStWZVGROdMWzLYUs76y6azTU0EcLFkc6Thu4J5VLVr656vuMa36wP0o401bTeHx5qb+gjGX8T6CyXCpSrtUUtVSLqypRVds7SJonauhLZquq/bVG1+FlR1FEio1vFNF3N38f0F+FW7Eh83IdlvHkjtdXP2biiYksnPt7Wq5lNvXVFTZTfxIXNgayR1NYiYppZORpknRUi8N6/ETeT2rqqpsVzbNW4YREoomKsaa69SJv4/oOi51E7qm76VeGUT3PjauynHsTfx/QVqmEvSMaGRZV6HDX99xCp8EWRVnR+J4NY6Vs7dI/CcqeDx/zqZfD9roMOw1sdvxRSSMqKHlHpPBrv+Sm/iSCrmrElr9ajDa/tYxqqnVou5N/H9B31c9YjJXLUYfbpaFTmpx9PE9ePWuKKZZl0luyeq/fsMa2sY2DdfbE79qlTR0Gi/g8eP+dDH4to471hZ7oaq1TVFJRwSosD9l6NRFRW6dPHVfEhmpqmpSlWVbpY262Xd8Brtb+HHcv+dBbqvR0kcl1sbo1tLNtEg0VURF5vHj1+ox+r1ehcrtcUp6cv33FI01PJyq6ubuRfjdh4ooJFeirseESbE9nfaMQVNKslOrUTaaqdTm6p6yMQOax6aqzwjHUdODNhjYpreiXax0jKPCelRY4dhF0WTerd3xzlQVMnL25vuphzdXSrorN6cd69nV5DpfUMZDhGRlZYY05N2+SPVW/h79512qvY2e26XPDrVSsmXfT728eO/gvQZzaVhre63DXTv+bKvxfGsmIa2XapXKszl1i8Bd68OwwkyOSnkRGt4oZXFdTtXyq/e7tZXb426NXf0dhiJUV9O/ZROKbkMGxreehs2PF9XHX2Hj1ftImiIeqhikqa2OnasaK9yN1cu5Nek40FtrKysiggh2nvXZanWqlh4ZsLLFNT1vuxbmV61PISRyM20iTTjrrvLKjKXLkXb74VLTXieiWrSmpqGiiuVqdFS1aRxqkeq6Imm0vYeqw1ap3uq3S0Nayskem1DrpuXevYdLlkdJTa3a2L+2L96U/DjzvEvUYzE15faMPRxw3CjlnqZ5dY44NHMau5Xa9SmTF6cWQjr6xqEeb/AH3EDv0slbeaufaiVZJXO1buRdVXgdM9LUyWqRrE2ucnBTqSRHSv1VqrqvQexV1tsu/4yfWY0Um2T/GCSXZoeKy2ut78YqxO0TiTzNWN9NhzDtPwVtC6RU/Ckd7CL4ehWWpYiaqqr1ktzyekVfSUSf7pb4IlTqXYRy+lVMqEFGhsw7ZuzLgn2amM7naJ0mKrlUrwjptPO5BmncYvfpUN1TmK1PMiGa7m6hXvC8V6pokkjI2r51X6ivcfufUYuuE6Lq1Znaec9nrDDh7WyqEI27Ss9iSLhycq2Ot1ZN0I5ies10v9ybLieun6HVDl9KmwOVsC0eXVXWyc1XJJJr2NZqaxVDlkq5X8Vc9V9Jj563Kq/aZOx4qWRe+7RE4wrmBccKVjqy2JHyrmKxdtu0mikhf3QWM1XdHQ+WFCvrLhW/33VLVbpqlWpqqMbwQyrcrMeO4Ydq18hiQlkaeZroSF2Ps+Utbt3X26ErTugsapwjt/zCD9cJjjoZb/AJhCNMyjzCdww3Veg7EydzFXhhqq86e0r6zLXeY7xdjdqh8CRfrhcc/It3zCD9cNjn7XbfmEMAmTOZC8MM1Pnb7R+oxmVr/sxVedvtPeuzO9lPk2xe6HvRIU7ojHKfYrZ+boff1xWO04RWz83Qj36i+Zf3L1X5TfaEyWzLX+K9V52+0dfmd7Hk2xe6HvRKbf3SON4a2GSpp7bLTteiyRtg2Vc3XeiL0Ft1vdGYHZYnVlM6tkrlj1bSLDoqP04K7hpr0mvn6imZn3LVX5TfafUyTzMX+K9V+U32lcMrLhrzfijGyNm7FvcW5RWnc0tfEhV+uc13vFXcp9EkqZXSOROjVdTwFjtyQzOcu7C9T5XN9pzTIvM9f4szfON9phum1vXdZNR2hhRWitj70VqCzP1Ccz/ubl+cb7S0Mksl34abXYtzCtjdmgjWSnpHqj0XZTVXKnqRSqGLbN6aaFnJ21h0VuampPuTTbNapKSqjiSWSmmZGvBzmKiL5ToNssDZ1WTHeKXYOu+F6SnoatXRUiro9F46I5NN2vWnAofPTCdNg3MSttVFr3m5GzwIvxWuTXZ8nA9sx1GHWQeq5HmHtKdt7x769yWmq466ogoAMYlgAAAAAAAAAAAAAAAAAAbQdyZhZLVhyvxjXN2XViLHT6pwibvVfKvqNcsK2aqxDiKgstG1XTVczYm9mq718huzeaemw7hWgw5QIjIoYWxoifJanHyr9ZPbAw3fkb3cab0x2h1WMsaL4z5+C/UjN2qn1dZLUPXnSOVfEnQeHpOyXVXdJxRp1SKUUkjncVojsp2Oe9EaiqqroiIe/OvELcD5STU8EiMr65ve0Wi6O2nJz3eRPWh78FUHfV0bI9uscPPd4+j/PYa/d1Lin3ezCdbIJtuktTOQaiLuWTi9fPu8hqvSbO6qrcT4kz0ewfLs+Kfox4v8ORUqqqrqvE+AHNzroAAANp+5axK2/YKrMKV0m1NQfuWvFYnexfWhqwTfJDFK4TzEt9fI9W0sz+96lOtjt2vkXRTO2dkvHvUuwhdv7P8uwZwXpLivFGxdxpn09TJDImjmOVq+NDybJM8dUDUnir49FZM3RVThqnBfKnqIk5qJ0HXsa5XVKRyKt6o+QK5j2uRdFRdUXqPbnjh1uN8o5K2njR9fbkWpjROPNT4Rvm3+Q8bERF4ExwBWsSWW3TaOjnbq1rk3Kum9PKnqI/bWKsnHaL+PkSxL43w5xepokqaLovE+E3zuwlJg7MO4W5sTmUcr+XpHKm50bt6aeJdU8hCDk1kHXNxfNHase+N9UbYcmtQACgvAAAAsbubP4ZLH+FJ/ZuK5LG7m3+GSx/hSf2bjIxPr4eKMDav2K7/F/I2YzA/wBdO/FtIqvEleYH+unfi2kUdxOx4X1EfA4tR6COTOJL7Av/AMIvf4iX+zIgziS+wb8EXtP+RN/ZmNtb7NIuf8kPFfM0bf4a+M+H1/hL4z4cdO6AAAAAAAAAAAAAAAF+9xdIqYuvcXQ6havmentLPviaXGpTqld61Ks7jD/ba8L/APX/AN9pal+33Oq/HO9Z0Pom/wCT++85P0pX/wArLwXyMYpzj4nBTnHxU3Ag3yMvmKzlcgL01eilevmfqaVm62Pl2cg72qr/ALnJ6XGlJyvpF9rf4/M6D0J+yWf5fkAAQBuZsj3Fv7liVPxP98md3/f0/wCMd6yF9xZ4OJU/Ef3iaXf9/VH4x3rOj9FH/wCP++85H0l/q1n4fJHhOyLicDnHxNtZDy5HR3TP8B1F+PpvoqamG2fdM/wH0f4+m+ipqYck279rfh+bOk9Df6d/7P8AIAAhjawAAAAAAAAAAAAb1Vb+Xy0sEy71dS06+eJDRU3mammVGHkdxSjpv7NDZOjP2r3GjdOF/IqftfyIrL4ZwOUvhqcU1RTqBoi5Ely/cqXzTricnqNcO6jiSPOa7aJ4ccLvPGhsdgFP2+b+Lca691Q5FzmuenRDAn/9aGjdLeXuNk6Hf1GX+L+aKsAPdYaN1wvlDQsTV09QyNE8bkQ0WKcmkjp0pKMXJ9huNgG3NwvktaqJibMs9O18i9O1JznehdDDyORXEvxq1KS32+3s3Mjj007EREQhbuJ17Y9Kqx0kcNla77p2y5ybZ2NYjl00JdgqhhhjqLrVKjIoGro53Bu7Vy+RCJQLzk1MnmjdFsGRdxnjXYlqYuSavTrIui/1dRtfIdOO2e10vIuhSv7mkax5xYxqcZ41q690jlo4nLFSRqu5kaLu8q8SGAHI7JuyTlLmzt1FEKK41QWiS0AAKC6AAADJ4WvNZh/EFFeaGRY56WVJGqnTpxRexUMYD1NxeqKZwjOLjJcGb1X2opr/AIVteI6RPg6mJj0/BemunkXcRF6aKqHLIuuW5ZBQRyO2lo3SQpr965HJ9I4TLz1Ot7Eud2KmziOTQsbKspX9raDV0VN5Lm0keIMsbvZ5mo/bppomovXs6t9OhDkdvJrlvLqlZCuioqNd60L21q1ZjtMsObrnGa5ppmikrFjlexdytcqKcTL40pEocX3ijRNEhrZmJ4kepiDj8luto7pXLfgpLtAAKSsk2VKa5k4dRf8AiEX0kNvsffvyH8X9ZqFlT/CVh3/yEX0kNvcffvyH8X9ZunRH05fvsObdN/tVPg/mRReJ203hnV0ndTeEdAfI1KfIxXdZJ/oxtP8A3bPoKaqm1XdafwY2r/vGfQU1VORbb+1PwOndD/6ZHxYABEG0AAAAnmQlkbfc07PTSs2oYZe+JE60Ym169CBl5dx5QtlxndK9zde96PZavUrnJ9SKZWFX1mRCPtIzbWQ8fAtsXNJ/HgXjmDVcpcmwIvNiYm7tXev1EV4mSxJUcvdqmTXXWVUTxJuMW1d52LFr6umKON1rzT0UzFfIjUTVVXcenPbETsDZXLTUUnJ19f8AseNyblTVNXuTybvKd2GYknvNJGqbllRVTxb/AKio+7Cu8lTjehtCPXkqOlR+z0bT11182hrvSfKdVG7F/tkxsHEjl7RhCS4Li/w/2Uc5yucrnKqqq6qq9J8AOanXwAAAAAAXL3KmMJbLjf3vzyr3ldk2GtVdzZk8FfLvTylNGRwzXyWvENvuMTtl9NUMkRfE5FL+La6rozXYzC2jixy8WdMu1fHsNw8XUqUt2laxNGP57fKYTUl2PGNkbR1TN6SsXRezcqesiGu87HhWdZTFnFK9eT7DupnuZK17F0c1UVF7UML3XtDHXYDst7Y1NqCq2NpPkyN19bfSZiJdHHbnjTsru5/q3OTadA2J7V6lbIjfUqkP0kpVmM/B/qSWx7ep2lTP26e/gafAA5admM5gGzLiDGdps6IqtqqpjH6fJ153o1Ny8bTMgipbbDzY4mIuidCImjU8xrn3KNuSszUjqXM2m0dLJJv6FVNlPWXxi6blr1ULxRrtlPJuN36JY6bdjOadMsh2ZkKeyK1/FmFVVVdTlHqqocdN56aKJZJWsTiqoiG+Sei1NUlLREksjqOyWKsxHcnpHBTxOftL0NTjp2qu5DT/ADJxjcsbYnqLvXyO5NXK2nh2tWwx67mp/neX93Vd89x8CW7DdM9WPr5NqVE3fBs9rvUatnLukOdK6919iOg9DdnRhQ8ua86XBexf7AANdN1AAAAAAAAAAAAAAABtl3Laf6Haxeuqn+ihqabady1/A3V/91P9FCW2J9rRqvTH+mvxR6JvCOHSdk3hHWnHgdfRzOPokwy9X9mT/ik9Zp3mn/CRiH/yE30lNxsvE/Zc/wCKT1mnGaP8I2IP/ITfSU550t+sX77DbuhH2i7wXzI2ADTTpAAAAAPTa6dau5UtM1NVllaxE8aoh6lq9DxvRas23yQtCYWyZgqVbsVdx1qHLpv525v9Xf5Tqldq4mOLYmW6w2y1RbmQRtYidjGo1CGO3qdc2JQqsZHEMi95OTZc/wC5sInUZ/CNrSvuDeUbrFGm2/t6kMHE3VyITClrosNYAuuIZdPgIJJk1+9TRqef1mRtLI6ihyLLjKySrjzb0KK7qfMKW43l2DbVMrKCid+zFau6WX5Pib6yiDvuNXNXV89bUPV808jpHuXiqquqnQchyb5X2Ob7TtGzsGvBx40wXL4vtYABYM4AAAAAA2H7lLHzu+H4Fu0qyQzorqBz112V+NH4l4p4u0sfE9tW33KSFqfBrzo/wV/zoah4Xuk1kxFb7tTuVstJUMlaviXU3cxksNxs1vu9OiOjmY1zXdbXt2m/57Td+i2c9eqbOYdL8CONlxyILRT5+KINodsLtHHxyJtcA3wuCG+PuNZfFHsz3tCYsyUlrGt26u3IlS1U483c/wDq6qadG92FY2XHDF0tUibTZI3sVF6nsVDRi4QOpa+opnJosMrmL5F0OW9I6FVk6o3/AKE5Lnj2Uv8Ateq/H/o6AAa8bsbEdxjaGvuN8vsjU0hiZTsVehXLtL6G+ksG+1C1Vwnn11R71VPF0GC7kxne2Vd4rE3K+rk3/gxpp6zIzqiuU6T0WpUcfe/fE5B0hudu1LdezRe5HVoeimiWSRrWpqqroidanSZzB8KTX2la5NUa7bXyIq+vQ2a2e5By7iIm9EeDPLFP6n2XLaS3ybFzr1WGF6Lvbu57/JwTxmnUj3ySOkkcrnuXVzlXVVUubuvbw6tzIhtTX6xW6kY3Z13I9/OX0KhS5yLauTK/Ik2+R1ToxgRxcCMtPOnxf5AAEabEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADaPuLX2qssV9oqu20dVU08rJWrLC1ztlUVNEVU6zVwvDuN7ylDmVPbHu0ZcKN7U7XN5yeoycNpXR1IrbcJSwp7r4rj7i/KjHlkppXxx4UpmK1ytX4KNOHkEOYNM9fgbBTt/JT1NINjqmWjxXXU6bmukV6eJd/wBZ5KBqMkbq70ky9N9pI01VKValq+PtZNs254cXZJ3WpZRtjmplR+wmi7KtcmunkU06p3LT1MM7E0dG/U3RwDFDcbRe7DKrXMqYFVG/hNVq/UahXi2uo7rWUkjdl0Mrmqi9GimDnQ0kpInNgW6RsqfY9feWvWXuu9z6K4U9XKyN6NVyI7cY7PijbVUdpujd6SR7Ouvl+sx+HZ21+DFp1dq+nXTTsJBiSNLxlJDMnOlonc7ybvVoZql1tMovtWvuLTfUZMJLsenv5FSWxEp6yCdPCjka70mzWPmw3bBFHcmptJpHLqn3zd/pNXWyKiaopsTllXpiHKh9C5dqanY+HTxc5pa2c1Lfr718ivbsJR6u/wBV/MwWEZ0o7rTVKbuTlaq+LUzPdH0OtJarxEnNYroHOTqXnN/vENguDYpHMXc5F00LJxBpi3KWZrG7c0UO01P+ZH7U185fr0nTKtc+ZH2t05Vdz5a6P8SusvKmOepWjlfoypifCu/pVOb6dDHzNpoa/Y5SbaR/SiacfGR7Dla+nqWKiq2SN2viVFJJieDaucNfAxeRqkSRNOhV8JPPqWIWOVa9hIW1Rhe9e0kmflQiY4aqqm+khXd+CQ+21DppYYU5JEe9EVVTgnWSXPpj1xhAqIi/sKHo+9OnLShhlfV1dRW0dI6lpXyMWZqLtu002URV47yh6uzQt1OMMSMvYWFWXJIIqyliulgdHHbo42L3u5dUT4qffdanc+5OV10ctywsrG0Mau+AVNpERdze32oeGqrEe65KuIrMu3b4tdIG8/71N/Ew2adfFHY5WNuVmrpZnRRI6nhRHsa1mqqiou5NV08hlOzRN6kNCh2TUWuf+vYV1ia/112udVcNYIeUk5rIk2WNToRE6jGR1dUq6rMuq9pyYxvervB8JDimmnBCP1k3q2bOoQjHdUeR3vrqpsuiSr5z1xVtU6F+1Nru6VMZKjuV10PVTKvJP5rV3Jx8Z4959p5uwSXAtPKS8VElpvFBJW0EKJRvVvfDFdqmu9rScU1z2KmR3uzZU/adG7qdfyfH/nQpDBV3ktV8hnbyDWO1jk201bsuTRdU8pcS3TYq6iNL5YdPcpGNdySaKifF48f86GRQ21xITaFUY2PRczB5sU8E1HR3SK42qabkkSRlKxW6IqbtU86FQKqq9F22eEXjcZ4rnQNo6i9WBY321U0SNEVF13N11466encUY1qJVKzWPTaLuTHimmXdlz1hKLXIvSmmelLg/wDZ1hYjWu0V7FVW7vj/AOeJ10VTIye2Klxw2n7PmXVYl5vHevZ1eQ7KSopu9sJtiudjYsLHI5XRIqsX77fv9B8pJ2sW1qt6w61ra6Vd8DV2eO9d+9PN0GTure5kRx05d/5+wxaJTSup5ZpcMvc+6P2ldCuumq71+8O6B1LGyPYXCqL7pKmqwL4O/f8AgHKKugbHRIl5w/r7qPcusCc3evOXf4PZ4g24UjYWOdebCipdFeqJTp+Vx8HsKtYrTiVrffY/3+B2Udc+GRvJVmGmIl1VU+BVNO1PvD2d9vWqhT3Qw63S6vVHMiVeKcfwTDsvNvi1fJerI1EuiyL+xkXdp4X4PYYDEWYsNuex1rqKOsqWVUsyKlGjY01TRF111Xr0LV04JcyunGttlpGP79xKb1eYLTb1ram8W2TYuEskcNNAm25ya6Lv4N10Kbvdxmu9xfWVUqPe52vDRE38EQ8V2u1xvNbJW1siSSyOVzlRNE8idB52K9HImwnmI6y1z4LkbDiYMcdat+cehsLXVDmta5VVehCS0eFL1VWp0sNsrHRvVNl6QuVF8uh35aW1a69yVlcxI7ZQpy9XK5NzWJ0eNeCISnE2c2KqimetmnjttIyVGQRxMTVGdGqnsI6LWRTfbNz3KuOnPUx+X+Dq92IaKKqpp4WLK1X7bFTRqb14p1IRrN+tWsvVxqtv92mc5qa9Gu5C2cO5hYkbgC73S8XB06yRpS0yPamqyP4qnibr50NfLrJVX3E9Ja4NZJZpmxonWqqXb24VqK7S3gKVuRKyz+0vPK2lTD+U8dTLzHyMkqlVfFonqTzlNKiV1RLIrtpXyKvpLezxuUWGcBQWindo57G07ET5LUTVfUUjl42puWJqKgZtOSWZqO7E13l7MklKuhdi+Y2bFzhblvtb9yL0xQ9mGsj5dV2Xvo0an4Ui+zU1VY/R21066mwHdS3pYLPbLDC7ZSVyyvai/Famy36zX2JrpHoxqKrl3IiGLteet6rX9qSJHo/U1jO2X97bJVh7H+IcO7XuTVJBtpo7mIuqeVDNtzsx+3hdI0/oGewxlHlfjKtoo6yntT3RSN2m6uRFVPEckypxyq6JZZPykLEY5iWkVLT8TKs/hs5Nz3W/boZVueeYTeF1j+YZ7DsTPjMVOF1j+YZ7DD/qTY7/AOCv/LQ5tyix67hZH/loNM3ul8S069k90PgZdM/MyE4XaL83Z7DupO6CzIhqWSSXKnmY1dXRupmaOTq3IYRcnswtlXNw/M/Toa5FUhl2ttfaa+WguVJLS1MS6PjlarXIviLc7MqvjJtFdeHsy/VVwg/DQ2WbmrjDFOG3XTCl3jp6yBvw9E6Bjl17NxXUvdAZoQTOilucLXsXRzXUrEVF8xXWFL/X4cu8dwoZFRzV0exV5r29KKWVirD9Bj+xe+nC8bG3BifsukTwlXxdfrMnrbMmOsH5y5rv9qML+HYmHZu2VpwfJ6Lg+5+zuZ1t7onMtP8A8lTL/wCsz2HP9cZmX0XGm/NmewqGRj4pHRyNVj2ro5qpoqKcTC8ot9Zkn/CcF/8AFH3Fvr3RmZvRc6b82Z7DivdFZnf8VpvzVnsKiB55Rb6zPf4Tg/dR9yLcXuiczlTT3VpkXr71Z7CcZSZ7zXuerw9mNWxLTVzFZFVcmkbWaoqK12icF149BrWCuGXbCWuupZv2JhW1uCrUde1LRo2swzl/lngC+uxlU4xp6qKFVkpYnSsXYVeG5qqrl6ihM48XtxtjusvUMbo6ZUSKBruOw1NEVe1eJD1cqpoqqqeM+C3J34bkY6Lme4ezHRa77bHOemmr4aL8AADGJUAAAAAAAAAAAAAAAAHdRU0tZWQ0kDFfLM9GManFVVdECWvA8bSWrL77kPCLp7rV4xq40SGlasFMrk4vVOcvkT1loYkr1rrlLNrzddlidTU4GQs9thwRltQYfg0SdsSMkc34z13vd9XmI1LJqp1Do7g9RSpNcTjW18/+IZs7Vy5LwQ4rxOcbUVTpRTI2KFlRc6aCVURj5ER2vUbDOW7Fy7jAk9EZu93aDA+WVdfqhUbOsSuiavF0jk0Yn1+c0graiWrrJqqZyvlmer3uXiqquqm5efuX2KceW2326xVlBBSQOWSVk8jmq53BOCLuRPWU5+tnx7/LbJ+cP/wHL9s9flX6qLaN56LZGDh4znbYlOT48ezsKRBdi9zTj5OFXZV/9h3+E4/ra8f9FTZvzl3+Eh/I7/UfuNo/jez/AL6PvKVBdP62vMD+UWb85d/hH62zH/TU2X85d/hPPJL/AFH7h/G9n/fR95Sx9RVRUVF0VC6U7mzHnTWWVP8A2Hf4Qvc2Y60/f1k/OH/4CryLI9R+4p/juzvvo+8uLJLEXv5ykjgqZUfcaBO95NeKq1OY7ypu8h5KnRj1RdyniyEyvxlgC+Vc9yrbbJb6uHZkihlc520m9rt7U7U8pnMYU7aa+TsaiIjl20Tq1/TqdD6O3WSr3LFozlu1lRDOn5PJSg+K09vYYnaToPTb6uSmqYp410exyOTxoeI5IuhszipLRmDJao6+6iw3HifLumxRRM2qm1892nFYXbnJ/NXRfOalm9WEHw3W0VtgrU24Z4nJsr0scmjk9OvlNM8wMOVOFMX3GxVKLrTSqjHKnhsXe13lTQ5b0hwXj37y5M6D0N2h1lEsWT4x4rwf+zAgA143UAAAFjdzbvzksf4Un0HFcljdzZ/DJZPwpPoOMjE+vh4owNqfYrf8X8jZnMD/AF078W36yLKm8lOYOvu0v4tv1kWdxOx4X1EfA4tT6AbxJfYE/wDhF7X/AJEv9mRFnEl9h/2Gvn4iX+zUxtrfZmXP74eK+Zo0/wANfGfD6/w18Z8OOndEAAAAAAAAAAAAAAAbBdxbAq4hv9VpzWUrGa+N2v1FjXl+1X1DuuVy+kivcaUqQYYxFc3pptzsjRexrVVfWSOsdtSOd1rqdI6Kw3aNTkfSSe/tWz2aL4HnVew5xLqvA61OyHwjayHlyMpmnJyHc+Xdy7tqmRv5UqJ9Zpebh90BP3l3Pk8a7nT97Rp5Xo71IaeHJ9vz3st/vtOi9C4aYMpd8n8kAAQht5sh3FnDEv8AQf3iaXf9/wBR+Md6yF9xZwxL/Qf3iaXj9/z/AIx3rOj9FPqP33nJOkv9Ws8F8keJDsjOrU7GKbayGlyOjumtf1D6L8fT/RU1MNs+6Z/gOovx9P8ARU1MOSbd+1v99rOk9Df6d/7P8gACGNrAAAAAAAAAAAAPqJqqInSb23hne2ALLTaeBBAzzRoaQ4bon3LEFvt8bdp9TUxxIn4TkQ3hx85IaOipE+I3XzIiG0dFq3LIb8DQenFi0pr9rfyITJ4SrocfGfXLvPiHTGaSiUZesVb0q9CRO9aGsndJVDanOS+OauqMeyP8liIbS5cx/s6eTobGiedf0Gnubda24ZmYiq2O2mPuEqNXsRyonqNB6Wz85R9q+RtXQuvXMsn3R/MixM8kaVKzNfDsLk1RK1j1T8Hf9RDU8FSxe5ujSTOGy6p4Kvd5mKahjL+dDxRv20JbuJa//q/kbOY/l1ubWdDIk9KqRRXISTHe+9S9jG+ojSodjwo6UROJULzTti013Eox5gpmPMu6SxsuaUW+OXlEZt+C1d2mqdZEUVU3nfHUSNTRr1TxKWc/BWZDcb4F+udlNsba3pKPIiH62GX7rGL/AOr/AP6Pi9zDNpuxYz81/wD9E0StmT7I/wA5yStm+2v85Avonj9/zJf6S7V+8XuRCP1sNT0Ysh/NV9pxXuYqn7rIPzZfaTnvyb7a/wA58Wrl+2O84+iWP3/M9+k21vvF7kQb9bHU/dXB+bL7T5+tkqvuqh/NV9pOu+pftr/OO+pvtrvOPolj9/zD6TbW+8XuRBk7mSo+6uL81X2he5kqd/8A8qh/NV9pOe+5vtrvOfFq59P3V/nPV0Tx+/5nn0m2t94vcv0M1gLBSYBy7rbI+4pWue+SZZNjZTnNRNETyEclVdpTufUyvTRz3Knap0O3k/gYSw69xPgQ07LbrZXWvWT5nxOgluXLlSuqE64k9ZEtCV5dovf866Luj+srz/qJFm/0TUnNyNI8zcRMT+Xyr511IqSzOF6PzQxE5P5dInpImcbv+tl4s7hhfZq9fVXyAALRlEoyn35l4d/8hF9JDb7HyJ37D+L+s1Bym/hMw7/5CL6Rt9mB+/YfxX1m6dEfTl++w5t03+1U+D+ZFFO2lTnHUp203hm/vkajP0TFd1p/Bhaf+8Z9BTVQ2r7rVf8ARhaU/wCsZ9BTVQ5Htv7U/A6d0O/pkfFgAEQbSAAADZHuOYGtteIqxU523EzXs0cprcbN9yI1EwViB/Ss6ehikrsZa5cTW+lktNlz9unzJDWO25XOXiqqp5zunTVeJ1aHXlwRy+HIzmC3tbiGlV7kaibXHr2VMLmnkeuNcXT39uIUpeWaxvJLBtbOymnHUJq1dUU7m1M6fZX+cido7JhnPznwL2LlZGFb1tEtHy5EP/Wwyqv+1bNP+2/SF7mGb7q4/wA2X2kzSrm+2v8AOfe/J/tr/ORP0Tx/3qSf0l2r958F+hCv1sM/3Vxfmq+0+L3MVR91cX5qvtJv33P9uf5x35Ufbn+c8+ieP3/MfSbav3nwX6EH/WxVH3Vxfmq+0frY5/uri/NV9pOO+5+PLP8AOfO+p/tr/OPonj/vUfSbav3nwX6EJTuYp/urj/NV/wARyZ3MU6SNX31x7KLqv7FXX1k076m+2v8AOO+5vtr/ADnq6J4/71H0l2r958F+hLMa06Ullt9Kkm3yKJHtLxXRqJr6CFqdksz3pz3OXxnSqmy4tHUVqGupCRT4t82cm+EZTMJnLZD3pq79KV6+Z+pim8TK49dyeRF7cvTSvTzv0I/bf2Zl/F+11f5L5mmQAORnbzYfuMKNFuOIK9WpqyGOJF8aqv1E/uz1fXTvXpkcvpIl3GLESzYjk6eViT+q4lFbvqHqvylOldFoJY/4fmci6Rzctq2a9mnyOhDMYZh5W6QN++RfMYdCRYKbrd49/BFX0KbFkvdqkyDtfmlF913XOnzDpaLVdmlomIidrlV31lLlpd1JJymb1cnyIIW/1EKtOPZ8t7Jm/adk2HBQ2dSl6qAAMQlQAAAAAAAAAAAAAAAba9y3/A1Vf9zP6kNSjbXuXP4Gqr/uZ/UhLbE+1o1Xpj/TX4o75/COCLvOU/hHBp19HM4+iTTLz991H4tPWab5ofwi4g/8hN9JTcfLz99z/i09Zpvmf/CJiD/yE30lOd9LfrV++w2/oP8AaLvBfMjgANOOjgAAAk2VVIlbmRh6lVNUfcIdU7NpCMk6yCjSTN/DrV6KpHeZFUu0rWyK9qMXNluY1ku5P5G1+Y79a6nbv3RqvnX9BDl4kszFXW6xp1RJ61Ikp2PAWmPE4hT6J6KVNZEOfdG1DrZkS+GNdlaqSCF2nSiqrl+icKJfhTzd14/Yynt0SbkdcY008UbyG6TzccZoktiwU9qUp9/yNSQAcwOzgAAAAAAAAA3Qy4rXXnIe0VD12pIadGO/mP2fUiGl5t93PTllyF2V4MdUN828nOj83HLRp/TWtSwYy7pL8zqk3OPicUOcqc9d5wTim86uc6jyJpltJ+zKmPoWNF8y/pNNMy6bvPMC/U2miMr5URP5ym4eXbtLu9OuJfWhqnnzCkGb2I2JwWsc7zoinPulsNLE/wB8jbehM9Mq2PsXzIOADTTpBth3NPMyOrnInGpm9TUPZL4a+M8nc3fwE1i/9TN/dPZJ4a+M6n0b+yLwXyOMbX/qV/8Akzr6SU5et1vLlX4sLl9KEX03ksy8b+2sv4hfpISubwx5Ebc/NNU8/ah1TnBiR7l12KtY08TURPqIKTDOtdc2cTr/APZTfSUh5x3Jet0vFnbsBaYta/8AqvkAAWTLAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABKMqL0uH8xLJdNrZbFVsR6/euXRfQpFzlG9Y5GvauitVFQqjJxkmii2tWQcHya0N0c4qNGXimuDE1jnj0VU60/QqEHZJsv11XgTWW5JizJW1Xxio6aKBiyde03mP9pXiS7vC38OJsctW1Jcmc+xlpB1y5xbRMcBXXvHFtG5ZVRk+sD9/Xw9OhUef9s9yMyrgrG6Q1SpUM/nb19OpMI5uTWOdiqkkbke1e1FPd3SdtivOFrNimnai6NSOVU6nJqnp1Qxcl79b9hl4LVGZFvlLh+hTuBrgsVZPSudo2VvAnmX1QlVFeMPTu5k0aujResqmkf3tWwzs6FTUmtvr/crENFc2eA5yK7tRdymPjXbumvZ8mTOdQpJ6c380QK608tFcp6Z6KiserdPKWf3N98WmvlXZZXojapm3Gir8du/0pqYfOO0xwXttzp26wVTUeipw1UiGH7lLZr3SXKnXZfBK12viUprk8XIT7n8C7ZGOfhOK7V8Sy8wrdJasWVDUVUhlXlI9Opd5NMlrxGr6mzyu15ROVjRV4qnFPKnqPmYsEF/wnSYgom7atYj00+Q7inkUr3Dl1dbLnTVsOqPhkRydvYSUtMbI3lyfH8GQSTzMNwfpLh+KPPmBZWYbxxV00aObTyO5WFV+Q7ensM5h2dtfQLRq/R0buUjRV4p8ZPrJfnLZafEuEqbEdtTWWmYj93FYl4p/NX1lWYWrO96yJ6SI1WO36lmSWPe1/a/zL9dnleIpf3R4PxROe6Be+PG2w12iJTRImi9hXs08yUjVRzuPWXni3DmG8WOpL5PiuipnzU7EdHIm9rkTRU85g34AwmkGyuNLfuX5Cns6ZOTaZiYu0Kq6owknqufBlOtnnV/hOPPPLMr1RXO4lzw4AwgkjdcaW9deqNfadFRgLCDZ1RuMqB2q9MTizLGnoZ0Nq0a8n7mVRCyoWkc5Edpqh0bciLoquQ2ggtGGbL3lhttlpqumqebLUSR6vfqm57V6EKAx9R0NqxXX2+lka+KGdzWKidGpTbRKtJsqwtpV5U3GKMBPLIkmm07znZFPJyEnOXgnT2n2pSDlV1lRP5qiNIeQk+F6E+L2lnjqSDa0Ohs8u3ucvnPVJVTcnHz14dfaeViQbX7t/VU9E6QpHH8L8X5K9YWveJaargc6Wpm5Tw139p0JK9Haoq6nbSOh5VE5T+qp1K6BHfuv9VT1vgeJLV8DsqauoSCPR7k49J546mpVyayO016z1TNhdBGqy9C/FXrPlOynV7U5XiqfFU8erfMR3UuR5KiadJXN23cesLJP3s5dp25TIzw0vfD0WZPCX4qnpjp6JaJ6LN8ZN+yo3Wz3rYpLgRxr53u2dpyqpn4sLX59rbdUttU6jX7MkaqzzndaqW2Mr4nyuWSNHIrmom9UNsffNhi0ZasuUDYmWvkOTp4HN5z3aKmzovHfxLlNO+m5MwNobRljuKrjrqa44EwbLdYpamqnjpKKFNZZ5ODexOtewykttwbBNyPuvUPci6bSUm5f6xmMBd7YuufuAyvWDbY9YW8nzEciK7eidhCbxb4KLEFRRuqkc+GZY10Yuiqi6GTrCMFpxMRSttukpSa07ESXHGILa20RYYw1E5lvbo+qme3ZfUy9vU1OhDG2Owy3GzchFEj5XVLEYiJqq6op4lt0Utc9qTJrtL8VSy8M8jhHCFViCdGvmV3JW9qp4Uui6u/mouvj0LsKdW5S5Fm7I6qChXzbIlm1Uw2qjpcN0sjeStkfwzmrufO7e5fJuTyGO7mnC63jF1TiWpave9tTWNVTc6V25vm3r5CGYqnqbhW8gxXy1FRJ41c5VNhY6alyoycZC5zW3B0e3J1unenD+anqUs1x6y/elyjxMq+Xk2GqoenPh7+ZUWf1zjvWMFo45dqCj+D3LuV3T6TL5AYchbcp7zIzVsDNli/fL+gq1kk9wr3yPc58kr9V16dVLtuNczAGUz5F0ZWTR7LU6Vkcn1J6i5iaWXSyJ8o8f0K82MqcaGJXzlw/UpvPW+svuYFYsL0dT0n7HjVF3Ls8V8q6kGppXwTNmjXRzV1Q+SyPllfI9dXOVVVSaYBwSt/tFfdaqfvelpmKqOVPCVEVVIjSzKubjzfE2JdVhY8Yy5LRHxuauNY42xMuzka1ERE2E3IhlsHZjY2umJqGgfd3uZNK1rk2E4a7+grWoa1sz2tXVqOVEUkeWV5tmH8WU91usUssELXKjI9NVdpu49pcqyrusipTemveW8jCoVUnCtN6dyJ9mnmDiyxYodb6G6PjjZG1VTYTiqeIjEebmO04XhfyEMXmliKjxRi6ou1DDJFBI1qNa/TVNE06CLNXRT3IzLXbJxm9Ne8t4mz6Ooh1la1048EWRb86Mf0dbFU+63KtjciuifGmy9OpS6Lna8Md0BghbnaeRocU0UfPjXRF1+SvW1eheg1Rcpm8DYrvGDsQwXqzVDoponc5uvNkb0tcnSilNeXJvdte9FlvK2VBpWYyUJx5NdvsfsMffbVX2S61FrudNJT1VO9WSMemioqHvwXie44WvDK+gfq3hLEq82RvUpsdiO04bz+wZ7v2PkqLFNHHpLEqoiqqJ4LutF6HeRTV+726ttNxnt1xppKaqgerJI3porVQpsrljyU4Ph2MvYeXDOrlVbHSS4Si/wB8i3cX4dtGYViXFWE0ay4sTWqpODnKib93X29JTMjHxSOjkarHtXRzVTRUUy+D8R3HDF4juFvlVNF0ljVebI3pRULOxXhm04/sLsWYURGXBrdaqk3Iqu6U0+V29JkTjHMi5wWk1zXf7V+aLcJy2fJV2PWt8n3ex+zuZTAOUsb4pHRyMVj2ro5qpoqKcSNJcAAAAAAAAAAAAAAAAAAAAAAAAFx9ytg5L9jR9+qmKtHaESRuqbnTL4KeTevkQp1EVVRETVV4IboZUWNmBMoqSN7EZX1jeXm14rI9NyeRunmJTZGK8jJXDka50o2h5JhOMX50+C/M7cY13fd1e1q6xxcxvV2qYBeJ3zO2nquup1Kh1ymCrgorsOWVx3UcUU7GPVq6tXRThsn1GqXCpmVZf7uxqNbcKhEThzzl74rz/wARqPyjEoi9h90LLx6vVXuKNyJlffDef+JVH5R898N5/wCI1H5Ri0TtQ+6dqDyer1V7huRMp74bz/xGo/KPi4gvH/Eqn8oxmnag08Q8nq9Ve4bkTJLfrwv/AORqPyj4t9vH/Eaj8ox2i9Z80UeT1eqvcebkTIrfLuqf6wqPyjHTySTyOkle573b1Vy6qoVF6xovWVxrhDjFaFSjFcjgjT7snLh0gr1KjIWKrdQ3CGpb8R29OtOlPMRDuv8ACTKu1W/G1CxHLGiU9UrU4tXex3rTzEijdouupMqCjpcXYGuWFq5yaSwujRV37KLva7yOT0GudIcJZFO8Zmy8x4GZC5cu3w7TQ8GQxFaqqx32ttFaxWVFJM6KRF60XQx5y9pp6M7PGSklJcmAAeHoLG7m3+GSyfhSfQcVyWN3Nn8Mlj/Ck+g4yMX6+HijA2p9it/xfyNmswf9dL+Lb9ZFncSVZhf66X8U36yKu4nYsH6iPgcWp9EN4kvw/wD7D3z8TL/ZkPbxJjh5P/g18/Ezf2Zj7W+zMuL6yHivmaNP8N3jOJyf4bvGcTjp3RAAAAAAAAAAAAAAkOXGHpsU40tlkhaqpPMnKL8lib3L5tSqMXKSiu0otsjVBzlyXE2nyatK4ZyOpeUbsVFc1Z3a7l1kXd6DyTrq7cTHG8sNJSUVnpkRsUMac1OhETRqebUhr11Xih1rYuP1OMkcSyMh5ORO5/3Ns4aHdTsVz0aiKqruQ6006zMYWpe+b1Sx6aoj9t3iTeSds9yDl3Fmb0iRjuwa1tFl5ZrQi6LUVe1p2Rs//wBoapl4d2HeO+8f0dnZIro7fSNVzddyPeu0v9XZKPOQbUs38mTOsdGcfqNm1p83x94ABHk8bIdxZ4OJV/Ef3yZ3j9/1H413rIZ3FvgYlT8R/eJleP8AWFR+Md6zo/RT6j995yTpL/VrPw+SPEc2blOCHNvjNtIZ8jq7pjfkbR/j6f6Kmphtn3S/8BlF+Pp/oqamHJNu/a3++1nSuh39O/8AZ/kAAQxtQAAAAAAAAAAABZXc1WZbvmzbHqzaiodqqeunDZTm+lUNk8dVfLXl8aLqkLUZ5eK+sgXclYbW1YXuWLq1mx338HDqm/k2b1Xyr6iQ3Gd9RUyTOXnSOVy+VdToXRTF3a+sfico6UZSydouMeUFp+PaeZVOTN6nDQ5xIu0huTIJvRE3wk9tBhy63OTc2GJz9V6mMVTRWvndU109Q5dXSyOeq+NdTcnNO4+93Iq5yK7Ymq4UhZv36yLv/q6ml5y7pLf1mTob50Io3aLLn2vT3f8AZ9TwVLJ7mdyNzitGvSkqJ+QpWpOchKtKPNzD0jl0R1Uka/zkVPrIPG+uh4o2vaUXLEtS9V/I2jxyn7dzfgt9RG1JVj5mzeXL0OjavrT6iL7ulTseG9aYnFKfRPiN1UysOHrnLG2RlOuy5NUVXIm48EKt1MtnJi28YPyvpL1YVgbU7cMbnSxo9EarV6F8Ri7Tz3h176Rfppsyb4UVvjJ6cTr97N1+0N/LQe9q6/aGfOIUT+uFzF00We2L295NOLu6CzEX/eLan/ptNb+l0e42H6H7R9aPxL4TDd1+0M+cQe9u6/aWfOIUIuf+Yi/73b0/9Nh8/V+zE/llD+ZsPPpdH1We/Q/aPrR+P6F++9q6/aWfOIfUwzdftLPnEKA/V9zF/ltF+aM9h9/V+zF/ltD+aM9h59Ll6rPfoftH14/H9C//AHsXVfsLPnEHvXuv2lnziFApn9mKn++0P5ow+p3QGYqf75QfmbB9Ll6p59Dto+vH4l/e9a6/aWfOIPerdV+ws+cQoL9cFmN/K7f+ZsPv64PMb+V2/wDM2Hn0u/8AqPodtD14/Ev33q3VPsTPnEM/hK1y2hlXVV6siYkeqrtJojU1VVVTWT9cJmP/ACu3fmTDGYnzrx/iCzzWqsuUENNO3YlSnp2xue3pRVTfoWr+lKtrcN0qh0MzXJKc46dvMh2Ma9Lpiy7XFu9tTWSyN8SuVUMSAaZJ7zbZ0uEFCKiuwAA8KiUZT7sy8O/+Qi+kht7mB+/4fxX1moGVS6Zk4eX/AOwi+kht9mD+/wCHf9j+s3Toj6cv32HNum/2qnwfzIoqnbTLzjpVd/E7KdedxOgPkajP0WY3utP4MbT/AN4z6CmqptX3WDdrKy1O6ErI/oKaqHItt/an4HTuh39Mj4sAAiDaQAAAbO9yJvwPf0T+UJ9BTWI2Y7jmVH4dxHTa70midp2K1yErsZ6ZcTW+li12XPxXzJJMm860Q76nRr1RV4KdOretDrq4o5fF8Dvo6WarmSGCNXvXgiGSbhq6rv72VPG5Pad+CntS+w66b0cnoK5zszixlhLH1VZLStAykiYxzOVpke5dWovFSE2rtZ4D1a4GTgYN+0b3TS0mlrxLA97N1/k6flp7R72br/J2/lt9pRK90PmIv2W1/mbTg7uhMxF+z21P/TaQf0uj3Mm/oftH1o+9/oXz72rt/J2/lt9p897V2/k7fnG+0oX9cDmJ/KLd+ZtPn64DMP8AlNv/ADRp59Lo+qx9Dto+tH4/oX3727t9ob8432n33tXZfsDPnG+0oP8AXAZh/wAqoPzRp8/V/wAw/wCV0P5owfS6PqsfQ7aPrR+P6F+phm6/aWfON9p9TDF16YWfOIUD+r9mJ/LKH80YP1f8xf5ZQ/mbB9Ll6rPfodtH1o/H9C//AHr3T7Qz5xPaPetdftLPnEKA/XAZjfy2h/M2H1O6BzGT/fLev/psH0vXcx9D9o+tH4/oX971rsnCBnzjTDZ/1SWHI6egncjairfHA1qLxVXo93oRSnW90LmMn+821f8A0mkPx/j/ABPjiaB+IK1srKdF5KKONGMaq8V0Tp7TB2h0j8qpdaXEzdndE8qrKhbfJbsXrw17CKgA1M6EbM9xk5FsmJGdPKxL/VcSesX4d/jUhHcYVSd94iolXe6KOVE8Sqn1k5uTVZVytVOD3J6TpXRaSeP+H5nIekcN3atmvbp8jzoSPA6/twxOtq+ojW8zeE5uSvECquiK7Z8+42LKWtUkQdq80177p9qtzhueqcYoVT8hCsC5e64oXU+ZUVaqc2ro43IvXs6t+opo49nRcciafedm2JNT2fS16qAAMQlAAAAAAAAAAAAAAAAbady5/AzVL/1U/wBFDUs217l3+Biq/wC5n+ihLbF+1o1bph/TX4o7ZlTaOKLvOU3hHW3idfRzJeiTTLxf2XUfi09Zpxmf/CJiD/yEv0lNxsvF/Zk6a/Yk9Zp3mm1WZj4havRcJvpKc76W/WL99ht3Qf7Rd4L5kaABpx0gAAAE+7ntUbnDh7XpqFT+qpASXZNVSUeaWHJ3LoiV8TVXxu0+su0PS2L9qMTPi5YtkV6r+RttmGml3Z+KT1qRJU3kwzIbpcoXdcf1qQ9eJ2TAf8iJxKrkd9GukqKeTuvk28rLW9OCXFnpjeeinXRxz7pCnW5ZFJUsTaWmlgmXs4tX6RCdJ4OWM2SWxJqG1KW+81BABzE7MAAAAAAAAADbzuc0VmQ71XpkqFTzIahm5GT9K625A29Hpo6eJ0mn4cionoJrYMXLLRqPTSSWBGPfJfmeKbTbU4n2Tw1Ph1k5xHgiVZef64Vf+S71oas90G9H5xYiVvBKnT+qhtXlyzW5yu6ovWqGoOblT33mbiGfXXar5E8y6fUaB0tkt9L98jbOhUdcu2X/ANfzIqADSzpJtl3N6f6CKz/uZv7p63+GvjPJ3Nyf6CKv/uZv7p65NNtfGdT6OfZF4L5HGNr/ANSv/wAmcSW5ef60l/EL60Il0kty7091ZfxK+tCUzvqJEZd6JqNnT/Cxif8A8lN9JSIEvzo/hXxP/wCTm+kpEDjuR9bLxZ3HC+zV/wCK+QABaMkAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA2c7k66w3XB94wnVSaqxVkjaq/EemjvMuhjLhROorjPRy6o+GRWOTtRStch8Se9rMOgqJJNmmqF5Cbfu2XbvQuil35v0LaO/suEenJVbdpVThtpuX6lJvGuc6F7DTM6nyfaEu6a1/FcyLvmbGxG6a6dOpLrFNFifLq8YYkbtTxRq+BFXypp5U9JAZZNpFXXcZDBF0daMT01S9+kD15Ob8FSt7jfHtLN1UnDWPNcV+BTVS18c0kT2q1zHKiovQZulqO+7M1vx4V9BKM+cLe4mLpK2nRO9K/4VitTcirxTz+sgtjlSCvSKRdI5uapH7vV2OLNhhbHJojbHxLDpXpifAklDJzquiTVnWregqaqa+J74nIqOaum8snDEktnvzFTVYnc16daKYzNjD6W65pXwInIVHORU4IplZFTspVi5rg/yMbDujTe6uyXFfmTbufcRx19rqcLXByOVjVdC13xmL4TfrI9jS1z4dxBLSK34JV2ondbV4KV7h+6VNlvFPc6ORWSwvR27pTqL9xNTUeO8Fw3a3qi1MbNtiJx1+Mz2F7Haysfc/uhy9qMXLr8iy+t/snz9jPuTOI0nZJh6u2XRy6rCjuC6pzm+VCBZk4dnwpiVyRtXvKoXbp39nV404GLw++qiuLI6dJe+WP5qMRdpFQuW6U0GOcJy2y4R973SnRF53GOTTc7xO6SuuPlNO5/cuX6GLbJYOV1n9kuf6lb4cuUdTCtDVPajJPAevxHdHkPLfI5qTaieitc1+hE6htbZbtLb66N8UsL1a5FJxZ6yO+2xtE9kS1saJyTnfHRPi+PqLFdnWR3HzRl3UdVJWR4xf71MFSVEnLMXXpQ656yZtQ/RF4kmtNtZTSrWXemSCljdvRW6PkVF8FqfWfK3E1sdUv5HDVsjbruRWvVdO3nFqSaXE9jYnLzVqei25lYnt9l7xhmY9kabMb5I0c6NOxSC1dVPVVT550V8j3K5zl4qqk7ocRWd0LkrMN0D4tU15LaY7z6qetl1wC5yK/DtWmvyahPYeSjvc2UVzVMm418+7QrisavLqmyc4YnLSTLs9CestCoqcuHz6SWW6NVdNVbUN9h777hC2rh198wq3v+2u05TaaqywKnFHonrPVVxYe0EklKOmveUsyF6u8FfMe+qoZ+96dyMXnNXTd2qZRa1kUyt71pl062GYqrjGygo9KeBV2F1TY++Ut7i0fEypXveXAzGVOUd1xVE64TS950aaox7maq93YnV2kfzJy+u+DbklPWNSSN++KVngvQ2EyGx5bK6zQYenjSCrpWOcxWt5r2pv8AIpB8+8fW6/18duoKdr4aNzmulkbve7gunZuLkoxVfAi6cvIlmOMuRSFTTvZQwPVvHX1nGkjVZGbulCQ3CrY220+lPCvhLvZ2mPpqt0lVGxtLBorkTc3tLaXHiSm+3F6HhrWKlXImz8ZT1U0SrQPXZ15yHvfFVz3aSmho45HrIqIiMVVXeWjh/B9HZrC67Y05ClgRWvjpWfusnZp0FcYptmLfkqqK15kWy0wWl4c+6XJO87PS8+oqX7kVE+K3rU78y8QRXqqipKKHve10bOTo4E4I35S9qnXjbMKru0bbdRUkVHaoV0hpmbk063acVI7V1z3St1pol5idfV4ypOKjoizGFs7FZZ+C7iWZBtZDmNQ6Jpqkn0HGBxSrXY7uSIn++P8ApKSTJOfazDt2tNG1VV6apr8hx7bTh+e/5h3OOKjiRjKqR8kr9UaxqOVVVV6CuEFJJLvLFtyqvnOXqr5nfgiwrcrpNPPsQUdPrLUzu8GNicV8fYYfMfFkd1rWxUkSQ22kasdJF1N+UvavFTPZi4tt9PRuw1h9qJbWP1qZ03LUyf4U6CDYGwxWZgYujt0DXRW+DR9ZUIm6NidCdq8EQv3WrTcii3h0uTd9r0S+BLu58wb7q3iXGl1gRKKjcqUbXpukl+V4m8fHoYXPLE/vmvzqOmftUNIqtZp8d3S4sbOPFVBhbD0GD7C1IHJCkezGv7jH2/fO4r4yjKGiluFfFBTsc+SVURqcVVS3JKMeqXN8y/jt3W+Vz4JcI+HeZnKbCyV9879nh1pqXnL1K7oQj3dE4pS7YgZZaV6LTUGqOVq7nSLxXycPIWbi250uXmAuQp3t7/mRWs04q9U3u8SGtVS6SpmfPK5XPe5XOVelT3PaxqVjR5vi/wBDO2XB5eQ8uforhH82eejgkqquOnjarnyORqInWpcOPa6LCOW1HhqkVG1VU34bTjpxcvlXd5CP5OYfbUXR94q26QUiatVeG11+QjuYl4dfMT1FQ1yrCxdiJOpqGLV/4+NKf90uC8O0kbdMrKjX/bDi/HsI34S9pybDI5dGxuXxIWRkFgd2LMaQ99wq620fw1Uq8FRODfKu42UmvGFKGofBR4UoHJG5Wo9IY0RdPIWsbBlfHe10RZ2htqOJZ1UYbz+RpVHba6TwKSd3iYp7KfDt6k3stVY7xQuNzGY3oo1RKew0kfian1ISXB2IpLs6plnpaenpYGaq9qdP/wCtTJ/henORGT6T2JfVfE0FuVvqaFyR1VPLA9fivaqL6TwFnZ3YkixXj643FiotMx3JQaJ8Ru5FK1maiO3KRdkVGWiNoxrJWVqUlo2ZrAmLLxg3EEN5s1Qscsa6PYq82VvS1ydKGw+I7PhnPrB/u/h/kaLFVJGiTQKqIrl+S7rTqcatGcwTim74Qv0N4s1S6KeNec34sjelrk6UUvUX7i3J8Yv98DEz8B3NXUvdsjyff7H7DHXa3VtpuM9uuFPJT1UD1ZJG9NFaqGTwRii4YUvTLhQu1b4M0KrzZG9KKX3iOgw1nphP3bsiRUGKqSNEmhcqIrt3gu60Xod0cFNb7nQ1dsr5qCup5KepherJI3poqKhVZXLHkpwfDsZ7i5UM2uVVsdJLhKL/AHy7i37xX5U4mlS61rnUVXK3WVjdpq7XTromi+Mxb6HKVvCvnX+c72FVgvS2jvPWVcW/D/ZTHZm4tI2yS8SzpKTKnorKryK72HmfS5X67q2u8mvsK6BbeYn/AMcfd/suLAa/5Ze//RNb9T4AbapnWqsrHViJ8G1yLoq9u4hQBj22dY9d1LwMqmrqlpvN+IABaLwAAAAAAAAAAAAAABYvc94P992YlLHURq6gof2TU7tyo1ea1fGuiGzuOa5Ja9KOPRI6dNFROG0vHzcCMdznh9mEMrH32riRlZdPht6b9jhG3y8fKhzq53yyukeu05yqqr1qdD6L4Drr6ySOTdJc7y3PcY+jDgvzOt28+anHXrOyJEc7fwNwIR8EZjDVmfd6l0auWONiaudp6D2SU+B4ZXQz4ttrJGLo5rq2NFRfFqeXHN3bgXKK4XZHcnXVLOTg69t+5vmTVTS2SR8kjpHuVznLqqqvFTSds9ILce7cqZsGwuj38TrlbZNxSei07e83ZVMAN44wtaf+7GcFfl6n8cbZ+exmk+q9ajVeshvpRmE79CKPvZfA3WWXL1P442388jOKzZfJ/HG2/nkZpXqvWNV6x9KMwfQjH+9l8DdPvjL77sbb+dsHfGX33Y2387jNLNV6xqvWPpRmD6D4/wB7L4G6iT5frwxjbPzyM5JJgBf45Wz88jNKdV6xqvWPpRmD6EY/3svgbstdgBeGMbZ+exhVwFqie/G16rwTv2P2mk2q9Y1XrU9XSjLPPoRR97L3I3axDYWUFNFV003L08qbnpoqb01RdU4opHVXecO5xxB77sr6iw1sqPrLWvJIrl1VY13sXyaKnmOVVE+GV0b2qjmqqKnabxsjP8so3nzNIysWeHkzx584v/o+6mYwrc1t12inc7SNV2JPwV/zqYHTsOcWqOQkrIKyDi+0sTjqiDd2DhNtHiCjxfSMRILi3kqjZTckrU3O8qaeZSgjeG/WKHMHKuvsE2i1kUesDl4pI1NWL5eBpHVQS0tVLTTsVksT1Y9q8UVF0VDk22cR42Q13nT+iu0HlYarm/Ohw/DsOoAESbOCxu5t/hksf4Un0HFcli9zcumcli/Df9BxkYv18PFGDtT7Fb/i/kbN5h/66X8U36yLKSjMNf27Xf8AYm/WRZynYsL7PDwOK1eiG8SZWDdgO+L1QTf2ZDGLvJpYv9gb7+Im/sjG2u//ABmXF9ZDxXzNGH+G7xnE5P8ADd4ziceO6IAAAAAAAAAAHKNj5HpHGxz3uXRGtTVVUA4m0/cxYCXDlilxpe4uSqquLSlY9N8cPyvG71eMi+R2Sk888GJMZQchRx6SQUUiaOk6Uc/qb2dJcGLMQNqtKKj0bSx7t25HacN3UbTsHY9ltismjn/Sjb0LIvDx3rr6TXy/UxN6rX11fLUv11e7cnUnQhjlU+ukVxx1Q6TCKhFRXYaVFaI5Iu8muX0DIm1VznVGRxMVNpeCIm9y+TRCG00TppmRxt1e5dETrU9GfWI4cD5UraaaVEuNzatPGicdF/dH+ZdPKRG28tY+M+8u4uPLLyIUQ7WavZmX52Jsd3e9L4NTUuWNNeDEXRqeZEI4AcmlJyk5PtO2VVxqgoR5JaAAFJcNj+4tXfiTxQ/3iZ3j/WFR+Nd6yF9xb4WJPFD/AHiZXfX3QqPxrvWdH6KfUfvvOS9Jf6tZ4L5I8hzadbU7DtY3cbaQr5HV3S38BVGv/Ppvoqalm23dKNX9QikXqmpvoqaknJNu/an++1nSeh39O/8AZ/kAAQxtYAAAAAAAAAJFl1hS4YzxVSWO3sVVldrLJpujjTwnL5DjgbB99xleGW2y0jpVVfhJVTSOJOtzuCG3mAcJ2DKnDCxQK2qutQ34edU0dK7qTqYhJbO2dZl2LRcDX9ubcq2dW4xetj5Lu9rPdf2Ulgw5R4atrUjihiazZToYnX2qu8h71VXa6HruFZJV1Ek8z9p711VTxqdXwsdY9SgjlSTbcpPVsHus1KtXXw07U3yPRF8XT6DxsYjl4EywVQxUdLU3utckcEEblR7tyI1E1c49zMhU0uTKZ6vSKKi7sTETGQ2jCVM9OYnfU6IvD4rEX0r5TW8k+aWJX4tx1c72qryU0qthReiNu5qeZCMHH82/r75TOybGwvIsKFL56cfFgyuD61bdiu1V6LpyFXG/XxOQxR9aqtcjk4ouqGPCW7JS7iQsgpxcX2m8eYPPlpalngyxaIviXX6yHq5VJDaa5mJcprJeo123tp2JIqdComw70oR57NHaHYNl2q3Gi4nDerdNkqpc02jtgXnJqZPNm3LfchbgyJNqSkjSVET7x2/+qqmJZqiopNMCz09ZSVlkrGo+Gojdq1fjNVNHJ5i1tijrcZouU3dRfC5f2tM0VBJ80MLVOD8a3CyTtdsRSK6F6pufGu9qp5CMHJJxcJOL7DttVsbYKyD1T4gAFJcAAAAAAAAAAAAAAAAAAJFlk7YzDsDuq4Q/TQ3EzDT9mQL1xr6zS/Bs6UuLbRUKuiR1sTlX+ehutmKxVdSydbXJ6jcuiUtLGv3yOc9OI/z6ZexkKchzgTRTg45RO0XgdCZqD4o4d0xTrV5I01SxNeRqYHr2JsuT1qhqSbwXm2e+3KO7WNmjp+Qe2NPv285nnVNDSKeN8Mz4ZGq17HK1yLxRUOU9IanDK1Z0ToXfGWHKrtjL5nAAECbiAAAC++44rlZiK925XbpqRsiJ1q1yJ6lKELK7mu8ss+a9uSV2zHWI6lcqru1cm706GZgWdXkQl7SJ27Q79n2wXPT5cS973GsNxqIl+LI5PSeHUkOOqVYb3K7TRJER6f58hHVadholv1RkcfqesTL4ZnSG80z1XRNtEXy7vrKk7r+1SU2OqK6oxUhrKRqbWm7aYqoqebQsqm1Y9HNXRUXUymdWF3Y+ynWpomJJcaD9kRNTi5UTntTxpv8AIa50nxZWUbyJfYGVHD2jCcvRfB/iaZg+va5jla5FRyLoqL0Hw5qdfAAAAAAAAAAAAAAAAAALm7kSt73zLnpNrRKqhemnWrdHfUXPieLkbzUs0056qnl3/WavZQXxMO5kWW6PfsRMqWslX7x3NX0Kbb4/pNKyOqjRFZKzTVOtP0G9dEr1o62cw6ZUOvOjb2SXxRFD0UUroZ2SNXe1yOTyHnVND6xdF6jeGtVoavJaoxHdZWJbrg22YmpmK9aN+xKqJ9jfvRfIvrNXTeeyxUWJMLV+GLkiOjmhczt2V6U7UXRTTfH2Frhg/FFXY7ixUfC74OTTmyM6HJ2Khy3pBhSpyHPTgzofQ3aEZ47xJPzo8vB/oYAAGvm6AAAAAAAAAAAAAAAA207lhdrJutb1VU30UNSzavuRZkmy0u9KnGOrdu/CYnsJXYr0y0av0vWuzZeKMhMnOOtOJ2z6o7gdOui6nXlyOYx5Ety+k0uz2fKiX0KhqnntSLR5t4jiVFRHVr5G+J29PWbLYXrEpLzTyuXRqu2XeJdxUXde4emo8bU2IY4l71uMDWueibkkYmip5tlfKaN0sok0po2boffGraEq3/cviuJR4ANFOoAAAA9+HqlaK/UFWi6LDUxv16tHIp4D6iqioqcUPU9HqUyjvJpm9eYCtqaahro97JWaovWioioQl3EzmArkmK8l7VXNdyk9NC2KRE4o6Pmr/V0Uw0rNHHXtj3K3Gizh9tTovnU+xtHxi6OJWlA3E+WN4w+qaySU8kbUXrVNpvpIq1N5JMD3BKK6tZI7SKdNh2vQvQv+esubTx+vx5RKFOVc42R5p6mk1RDJT1EkErVbJG5WuRehUXRTrLl7qHL+fDeLJMRUUKraro9X6tTdFL8Zq9WvFP0FNHIb6nTY4PsO1YOXDMojdDk0AAWjLAAAAAAPRbaSavuFPRU7FfLPI2NjU4qqrohvBeqZljwbarFGqfAwsjXTp2GpqvnKD7lfAs95xS3FdZHs261u1iVyfus3QieLivkLrxfcErro/k11ijTYbp09a+c3Pothtz61nNumWdG6+GNF+jxfizAvXnHxE1U+qpziTVxv7NT10RMsAq2lpLhXyaIyKNFVV7EVymkGIaz3Qv1fXa698VMknncqm32Zt4TCGR9fU7SNqrgxYIUXjrJu9DdVNMjmPSbI6zJ0RvvQnGcarL32vT3AAGtm8G2fc3/wEVX/AHM3909Umu2p5O5u/gJq0/6mb1IeiXwlOp9HPsi8F8ji+1v6lf8A5MEry8/1rL+JX6SEQ0JZl5/rWX8Sv0kJXN+okR13ompec/8ACvif/wAlN9JSIkuzm/hWxP8A+Tm+mpETjuR9bLxZ3DC+zV/4r5AAFkyQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADshe6ORsjVVHNXVFNrbBVMx9lFTVDXo+upGaOTiu2xN6eVvpNTi3e5nxc2zYsWx1kmzR3PRjVVdzZU8FfLw8pn7PuVdm7Lk+BCbdxJXUdZD0ocV+Zkn6t5m0mqdh1PVyKnYSbNCysseIHyxtVtNU6yR9SdbfIpEe+GO6TOsW7JxkRVMlbWpx5MsGujZjjLKSjciOudrTVnW5qJ9abvIUHUwqyRUVuy5iluYAuNVQ4gilp41ex/NlanS1eJF86aK1UGKJH2ueJ6Tc+SNi/ubl4oUZMFOtWdq4FzZzlTfKjsfFezvR02nEFupLa2srE5WqiTZbH8rtUjOLMUV9/frUvRIm+BGm5GoYyVjnN4KSDL3Ly/45u7aO107khaqLNO5NGRp1qv1GJPJsnHq1yJaGNRQ3dL3vsIa5ysUnOUmNJbBdUoKmVfc+qciO14Md0OJ5m/kvT2nClPdcMSSVq0TVjrtN6uVOL0To04aFCbDmv0VFRUUtRlZi2KS5lcJ4+0qGlxXLwL4xjbKi03aPFNoXZbqjpeTRF2fvk7FI9NmNWU93gq6KJVkYukr3cZG9KKh68pcXpV07cOXdzXOVNmB8nByfIU6sa4DqKSu77tsTpKeV+mwiarGq9HiJWzenDrqOT5ruZC11112dRlLiuT70SvFNnt+Y2Ho7va9I7lGzr3r9476lKnon19puC01SySGeJ2ioqaKioXdR2ahy0wTFcbq+RbxWORY6ZH6I1vSip0+08V8s1lx/a0uVvfHDXtb4fTr8l/tLk8bynzo8LO1d/+zGxsxY6cJcaddE+7/RhaS4Limnigr6nYro27MMr15r06Gr1L2mAueHrjS1j46inexyLvR2hiKykumH7g6kuED4ntXcq8HJ1opMLFiamqqZlDeoVqoGpoyRF0liT71elOxTHTU3uz4MvzhOjz6eMX++BhI7bOlLJzNF3cVQ6G0U6ORNlOPykJfeLAjrdJV2iZK6kXRVcxNHx/ht6PHwIXLFNHImrV01PLIboot61PRnvraWVtSirppu+MhY2RVxmp8QS29VRaargc2WNXIqO0TVNxVV6c5Kpd68E9RKMlnPXGUSNVdeTf9FS0rP5nA8yaFLFk33GOv1Gxt6qmsjYjElciJtJ1+M51tIrqSl2WJuYuvOTrXtI/fFet5qtVX91d6zI1LXe59Gu/exfWpRGXFl+VWkYcf3oT7JCOSLGSat0TvaXpT5JEcQ0dRLearZj1RZn9KfKUkWRkTlxn0697S/RIdf2vS/1SbSp8O76Sl6T8xGBVD/y58exEttWD7leqWjpqOkdNM7a0aip1+Mk1BlnbbPNFJibEFvt70cju92Lysvi0buQ733GqwlltbaWzSO7/ALrEs09W1NHRx66bDV85WUCXOe7RSP5Z6rImqrqvSXGlquBajKdil52i4lr3S82HDtTUMwvaolrFcqPrqtWq9F+9b0EBu9Rc7vDUz1kj6iZz057pEXr7dxwxHaa117q1WKT90XoXrOdFZKl1qqPg3bntTh4y4q3JtaFqE664qWvHgR5tpqFfryO/8JPaZKSz1b6hqNiTXYb8ZOoyltwxVz1DI2QyPc5dERE1VSyI8G2jD7I6/FNSsKrG1Y6KLfO/cnH5KeM9jjR04ldu0Gn5vEw2TeG6+nxPT3WeNI6Sl2nzzOciNjTZVNVUZg40padtXZsMNWChklc6pqdE26pyrr5G9h5MbYwdW0aWyghbQWuPe2lh4OXrevFy+MiuE8JXvG9171tkOxTsVO+Kp6KkcLfH0r1IWprc82KPaautl11z00MdYbXesaX+OzWliq9y6zSqnMhZ0ucvQXperjh3JzATaC3I2WtlTVm14dRJpvkd1NToT9J3102Fsn8ILSUTGy1krdrZX92qn/Lf1NReCf8A7NZsZX664lvE1zuEzpZZHbk6Gp0IidCFLaoWv9z+BkVwltCSS4VL/wDr/QuF3rrxc5a6qlfNPUPVz3KvFVLQwJaqfD1nlxBeXJG9sSubtfY2dfjUj2XWElijbebxGjI2ptxRv3a/fL1IQrN/Hsl8q3Wq3SObb4Xc5UX91d1+IyK9MOvr7fSfJfmZE4POt8mp4RXpP8jEZi4qqcWYhlrHqradi7MEeu5rTA0cTppGRt3q92hxoKCunopa2GlmfTxKiSSNaqtaq8NVENQ+CVsjNzmrqhCym7Jb8+02OFca4dXXyRaGJqtmFMCQ2qnXZqqpvP046Lx9hVtMx00rWNarnuVEROtVPfiC9Vt+qmVFa/acxqNTRNE0Q6KGR1NPHPE7Zkjcjmr2oXsm5XTW76K4IsYtDorevpPi/E2swPZ4sv8ALGGB7Nm7XNEfL8puqbk8iL51MUj2r0KhgMMY/djJkUFzlay6QxoxG66JIidKdvWZ9I3JuVCao3XBbnI02+u2Fknd6TZyhp1c9E11VV3GczaukeBco30scmzcLknJpou/Vyc5fIm49uArWldeWSyN+AptJHqvBV6EKE7pDGzcVY4lgpZFdb7frBCqLucqeE7yr9RZzbnXDxKtnYqy8pRfKPF/kVdVyquu/VVXeeFV1U7JXanUa83qdAitEAAeFRlsJYhumGL5Bd7TUOhqIl3p8V7elrk6UUvDEVHh7ObC63yzMjosTUsek0Crvdp0L1ovQ7o4Ka8mUwxfblhy7xXO1VDoZ418jk6WqnSimXj5ChrCxaxfNfmvaR2bhO1q2p7tkeT7/Y/YeatttfRVUlLVUc8U0bla9jmLqinvwvhq53+7RUFNA9m0ur5HtVGsb0qpZEud75o2rLhyJ02nOclSqIq9ibJksF5p016vcdtr7fHb0m3RyJMrk2uhF1TpMunEw52Jdbwfsa+JjXZmfCqUup0aXen8DGVOVNjYjaJl7kS4q3VGuc3ev4PHQq/EVnq7FdprdWtRJI13KnBydCp2Fq3HA1+kzM92m1LO8u+EnSblOcjfk6cewieddfSV2LUZTPa9YIUjkc3em1qq6eQu5+LXGpz3Nxp6L2ot7OyrJWxg7N9Nav2MgoAIQngAAAAAAAAAAAAAAASzKPC7sYY+ttlVru93ycpUuT4sTd7l827xqRM2f7lDDbLPhW4Yxr4tmSr1ZTuVN6Qt8LTxu+iZmBjPIvjAidt5/kOFO1c+S8WWRjqtihbT2ila2OGBiasbuRNE0a3yJ9REHLqp3XKqkq6uSokXnyOVynmOwYtKpqUDj8E+bOSN1Mxhe2uuF1hg01ZrtPX71N6mJi3uTtJnbaumwpgi6YprVRqRQOezXp08FPK7Qs7QyVj0ORUouyarjzZR3dgYsStxJR4TpJNae2s250au7lXJw8iaFCHtvtyqbxeKu6Vj1fPVTOleq9arqeI5Bk3O61z7zs+zsOOHjQpXYvj2gAFgzQAAAAAAAAAAACwu59xW7CuZNBLLNsUNa7vWq1XdsuVNHL4l0U2ex9a0prilSxvwc6a6/fJx+o0ga5WuRzVVFRdUVDdTLO+tx9lBSVT37dxo28jNv1XlGJuX+c3Ty6m1dGs/qberfI0HplgaOGZFex/kYBUROs+t3KcpdEdpvOtV8Z0rXgaSuPElOB7n3heI9t2kU3wb/LwXzlAd1XhFMPZivulLEjKK7t74bspuST46eff5S2Y3q13FU8pl80bBHmJlLPGxqSXW3tWanXp22pzk/nN9OhqXSXA66vrIriTGwNoeQ5sXJ+bLgzTAH1zVa5WuTRUXRUPhzg64CxO5xXTOKx/hv+g4rssTucE1zjsSffv+g4yMT6+HijB2n9jt/wAX8jZjMNf27X8U36yLKpLcxI/28X8U36yLOYiHYcL6iPgcWq4ROpF3k5wW3v7DN0tzHJysrHtTX75miekhOiIeq3V9TQTpNSyuifw1Tp7F6z3Mx3fU4JlUtdU1zRQtZkpmZFUSMbheeVqOVEeyWNUcnWnOOlcmszU/ilWfOR/4jZxuNLy1ERXwr2rGgXGt3X+T/N/pNLfRGXZI2xdMs3TjXH4/qaxLk3mYn8Uqz8pn+I+Lk7mX9yNd52e02d9+t466f5r9I9+1566b5v8ASU/RGfrFX0yzPu4/E1i/UdzL+5Ku87fafUybzMX+KVb52e02dTG95/6b5v8ASfffveeun+b/AEj6I2esPplmfdx+JrG3JjM1V/2Tq08b2f4j1UuRmZk7kRcPLCi9MlRGiJ/WNkvfteF6YPmzhJjG8OT92Y38GNCqPRCXbIol0yzeyuPx/UqbDPczXqdzJMQXulo4+Lo6dqyP866J6y2MLYAy6y+RJqelZWXFifu06pLLr2JwaeKqv1xqUVJqyZzV+LtaJ5kMe+ZXLxJTE6M00vWREZm28/NW7ZPRdy4IzuIsQVFy1iZ8DT6+Ai718akedqfddek+Gy1VRqjuxWiIuMUuRxUImq9J3MZtEowphvvxyVlanJ0jd/O3bf6Cm++FMd6TEpachhOghoKSW/XR7YKaCN0iPeuiNaib3KaqZ044lx1jSe4sVzaCH4GjjXojReK9q8Sf90pmrFepHYPw1P8AtXA7SqqI3aJUOT4qfeIvnUog5jtzarzLN2PJHRei+xHix8pvXny5LuX6sAAgDcAAADY7uLfDxIn3sP8AeJneFT3Qqfxr/WQjuL3KlRiNv3kK+lxNLwq+6NT+Nf61Oi9FPqP33nJukv8AVZ+C+SPMi7zm1286UOSLobcQuhn83MO3PGOSkVusVP31WNWF7YkciK7Z3Kmqrpqa2rktmen8Uqv5yP8AxGxVmv8AcbW1Y6SfSNV1Vjk2k18SmU9+9464PmzTs/o1PJuc0ya2Z0gydm1OmuKa1146/qawOyXzOTjhKs8j2f4jguTmZifxSrvOz2m0Xv4vH/T/ADf6R7+Lx/0/zf6TB+iFnrEl9M8v7uPx/U1bXJ/MtOOEbh/V9pxXKHMn7kLh5m+02m9/F314U/zf6T779rt1U3zf6R9ELPWPfpnl/dR+Jqv+pHmR9yNx8zfadkWT2ZMi6JhSsb+E5ietxtH79Lqvxab8j9JxdjG6qm5YE/o0PV0Rn2yKH0zzeyuPx/U14tGQOYVbK1tTR0lvYvF89Qi6eRuqlj4V7nKyW9W1WKr26rRu9Yofgo/K5d6+gm8+J7xKmnfasT7xqIYqrq6ipdtzzSyu63uVTNx+ilcXrN6mBk9J9p5C0UlBexfmyTw3HDmF7alswvbqeJjdycmzZZr1qvFykWr66orKh09RI573dK+pOo8zl3nzU2bFwqsZaQRBtOUnKb1b7Wfdpe0+tccURVPdaLbVXGqSCnYrl+M5eDU61MmU1FasSkorVntw7b5bnXMgYio3i93yUIl3UmYMNmszMBWKZGzzMTv5zF/c4+hnjXivZ4yT5oY6teVuGe86JY6i/VTPgY1+L/zH9SJ0J0moF0r6u53Ge4V8756qoesksj11Vzl4qc+6Q7Y62XVVs23otsWV81mXrzV6K733+B5gAaedHAAANm+5Fv8ABcsNXfBdZN8JEqz0zV4rG7c/TxO0X+cSe50klNVSQyt0exytVDVvAGJqzCGLaC/0W99NIivZrokjF8Jq9ipuNyLm+3Yrw7S4qsUiTwzxo56N4onTqnQreCm9dF9pJLqZs5h0r2c8bL8pivNn8H/siGmnUeq3VctHVR1MLtmSN20h5pVRHHXr4zeJJSWjNZ3dUSLMfBNgzYsET0mbRXimb8FMiaq3713SrdfMatY3y0xhhKqkZcrTPJTtXm1UDVfE9OvVOHl0NiaWqnpZmzQTOikbwc1dFJPb8a1TGcnW00dQnBXIuyq+PoU1DafRpXS36+ZN7L6QZWzY9Xpvw7n2eDNH1RUXRUVF7T4buVa5fXVVfcsNUT5HeE59GxV86bzxOwrlHKursOW5P6B6eo16XRrLT4fmbLDptj/3VSXuZpgDc33m5QL/ABft/wCRIfUwZlD9z9v/ACJCj6O5fd8/0K/prh/dy+H6mmIN0EwZlB9z1u/IkOSYMyhX+L1t+bkPPo7l93z/AEH01w/u5fD9TS0G6fvMyh+522r/AEcg95eUH3OW38iQfR3L/ev6D6a4fqS+H6mlgN16bAuUU87IYsN250j10RNiT2lB91Fhqw4ZxrRUlgt8VDDLRJLJHHrptbTk13r1IhiZeyr8SG/YSGzekmNtC/qa4tPnx0/UqQAEYbEAAAc4nujlZI1dHNcioviN5bpVsvOA7NeWIipNBHIv85iL6zRc237na9RYoyjWxulRa216wq1eOz4UbvFxTyGwdHMhVZWj7TS+muM54sLl/a/gz65U14IcdUOVRG+OVzHNVHIqoqdR17zqWupz6OjRn8H3lLZcfhVXkJebJp0dS+QrnPvJasrLhPivBkDaqOo+EqaOLwtpeL2J0ovHTiShqGcsWIK62IjI5EfD9rfvTydRCbX2PHOjquZlYGffs2/rqPxT5M00rKWpo53U9XTywSsXRzJGq1UXxKdJvVW3PCl9Zs3+w0tS7hrLA2X0qmphKjA+T9W5Xvw7QsVfkpKz1KaVb0ayovRG609Nsdr+bW0/Zo/0NMAbpUOWOUdVUtggw9SyPdwTlZfrca3d0Fh+04ZzMrLVZaVKWjbFG9sSOVUarm6rx3kdmbMuxIqVhMbM6Q420rnVUmmlrx/7K+PVaayS3XSlr4V0kp5myt8bV1PKCPT0epOtKS0ZvXd6mlxRg224loNHxzQtkXToRyb08i7iFypoqkV7lHHdMtLNgG7yIiSq6ShV67lVfCj+tPKT3Elslt1e+JyKrF3sd1odR6P7QjkUKOvFHGNp4Utn5kqZcua9qMU12hJcG4hbaqpYp3KtLKvO+9XrIsvlCbicuqjdBwkYjjqjFZx5FsvdVPiTA8sKSz6yy0SuRGPcvFY14Jr1L+g15v2G79Yah1PeLRWUUjV0XlYlRPIvBTa21XiutrtaWoc1uu9i72r5CQR4thqYeRuduimYvhaaKi/zVNKzuizlJyqZsmz+leViQVd0d+K/BmjgN2ZqXLit1WqwxQKq8VWiZ9R51wvlLJvdhu3J/wCu5PUREujWWv2yaj02xn6VUl7jS4G6PvRyh+5y3/NSBMJZRfc3bvmpCj6OZfd8yv6aYnqS+H6mlwN0kwllF9zdt+akOXvSyiRf9mrZ808fR3L7vmPpriepL4fqaVg3TXCeUX3M2z5p5wdhTKFP4sW35p559Hcvu+Y+muJ93L4fqaXg3YtuBsq7hI+KlwpbXq1Od8G5NPOpp9jOkgoMW3WipWcnBBVyRxt6mo5URDAzdn24enWdpL7J27RtSUo1Ra3e8xAAMAmz6iqi6puVDcrKnEcePsqqdznI65W9qQTp07TU5q/zm+nU00LFyFx6uCMXItY93uTXIkVW1Pi9T0TrRfRqSeyc3yTIUuxmv9JNmPPw3uLz48V+a/EvWo5r1RU0U6treSXFdtimjZeLc9k1LO1H7Ua6tVF3o5OxSMKjmrpodaovjdBTicorevB8z1UFbNR1MdRC5WvYuqKZvF+G8N5pWFKS4NSnuUTfgZm6cpEvZ8pvYRpNTugkfFI17HqxzV1RWroqGNnbPrzIbskXIWWUWK2qWklyZRGOsn8aYWqJFW2yXGiTwaqkbttVO1OKeVCAzQzQPVk0T43JxR7VRTdm24vr6dEZOjKlqfLTR3nQ9tResMXRv7cWKnnX/mQsl9aGlZPRS6L1rfD3m34vTW2MUsivV96enwNFQbsVFhyoq+dNhm2oq/8ASbP0TyvwVk8/euHqFPE2VPrI99HMtdnzJFdNcTtrl8P1NMQbnNwZk8zhh2gXxtlX6zsZh3KaBdY8L2xdOumV3rC6OZj7PmevpriLlXL4fqaWnJjHvXRrXOXqRNTdiOLLmn/cMKWxFThpb4vrMrYK+xS1qU1vslLS6pqjmQMb6kLn0ayUtZPQsT6b0pebS/ejRFzVa5WuRUVOKKh8J1n2jG5t39I2NY3vjg1NE4IQU1+yDhNxfYbnj3ddVGzTTVJ+8AAoLwNi+4yujGyYgsz13vZHUNTxatX1oa6Fgdz9iVmGczbfUVEiR0tVrSzuXg1r+C+RdDMwLVVkRk+REbdxXlbPtrjz01X4cTYC6xrBWzQqmmw9U9J49SUY8tr6e5d9Nb8HPv1++6SMo1U4nYaLFZXGSOP1PWIaui8CV19ptWY2CZsN3ddmdrUWOT4zHJ4MifWhFUTQ9NHUy00zZYZHRyN3o5q6KhYzsKOVU4SK4znXNWVvSS4pmueYuWeKsEV0jLlb5JaJHfBVsLVdE9PH0L2KQs3uoMZ7cC09zpWVDHJo5URN6dqLuUx1bacrLm5ZKzC1t214qtGjV87TQcnoxkQl5nI3fF6aKMEsmvj3r9DSIG5z8FZOv3+9qhTxNlT6zAZuZe5fUWVF5vVlw/TU9RBC18E8bn6ou21Ole1TAv2Hk0Qc58kSWP0vw77Y1RjLWT07O38TVAAEMbWbBdx9iqOC61+Dq16JHWt5amRy7uUROc3yp6iz8S21bfcZYFTRuurF62rwNO7Fc6yzXilutBKsVTSytljcnQqKboYevtDmXgWnvlBssro02Z4UXfHIic5viXiim5dGdpKuXUzZzfpds103LMgvNlz9j/2RxdEU5MkRvA6p2vjkc17Va5F0VFTgcEcum43/AF1NTXFE5oa204rsEuGsSQxzxzM2NJPj9SovQ5Os1szZySxDhOqmrbPDLdrMqq5skTdZIU6nt+tNxbbXuRSSWbF1wo2tiqNKqJNyI9dHJ/O9prO1ej8MrzocGSOy9r5Oy5Pq+MXzT/LuNJ3tcxyte1WuTcqKmiofDdm72/LfE6q+94fpeXd4Ujodl2v4TN6+Uj1Tk3lHVrtRSTU2vRHVqif1kU1G3o9l1vgtTcqemmHJfzISi/DU1HBtkzIrKtHardK1U6u/mf4T20uT+UFE5HyMdU6dElW5yL+ToWY7Dy3/AGl6XTHZyXDef4GoUbHyPRkbHPcq6IjU1VS2crMj8SYoqYq29QS2i0ao5z5W6SSp1Mb9amw1qiwBhrR1hw9RxzN8GSOBEd+W7nHXeMVV1a10cbkp4l6GLvXxqS+F0XtnJO3kQ+d0yssi44sN32vn7j1Vs9rwzY4sN4fiZDFCzk+ZwYnTv6XL0qRJ7tVPr3bSnDQ3zFxYYte5E0zjKTlJ6thDLYctzrjcoqZEXYVdZFToanH2HgggfI9rGNVznLoiIm9VM/iu/UOV2BZ7xXcnJc502KeBV3vfpub+CnFVMfaWbDFpcm+JXVVPIsjVWtWyn+7DxTFV3234Ro3osduZy1Rs8OUem5vkaiflFAnsvdyrLxdqq6XCZ01VVSulle7irlXVTxnJMm932Ob7TsuzcKOFjQoj2L49oABYM42x7m3+Aur/AO5n9SHqenOU8fc3L/oNrP8AuZ/Uh6nqup1Po79kXgjjO1/6ld/kzjpwJZl2n7bS/iV+khE9V1QlmXn+t5vxK+tCVzfqJEbcvNNSs5v4VsT/APk5vpqREl2c38K2J/8Ayc301IiccyPrZeLO34X2ev8AxXyAALRkgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA5wSyQTMmicrHsVHNcnFFQ4ABrU2utdZT5oZTR1jGo+7ULdmVqceUam/yOTf4ytKC0z1FVsbCxtb4bnbkZ1qqkfyIx0uCsXMdVyO9yqzSKrb8lOh/jRT3Zr45p71fqyjw2xae1vkVVcm5ZV6V7E7CWeVCytTn6S4eJq9ez7qMidVa8x8U+7vR7b9iuKhida8Ou1eqbM1Xpvd2N6kIhT0M9TMskz3Pe5dVVd522Ki5RW6opsXk1kx7qRw3vEkL6e3ro6KmXc+ftXqaWG53syrLKcGD/bZA8o8nLnjCZtXUI6ltDHfCTuTRZPvW9fjNq8KYbtmG7bHbLRSMp4GN00RN7l61XpUztNBTUdJHSUcMcEEbdlkbE0a1E7A3ZR/EyoUbiNYy9ozyZcXou4pCguEtqvdak6ctQzzPSaJU13Kq70QqvPDKinoFdifD0fKWyfnyMZv5JV/u+rgWPfpWsuFamqbpX+tTqw9iOGiR9tuLWz2yoRWva/ejNeO7q7C86VOG7It42VbjWdZX+K71+pqy+n72Vr2KrXtXVF4Kha2X+PW17IrZdJ0irY9EhmcuiSacNV6+06c6cAe4j3XizNWa1TLtJsrryWvRr1dSlMTyvbLqiqiou5U6DChdZhWcP+zbFXRtWhPX9Uy5c4X3u5XFtyrJVniaxGN0TcxE7CHYev1XZ6ttTRzOjcnhN13OTqVD3YGx3E6NtpxF8JC5Nlk7t+idTutDIYqwU10a3KxuSWJ6bXJtXXd1oZEm7X11L8V2oxq4rHXk2QtF2PsZMqG+4bxvb0oLnE2KqRNyKujkXrYv1EDxZha6YcldPTo+rodd0jE3t8adBFIXzQVG/bilYvHgqKWDhjHFXFG2luiLUw6abenORO3rK3kwyVpatJd/6lvySzDetHGPqv8AIj+HsVVdFOkkE8kb29KO085PrbesNX2NGXih70qV4VdMiaKvW6Pp8mh5LhhPD+Io3VlqmZS1Dt6rGnN17W9BFbnhy/WNVdLSySQt4TRJtNX2Fr+ZVz4otyWNkvzfNl7mT+5YFqqpi1lqWkulPpqj6ZyOcidrPCTzGSyjsFRS4yYstK1itik15uipzVKvtWKLjbpmywzSRvYu5zV2VQsHDWdV7oZmuqkpq1ETZ1niRXafhJopVG6tvVoxL8TLVbgnqmRu9WqZt0qHJTxqiyuXe3tPTU0zkoKPWCLXYXcrO1SZx40wTdn8pXWaopJHLqrqadFRV8Tk+sy8b8ubhBE1LpXUisRU+Ep0dxXX4qmTXXU9eJi25GRFJShyMRkbTOdjXfBG3Sll4N06CJYkbyV+rEWkp10nfvVn3xdeBfeDYbv7pMxOyReSdGjVp3t4+QxV7tWW81bPVPxQ5eUer1aylcq711PXGK4GJC6zrXPTmiOXnEl6tthw/HQOhjjdQrq1YWu3o93Whj6TGGKle1UqY2ptJ4MDE+olt0u+WbaKip5JLlWd5xrGzZRsaORV1366mEq8eYSoE/arDdKr28H1MrpfRuQq361zYjVZJcIcSQpesb3C4ywUCyzIjt2xA1dPGuhIIbjV2WjeuLb5bGbSJ+xkijnl1Tjq1E0TyqU/fs28QVrOQjq+94eiOnakbdPE3j5SFVd1uFfMiayvfIu5GoqqpYtyY6+ajJo2VbJeey5sU5v0dLG6nw3bKahdpsrVrGzlneJETRpWFfiqe5zOdJLLJK92quc5XOcpm8HZS4sxC9s9XF7k0bt/LVbdHOT71nFS1rXhfAGWNIldXTRTV6JqlRVIj5VX/lxpw8fpLUesnx5Iy5eS4/mrzpdyIRgLKy7X/kq6+vkttueu0jFTSeZOxF8FO1ScYrx1hzAlq97+GKankqYk2Wxx744l+U93xnf5XqK+zCzeuV3V9HZnvt1E7VHPVfhpE7V+KnYhW9JJVV1YkEDZJXuXciN1VT1SSekOL7z1Y1lvn38Irs/U9d/uVbfbhNV108lVVTKurnb/ACJ1J2GdwdgtsCtuV2Y1Eam2yJ+5E7XdnYZqzWuz4YoFut3li74RNdt+9sfY1OlxXmOcfTX17qG2q+Ch137+dL2r2dhlqurF8+7jLsX6lcJW5X8ujhHtf6HPNjHE1aySzWWRUpvBmlbuWTsT70r7B2E7nie9w26jjXV7ufIqc1idKqpkqK3vq50janHwlXghcWWFVb8OokMcLXMk05Z/xl7U9hg7ks27ftfD98iSsyIbOxtyhcf3xZa+XuFLHhrCqYe70iqKOZmzVq9iKsjl4qpRefOStZhSZ9+sTH1djmdrzd7oNeheztNhaF7ZY45aeRJYpE1Y5u9FQiecWbFPhazz4Wt3IXC51TFZMx6I6OnRehU6XdnQZGdi1RhquBr+yM/KeS1HzteZp69nJKuvQe1bbcPcpLolHN3mrtjlthdja6teGpZuUmU1wzExKnKI6ntcLkfV1CN3InyW9qm20uHMBph39TvvGFKDktjk9n43XtfL6df/ANEVXRKfE2nM2rVjtR5vt9h+d0VbNTTsngkdHKxdWuauiopeGWGO6fEMTbZcntiubU0aq7km8X3xFc+Mobrl3eHSRtfVWadyrT1KJuT713UqFX0s01LVR1ED3RyxuRzXNXRUVD2jJtxZ/kX7sajaFOsX4M3EzXxAzLzKiaOJUZdboixs385Fcm9fI30qadSzvke5z1VVcuqqSXMDHN8xrLRSXmdJFo4EiZommv3y9q9ZFSnLyXfPXsPNk7P8jqal6TerPqrqfADFJUAAAAAAH1qq1yOaqoqb0VD4ADPOxjiZ1B3kt4qVh2dnwt+nVrxME5Vcqucqqq8VU+ArnZOfpPUohVCHopIAAoKwAAAAAAAAAAAAAADLYQstRiLE9vslK1XS1c7Y93QirvXyJqbq4qZTWPDtBh63tRkMUTWIidDGJonnXf5CmO5AwjJNdKzGFVD8FTtWnpFVOL18JyeJN3lLnxBYrzc7pLUpHEjFXSNFk4NTh7TcejWPCD66x6HM+l+0FdlLHi+EOfiyFO11Pmi9RJkwfd14th+cOxuDLt1QfOG8+WUesjVN9IwVppJKuthp2JzpHI3xdakW7rzFMdFZrbgigl2XPRKiqa1eDE3MavlRV8iFxYcsi2JtVdbs+OOOnhV2qO1RrUTVy+ZDSbMnEUuKsbXS+SqulROqxpr4LE3NTyJoab0n2jGUVXBmz9EsDyjMd8lwh8+wjoANHOoAAAAAAAAAAAAAAAAuXuUcVus2O1sU8ulJd28miKu5JU3tXy708pTR6bXW1FuuVNX0sixz08rZY3JxRyLqhex7nTYprsMPPxI5mNOiX9y/6NxMY0C0F5lYjdI5F22eJePp1MKTqJiY7wTZ7/b9hZKmFsmirpvXc9uvY5F8xjkwXd9f3OH5xDrGFtCqymLlI4vKMqZOua4rgRdEUlWX1etLdVppF+DqE038Nro9gTBl3+RD84d9PhK9QyNkY2FHNVFT4TgpcyL8e2twclxLcpJmsXdF4R96eZNYynh2KCv/AGVTaJuRHLzmp4l1TzFbm6vdIYLlxbln31FAi3a1J3wzZ3qrdPhGp5tfIaVqioqoqaKhyvaFHU3tLkzrnR7aHluFFt+dHgz4WN3Nv8M1h/GP+g4rkl+TV8o8OZl2W7179ilhqNJX/Ja5FRV8mpj40lG6LfeiR2hCU8WyMVxcX8jbbMfdfP6Jv1kTcm8n+J7Q6/uhudrqoJWPjTRdrmvbxRUVPGYFcH3jqg+cOs4OZSqIpyOJ67vmvmRpfIfCTe868fIh+cQ+pg28fIh+cQyvLqPWR7vojG8KSj3mXj5EPziH33mXj7XD84g8to9dDfRFengNewlXvLvHyIfnEC4Lu/yIfnEPPLaPXQ30RQ++YlXvMvH2uL5xD57zLx9ri+cQ98to9dDfRFfIfdSULgy8fa4fnECYNu3SyFP56Dy2j1kedYiL6jUlTcF3RfCdTt/nL7DujwZJG3aq66KJicVRv1roUS2hRH+4K1PkRFF16D10FJUVcqR08L5HdicPGvQZG53bLfDTXOvGIqSSVm/k0l23L/NZ9ZX+Ku6JtlHE+lwfY1cqbmz1SI1idqMbx8qkXldI8alcHqyRxdk5+Y/5Vb073wXxLZhtVosFvfd8TV1PT08KbTuUdoxOz75exCiM7s858RQS4ewnylFaF5ktR4MlQnUnyW9nEqzGWMsSYurO+b9c5qnReZHrsxs7GtTchHzSNpbbuzHouCN62P0Wqw2rb3vz+C/UAAhDbAAAAAADYjuL9VrsRJ/yovWpNLwipcqpP+a/1qV73Gt4oaLFl1tdVUMhmradvII5dNtzXeCnboqr5C8bzgyvnuM89M+B0cj1cmrtFTXo4G+9F8muulqb0OVdKYShtOU2uDS+RBU1Pu8lvvJu3yYfnD57yrv0Mh+cQ2vy3H9dGv76ImfSVLgq8fIh+cQ4+8u8p9jh+cQeW0euhvIi4JOuDLz9rh+cQ+Lg68/aofnEPfLaPWR5vojWunQNSSe868/a4fnEC4PvCcYovnEHltPrIb8e8jmp9RykhTCN4+1RfOIckwjd+mOFP6RB5bT6xS7IojmqqfSSswfdNd/IJ/P/AEHohwdVqvwtRC1PvUVfYHnUL+4862JEdnU7I4HSORrWOc5eCIm9SWVVvwnZI+Wvl+poGpxSWZsfo11IfiPPDLrDLHQ4fppLvUom50LNlmva929fIhG5XSDFpXPVmbjYGXlPSmtv5e8k9lwhWVapLV/saHiu14Sp4ujykWzPzdw7gWilsuFuQuF400c9q7UUK9bl+M7sTy9RS2YOdWMsWskpEqm2u3v3d7UmrdpOpzuK+orVVVVVVXVV6TTtpdIrcnza+CNx2X0PUZK3Nev/ANVy/E9t+u9xvt1nul1q5KqrndtPkeuqr7E7DwgGtNtvVm9RiorRLgAAeHoAAALKyRzRrcB3PvSrWSpsdS74eBF1WNflt7etOkrUFyq2VU1OD0aMfKxasup1WrWLN3ai127ENujvuGKqGpp527aNY7cvi6l60UjU9PNDKscsbmPTi1yaKhrhl9j3EeCLglTZqxUhcustNJzopU7U+tN5sRhTPHAuKIWU2J6X3Hq9NFfIm1Eq9j03p5U8pvWzOk8HFQv4M5ptLoxl4TcqFvw+K/D9Ds2F6j6iEvpLNh69RcvYr3T1LF3pyUrZE9C6nGXBde1V2JoXePVF9Rs1W08exaqRrc5uD0mmn7SJbxqpJlwhdU4RxL/POC4Su/2hnziF7yyn1kU9ZEjmq9R91UkHvTvH8nb+Wh996d4/kzfy09p75ZT6yHWRI8jlPu0pnvepef5K38tB70rx/J2floPLKfWQ34mB21PiyKZ/3pXj+Ts+cQ+e9C8r9gj+cQ8eZT6yG/Exlkmc270q/wDNb6yqe7DVVzEoNf8AhrPpvLvosJXmKsglWGNEZIjl56cEUpbux4ljx3anKnhW1vokean0pthZQnF6mydE9P4kmu5lGgA0E6qAAACd5I46fgTGcVfMjn2+oTkayNOlir4SdqLvIICuuyVclKPNFnIx68mqVVi1T4M3svdso75QxX+wyx1UFQxJNY11R6dadvWhD5YXMVUVNFTiULlJmrfcA1XJRKtdapHay0cjtyffMX4qmxmHswMusdQscy4R264P3LBUuSKRF8fgu85v+yekdcoqFz0ZyrafR/K2fJuEXOvsa5/ijEq1U6AS2pwhI9OUo6xkjF4K5N3nQ8EuFLsxebEyT8F6fWbPDOomtVIgetj2mB2htmY97N5/kTvym+05Nwtel/3JfK9vtK/KqvWQ6yDPmDJFTENN5fUpQHdSLrm/X/iIfoGymG8OXWkvMFRPT7MbFXaXaRdNymt3dUs2M4K3tp4V/qml9LLIWRi4vU2roa15fL/F/NFVAA0c6edtLPNS1MdTTyvimjcjmPYuitVOCoptRlBmfacd2qLDuKJo6a9xt2Y5XKjUqNOCovBH9adJqkcmPdG9HscrXNXVFRdFRTMws23Es34MitrbIo2nVuWcGuT7Ubm3zDddbnq5WrJD0SNTd5eow6wuTihWOWmf9+w/BHbcRQLeqBmjWyOdpOxvVtLud5fOXJZMeZXYuja+G6Q26rfxhnXkXovl5q+c33A6TUWpKzgzmubsLPwW96G9HvXH/oxGxoEQmT8KU9RHytvuMczF3ou5yL5UU8UuEbk3wVhf4nKn1E9DPomtVIhXaovR8CN7xqpnlwtd04U7V/nocVwteP5L/Xb7S55XV6yPVZBmC2l6xtKZz3rXjoo1/LT2j3rXj+Rr+W32jyur1ke78DBo5RtOM6mFbx/I/wCuntOSYUvH8k/rp7R5XV6yG/EwG044OVSSJhO8fyZv5aH1MI3bpp2floePLp9ZDfifMvXL7qTt62J6zUPHu/G161/l0v01N1sI4frrbcpJ6mJrWOajU0dqaW5jNRmPr61OCV8301NC6VWRsnFx9punQn667TuRgAAakdDAAALqyFzdbhxGYbxO90tmeukMyptLTKvWnS3s6C+7nh6nraZtysU0VVTSt22cm9HIqdbV6fEaNE0y6zMxTgeZG2ys5aiVdZKOfnRO8SfFXtQn9lbdtw3uy4xNP230Xjlzd+M92faux/ozYqenfE9WSMcxycUcmiodCt0PLhnPHA2Jo2U+JKZ1oqlTRXyJtxa9j2708qE0pbNZLzD3zYrzBUxu3pycjZE9C6ob1ibexchelxNBysLKw3pfW17ez3kTCqqEmmwfcW67D4ZPKqfUed+FrwnClR3ientJJZlL5SRhq2Bgdpes+aqZv3s3f+Qv86e0+phm8rwoJPOntPfKavWRV1kDCbTj6iqZxML3n+Qv86e0+phW8r/uTk/nJ7R5TV6yPd+JgtTM4KeiYgib0qxx3phS79NJp/PQ9+GcNXOixBFWzxNbCyNzV0dquqmLl5Vbqai9Txyi0zVXP1NM3cQf9z9SEEJ93QiImcGINP5R9SEBOSZX10/Fna9nfZKv8V8gACwZoPrVVrkciqipvRT4ADcHIfHFHmDgtMP3aVEvVBGjHK53OlYm5sida9C/pPZerTU26oWOdi6fFenBxp/ZbpcLLcobla6uWkq4XbUcsbtFRTYrL7ugrdcqeO148pGxSKiN79iZrG7te3injTzG37F6QdQlXbyOc7c6M3V2SvxFrF8XHtXgSJyKnQcdSV0dsw1iGHvrD16p52OTVEilSRPNrqh01GDbkzXk3wyeVUU3araWPatYyNNnJ1y3Zpp+1Eb2j5tqZp2F7yi/vNV8T2+04phi8/yB/wCU32l/ymr1kedZB9phtpT25pPX9b7evxDE/wD7mnvbhS9L/uap43p7Tqzet9RR5BX2GoZsSMhYqprr9maQu3L4TxJKL14GZs1p51GnrL5mmQAOWnbQTDKrH11wDiBK+i+GpZdG1VK5ebKz6lToUh4KoTlCSlF8UWr6K763XYtU+ZvBbZbDmHY2X7DlVHyrk+FiVdHNd8l6dC9vSYCttlTRzLFUROjenQqerrNWsG4sv2Ebq25WGvkpZk8Jqb2SJ1ObwVDY/BHdAYWxDBHb8aUDbbUqmi1DWq+BV6/lN9Juuy+kyilC85rtPotkYknPG8+Hd2r9T2LHoEaTWGy2C90/feH7vBUQu3osciSN9C6p5THVeFLnFvjZHMn3rtPXobdTtHHtWsZGrTm4PdmtH7SOb0Pu/tMpJYrqzjQTr4k19R0utVxRd9DVfNKZKvrfainfi+08KqvWp8Vx7fcuv130NV80pybaLg7hQ1S/0SnvXQ70e70TwK9eg+K5TLR4fu0i7rdUeVunrPdS4Pukq/CRxw/hu1X0aluWVVHnJDrIojabz3W2hqa6dIaaF0jl49SeNegkNVY7BYabvzEV3gp4W715WRI2+1fIVvjrugLFZoJLbgagbVzN1alXIzZhavW1vF3l0IjO6QY+PHg9WZ2Fs7Lz5aUQbXfyXvLJu9yw1ltY3XvEFUx1TsqkMSLq+R3yWN9a9BqLmljy7Y+xG+6XF3JwM1bS0zV5kLOhE7etekxGKMRXrE10fcr5cJq2pf8AGe7c1OpqcETsQxJz7aO07c2esuR0rYmwK9mx35Pesfb3exAAEYbCAAAbXdzav+g+tT/qZvooet/E6u5jpZanJaeGPTamqpkbqvTohJVwhd1XcyJf6Q6bsC+uvEW89OCOM7Zem0rv8mRxNSWZdr+2834hfpIeX3oXhN/JxfOIZrCVlrrZXyTVLGo10eymjtd+qewk8rJqnTJKRG2SUloadZyLrmridf8A7Of6akSJbnI1W5q4mRePulN9NSJHJL/rZeLO34f2evwXyAALRkgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAzuF6N9dXRU0MSyzSORrGNTVXKvQhgjIWG51dputNcaKVY6inkSRjk6FRdT2L0fEt2JuL05m5+S2TdNZoYL3iuOJ9UmjoaN2itj6lf1r2FxVd1oIU0lr6SJE4I6ZqaFT4IxbT5oYJjq4ZEZdKZqJUQo7TR2nHTqUwNyhqY3rG5HNc1VRUXoJ7HUElunM8666y2SuejXYXJPiaws1271Rp4pNfUddJijD9TUNiiu0T3uXRERFKCrUmTcqqZbBNWlBcVqpWJIkcTl0Xr03GRuyk9DFcEo6nPGFNGt6ru8rjSVLXSuVESVEXf0EPuEFdAirLTybPXs6p5zH3GaSaZ71XVXOVfSdNNVVkMiclUSs8TlKG0uBK1VtJcSVYUxBE2N1lu7Gz0E6KxEemqM16PEVVnbl4mF6lLlQyNdb6l68mirzmLx0/SXFh6JkVrmv+InwNoqdqva6RibTlTt/zqa/ZrY4q8Y358u0sdDCqspoUXc1vX41LGbKtU6T4y7CQ2NC6WW5U8If3dzfs9pDW8SZYKxpcbA5sD3LU0SrzonL4Pi6iO4cs1wv12htlspn1FTM7RrGod2I7JdMPXGS33Sklpp410Vr26f/ALIiuU6/PibVfGm7+TPRvuLhShwzjWm75oZ44qvTVyImj0XtTpIvdsM3KzPVZo1fFrukYmrf0Fb0NfV0FQ2eknfDI1dUc1dCzMK5rPSNKTEFOk7OHKtRNfKnSSFeRRdws819/YRFuFk43Gl70e58/wADx0dXPSypJBM6J6dLV0JhZMeVECJHcIW1EfBXJud+kS23DWIoVqbRVsjkdv2W/W0jV2w1d6LVzYVmjT40e/0F7dnVxi9V7DDboyPNsWj9vBk9dHgDEafCsipZ3cVT4J2vqPDXZVQSpylou+rV3o2VuqedPYVjI+eF+zIx7HdSpoe233u40aotNWzRafJeqDymmX1kPdwPfIsiv6m3h3PiiT1OX+KKNy8nDFO1OmORPUp51suKKbwrRWr2tjVU9ByocwMQ06JrWJKifbGIpmKXNW5x6JNSU0ni1T6x/wCP/a2i1Ly5elGMvgYZsGIW7ltVen9E47Y6DEdQ5EZarguvVC4ksOb8jU51rYq9kn6Du/VmmanMtcevbIpV/J7bH7iy3l68KF7yPwYJxnWuRI7NWNRemRuynpJDZslsXVui1ktFRNXjyk20vmbqdUudl5RPgKGjZ40cv1mOrM48XzorWV7KdF6Io2p6eJTJY3e2Vx/iElwjGJaNjyHw/RsbU329z1KN3ubGiRM/KUzjLtlXgZipa4KN9SzgsDeWkX+evDzmuNfi69XNyurblUzqvy5FU8TJ6iodssR71XqTUpU4L0Inrw7rPr5+7gXFjDOm7ViPhs7I7dGu7lNrblVPGvDyFVXO6VdfO+oqamWomeurnyPVzlXxqe+14YuVbo6ZEgjXpfx8xlahuF8MR8pXVDZp0Tc3wl18XQVuqya3pvRe09rdNL3KY6v2GEsmG7ldZWvk+Ag6XvT1ISC6X7DuBqJ0MDmVNeqeCm9yr98vQnYQnE+ZNdWMdTWlvecC7tpPDVPH0EBqHSVEiySvc9yrqqqu9S15ZGhaUrV9/wChn17PsyXrkPSPcvzMrivFd3xHWLNWzqkaeBE3c1qdiHzCMVPWXylo6ypSmhlkRrpXcGoqmKbCumqNU4u2mO3blI92SlPflxZMKqCr6uHBF6YywglgpmVFsR0tGqJq/iqL1r2KRu2XCWOZERV4npyjzESBWYcxI9s1BLzI5ZN/J69C9hyzcbasH3JEtdXDUS1LNtkbXbXJIvSq+okZ2wceshwXajX66rY2+T2rVvk+8kFyzPqcK2SSgt0rX1tQzmoqa8gq/GTtI5lFl/esyMSulke9KVJNusrH79lF4onW5eox2TeXl6zGv/KP246JjkdU1T03InUnWpsXizF9hy8sseDMIJEyrYzZllYmvJbt6qvS9fQWt6V73p8ha68LWmha2Pm+4lNddLNgiyR4Uws2OJ8SbMr2rqrVXiqr0vX0Ecjl5Rnhrqu/a1369ZCLNVpLo971e9y7TnLxVe0t/LmmsN0sc9HKxH1qr8LtbnI3oVq9X1k1TKFNerRqWVCcp6tnfa6m14rskuGMUxRVLJm7DVkT90To39Dk6zVbO3JarwNeXS06PqLLUOVaeo2fB+9d1KnpNjMRWips1WkT9p0Ll1hmTp9imfsl2t+I7VJhrE0LJ2zN2EdIm6Tq39Du0wMrGhZ50SQ2btKzDlz4dq/M/Pe5291M9W6LoY5U0Uvbug8rbjgm4OqqaN9XZZ3LyM6Jrsfeu6l9ZR1S3ZeqaEJZBwejN/xMmORWpxeqZ0gAtmUAAAAAAAAAAAAAAAAAAAAAAAAAAAAAASzDeY2NcOWttsst/qaOjaqubE1rVRFXjxQybc5cy0/jVVL444/8JAAXFbYlopMxp4WNN70q034IsH9WjMv7qKj5tn+E+/q05mfdTUfNs/wleg96+z1n7yn+H4v3Ufcib3rNfMG82ya23DEtVLSTt2ZY0a1u0nUqoiKQgAolOUuMnqXqqa6VpXFJexaAAFJdAAAAAAAAAAAAAAAAAAJbhbMnG2GLaltsl/qaSkRyubEjWua1V46bSLoZb9WvM77qZ/mY/wDCV4C4rbEtFJmNPCxpvelWm/BFifq2Zm/dRP8ANR/4T5+rVmb91NR81H/hK8B719nrP3lP8Pxfu4+5E+nzkzKmjfHJiqrVj0VrkRjE1RfIQOR7pJHSPXVzlVVXrU4golOUvSepeqoqp+ril4LQAApLpJsN4+xlhym72s2Ia6lg6IkftMTxIuqIZpM5syk/jRU/Ns/wlfguK2cVopMxp4ePN70q034IsFM58yk/jPUfNs/wn1M6cy0/jNP80z2Feg96+z1n7yj+H4n3UfcixP1a8y/ulm+aZ7D7+rZmX90svzTPYV0B19nrP3j+H4n3UfcixVztzM+6WX5pnsH6tmZf3Sy/NM9hXQHX2es/eP4fifdR9yLF/VtzL+6SX5lnsC52Zl/dLL80z2FdAdfZ6z94/h+J91H3IsNc6sy1/jNN80z2HXJnLmU9NFxTVJ+C1qfUQADr7PWfvH8Pxfu4+5Exqc0cwqjXlMX3ZNfkzq31GBuWIL7cnK64XivqlXiss7netTGAoc5Pmy9DHqh6MUvwR9VVVdVVVXtPgBSXgAAAAAAAAAAADsp5paeZk0Ej4pWLq17F0VF60UnNHnFmVSwNgixXWuY1NE5RGvXzqiqQIFUZyj6L0LVtFVv1kU/Falh/q1Zm/dTUfNR/4T6mdeZifxnn+aZ7CuwV9dZ6z95Z8gxfu4+5Fi/q25mfdLL80z2D9W3Mz7pZfmmewroDr7PWfvPP4fifdR9yLF/VszL+6WX5lnsPn6tWZX3SS/NM9hXYHX2es/eP4difdR9yLD/VpzK+6WX5pnsPn6tGZP3SzfNM9hXoHX2es/eP4difdR9yLBXOfMn7pZvmmew4OzjzId/GipTxMYn1EBA6+z1n7x/D8T7qPuRNps18xZU0diy4p+C9G+pDFXDG+MLgxWVuJrrO1eLXVTtPWR4FLsm+bZcjiUQ9GCX4I7JpppnbU0r5HL0ucqqdYBQZGmgAAAAAAAAAAAAAAAAAB3U1VU0r0fTVEsLk4Kx6tX0Ekt2YuOrexGUmK7tGxODe+HKnmUioKlJx5Mt2U12enFPxRYEOc2ZUSaJiipd+GxjvWh3JndmWn8Y3r44I/YVyCvr7fWfvMd7OxH/xR9yLI/VwzL+6FfzeP2D9XDMv7oF/N4/YVuD3yi31n7yn+GYf3UfciyP1cMy/ugX83j9h8/VwzL+6FfzeP/CVwB5Rb6z957/DcP7qPuRZH6uGZn3RL+bx/wCE+pnlman8Y1/No/8ACVsB5Rb6z94/huH91H3Ishc8szl/jI782i/wkRxfiq/4tuDK/EFwfW1DGcmxzmo3ZbrroiIiJ0mFBTK2clpJtl2rDx6pb1cEn7EkAAWzIAAAAAAARVRdUAAMtacTYhtLkW2Xu4Uip9qqHN9Sknoc4cyKRERmKKuRE+3I2T6SECBXGycfRbRj2YlFvpwT8Ui0I8+symJp7sQO8dLH7D67PvMteF5gb4qWP2FXAr8pu9Z+8sfwrC+6j7kWa7PjM5eF/Y3xUsX+EguJr9dcSXiW7XqrdV1kuiPkciJqicE0TcYwFErZzWkm2XqcPHoe9XBJ+xJAAFBkgAAAAAHvt15u1tej6C5VdK5OCxTOb6lJHSZo5g0yIkWLboqJwR8216yGgqjOUeTLNmPTZ6cE/FIsGLOfMmPhiaZ34UTF+o9Dc8cym/8A59F8dPH7CtgXPKLfWfvLD2bhv/ij7kWYmeuZSf8A5xn5tH7D7+rtmX/xxn5tH7CsgPKLfWfvPP4Zh/dR9yLM/V1zL/46z82j9gXPXMz/AI8382j/AMJWYHlFvrP3j+GYf3UfciylzzzN+6HT/wBaL/CfP1c8zvujX82i/wAJWwHlFvrP3nv8Nw/uo+5FjSZ35nPaqLiZ6appup4kX6JX1ZUz1lVLVVMrpZpXq+R7uLnLvVTqBRKyc/SepepxqaNergo69ySAAKC+AAAAAAD0UVbWUUqS0dVNTvTg6N6tX0HnAPGk1oyX2/M7H9C1G0+LLpspwa+ZXp6dTMU+d2ZcP8YnSfhwRr9RXALqusXKT95izwMWfpVxf4ItSLP7MlnG50r/AMKkZ7Dvb3Q2Y6Jp33Qr/wCq0qQFXlN3rP3lp7JwX/xR9yLcd3Q+Y68KuhT/ANVp1P7oHMp3C5UjfFSM9hVAHlN3rP3hbJwV/wAUfciz359Zmu4XyJvipIv8J5p878zpk0XE0jPwKeJP7pXIPPKLfWfvK1s3DXKqPuR6rtca27XGe43Gpkqaud23LK9dVcvWp5QCy3qZiSS0QAAPQAAAAADupamppZEkpp5YXpwdG9Wr6CT2zMrHtta1tJiu6Na3g106vTzO1IkCqM5R5MtWUV2+nFPxWpZlLnrmXA3T3dZL+MpY1+o9P64DMvT/AFpSp/6cfsKqBc8pu9Z+8xXsrCf/ABR9yLRfn5ma7heoG+Kjj9hhsUZsY9xLaJrTd766ain0SWJsLGI7RdU10RF4ohBweO+yS0cn7yuGzsStqUaopr2IAAtGYAAAAAAeu23K4W2dJ7fXVFJKm9HQyK1U8xM7TnFmNbkakeJqmdrfi1DWy/SRVICCuNk4ei9Cxdi03fWQT8UmXJRd0Zj2FESeK11OnyqfZX0KZSHumcTNT4TD9pevWivT6yhwX1nZC5TZHy2Bs2XOmPuL/Tunb6ib8MWzX8a86pu6bxKqfBYetUa9aue76yhQe+X5PrsoXR3Zi/4UXPWd0hj2ZFSCG1U+vyafa9akZu+c2ZFyRzZMTVNOx3xaZGxfRTUr4FuWTdLnJ+8yqtk4VXGFUV+CPVcblcLlOs9wraiqlcuqvmkVyr5zygFjXUz0klogAAegAAAAAEowvmDjHDFvW32K+VFFSq9X8m1Gqm0vFd6KZhM5sy04Ypqfmo/8JX4LitsitFJmNPCxpy3pVpvwRYP6tGZn3U1HzMf+E+LnNmWv8aaj5qP/AAlfg96+31n7yj+H4n3Ufcj03Ouq7ncJ7hXzunqqh6ySyO4ucvFVPMAWjLSSWiAAB6AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAD61dF1PgAJ3lLjquwLieC60rnOgVUbUQ67pGdKG5ciWnGeHKfE9ge2VkrNp7U49qL2ofn21yopbnc75rVGBb6lDcJHy2WrcjZo9deTX5SEhg5XVS3ZcjWtu7IeTDrqvTXxReF5oEbqqN0MXSIjWVCdUL/oqWTie3UtwoI75aJGT0dQxH6x700XpQgDqd0S1e7dyEip+SpsylHg0aNXJy4Mr9icovlJLgzDrLhUrVVatjooOdI925F06NTjg6xSXiRrI28xF1kfpuahG89MfUlup/eZhuVqRNTZrJmLxX5KL6zCscKq+tn/2TVcLcm3qKufa+5GEzux0mIatLHZnJHaKVdlNjckrk6fF1FW09vfUVcVLDG58srkaxqdKqeqjeyTmoqK5ThLWPpK1k1PIsU8Lkc1ycUVCAtm7Zb8jcMXHWNX1VS5fvibM4Kw1a8osHJcKyOOfE1ezRqLv5FF6PJ0+Y8b8R4dxlTe5OO7ZFt8Iq6NNFavk3p6iPYKzBosfW+KyYnlbFeIk2aeqXhL2L2+s818tU9tq3Qzxqiou5dNykqoxdadfGP75mqzrmr5LJ4Wc9flp7DB5g5JXS2wuumGJUvNtVNpOT3yNb2p0+QqKop56aV0U8T43tXRWuTRUNhMNYjulkl1oapY2/GjdvY7yEjr5MD41i5PFNnjpKxyad+U6aLr1qvt1MazChZxrej7iRo2xkY3m3x34965/iv0NW6OrqaSVJKeZ8T04K1dCZ2HMi90KNZUqysjT7Ym/zk9xN3P8AWLGtbhO5wXKmcmrWPcjX+ToUq3EGC8RWKRWXO1VNPovFzF0XymJu3474cCVhlYG0I8Gn48/1LCoceYSuzUju1CkL14uc1FTzpvPa6wYQurdu23CJjncEbJ9SlISwyMXRzVTyHKGWaNUVj3t06lMhbRbWlkE/mUS2RFcaZuPxRcs2Xkmiup65j06NTHT4GuzPAWJ3icQGiv14ptOSr6hmnU9TLQY1xDGiftjK78LeVeUY8v7WvxLDw82HKafijOvwde0X9xav85D4mDr2q/uLU/nIY1uPMQafvpF8bEDsc4gd/vaJ4mJ7DzrMfuZ4qc7vj8TMw4Ju71TbdEzxuPdBgRWJtVVexqdOiEOnxZfpUXW4zJ+Cuhjam6XGo/dquZ/jep511C5Rb/ErWLly9KaXgiynW7CdqbtVdeyRydG19SHkqcc2K3orLZQ8o5ODtERPaVm9Xv8ACcq+M+JE5eGpS8uS9BJFyOzYPjbJyJTeMfXuuR0cUqUsa9EW5fORSeWaeRZJpHPcvFXLqeqmttVUO0iicvboZqjwwjGpLcKhkLOOiqW2rbnq+JkxePjrSKSI7DG+RyNa1XL1IZ232J6s5esVIYk37+KmQfXWe2M2aGFJpU+O48tI26YhuDKeFHPVy8E4NQqVUYvTmyiV05LX0V3s9lJTx3GVttttKj1du2tPSYfFVlks9atPJIx66a80nNfdLRgO2LSUyx1N1kbz3J8X9BWdZc6i41klTUvV8j11XUryI1wiov0vkW8N22Sc1wh7eb9p50a/oXRU4E6yky1vWYmIWtc6RluhVFqap+9Gt6k617CG0Lqd9xp2VUnJU75ESR+muymu9TcK81UuGMm0XLiCGdnIo5s0e9yoqc6Ttd6vIW8bHVurfJFvam0JYqjCC86fBPsRisx8cWXLTDrMEYLaxlY1mzLIxU1i61Vel6+goGmuzkuC1NS+SZ73bT1V29VXpVSJ1Vxr5rk+ete9ZZH6yOfx16SSVVqlp6KOrhck0T26q5Og96yVj1S4Iprw68aOknq5c33ssmyXSN8LJIZNWr28CZYfvtRR1DKmmmdHKxUVrmqa/Wq6T0E+01yqxfCb0KWDYrqyoibJHLq1e3gSNOTvrdZDZuznB7y5G0uH79bsYWh1HWRMSoRPhI1+k3/O4h2ILNWWit2JFc+ncusMybvIvUpX9guc9LPHUU86xSxu1a5F4F34WvdDiy1LR1jY++tj4SLXwvvm/wCdxk1y3Hroa5kUyhy5GOtF4t9/t0mGsTQxVMNQzk0WTej06l6ndSmq/dA5O3DAtyfcaBr6qx1DlWKVE1WJfku7TY7EWG6mzVHOV0lMq6xS9PiXtMxYrrRXu2y4axNGyppqhnJo6Tg5Ope3qU8zMGFsN+HIy9l7UtwrNeafNH56ORUXRT4XT3Q+TFdgSvddLWySqsUzuZLpqsK/Jd7Sl13GtWVyrekjpOLlV5NasreqZ8ABQZAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAPqLop8ABe3c65yOwvMzDeInums07tlj3b1gVenxGw9zw42ufy9nfHLR1sTtiRq6tajk469RoGi6cC3crc7MRYOw3WWdqtq4nRqlLyq6rA5U4p7CTxM3cW5PkaptjYTtn1+Nwk+a7H7Sys68dW7L+xrg/Dj2rdZGaVMzeMevH+cvoNXZppJ5nSyOV73Lqqqu9VO+61lZc7hPX1sr5qid6ve9y6qqqWTkFlhUY3vqVdc10VlpHI6pkXdt/eIvWpYttsy7El+CJLGx6NlYzlN8ebfe/3yJP3OOWcNWx+NsWMbFZaVFWKOXhMqdKp8lPTwOGfGUjaeFcaYK/Z1kqOfLFFzlg1/u+osDNDEcFTCzDtkRkFppESNrY9zXqm7zIYjLfFNdhaZ0CtSrtUy6VFK5dd3Srden1mVKmCj1fx9pCQzcqVjyk//X2fqa00XKxVDXsc5j2rqipuVFLuwLjSC90EdjxOqcq1NmCrXj2I5frJBmvlHbbxRvxll9sSwyIr6iiZxavFdlOjxeYpGPbp3rFKixyMXRUXcqKWapTxZ+z4MlLJ0bUq1XNe9Mt292Kot021so+J29r28FQ8Mb3M7DF4Ox5JQwttt4R1XQO3Iq73R+LsJXXWyCppUuFomSppX702V1VpIRlGzjD3EHbG2h7t34PsZ34bxJXWaZHQSK6JV58SruXxdSlq2bENLeKFJEZBVR6aSRTMRVb2L7SiHte1d6Kmh6bXcqy21baqklVkjeKdDk6l60LkZLlLkYOThK3zoPSRcF3wNl5fkctbh5tNK7jJTLsr5uBCrz3PWGanV1mv8tOq70ZUx6onlQluD8Q0l8p/g15OqYnwkKrvTtTrQmFHGjtNozf4fjXQ3kiF/i+0cKe5vvh38TXW5dzxiaHVaGrt9YicNiZEVfIpHKvJbMCnVdmxSyonTG5rvUpuPRQQu0TY2l6jxYlxVb8PQPp6VGT3FyabDd7Yu1y9fYRmRg018mTOD0lzrXpJJmkt9wJimxtYt0tFTSpIqoxZGKiLoY6Gx3Fya8gqJ2m0+bNR7pZeWOSrlc+WSaRznrx13lEXSCopEVHqqxu8B6cFI+dUYs2nFz7L4avRMjDLBVac7Zb41Oz3D2N8k8aeU7qmZ6fGXznifM9ztNRvVrsMlddLtO+O30KSI10rnqq6aIh7KxlDa5lhWnZI9qIu0jkci+Uxz5O9m6fZHf1UFex8lBBVfFTVir2oeqaS4I83JSa3nwOyovlQibMCMiT71DD1dZUTv2pZXO8ajZVztlqaqvUTDDmC2rS+6t+lSjomptaOXRXHkVZc9EXZSpx1rL/ZgMN2CtvVQiRtVkKLz5HcEQkF8xFbsLULrVYFSWscmk1Tx08RjMXYyjfCtqw/H3rRN5qvbuc8g6NklfoiK5yr41U8laqvNr4vv/Q9hRPIe/dwj2L9RU1E1TO6aaR0kjl1VVXXUkdiwpd6+0y3KKBUiYmrUXi7xGdwZgiJIEu2IHpDTt5zYnLorvGZKfHPet5jgooP2tZzHN04p1oV1YsYrfvemvv8Sm/MlJuvGWunPu8CtZ9pHKx7dFRdFQtHInNGbB1clpvG3UWKpdo5NdVgVfjN+tD5jHBkN3ovd+xOZIj02pI2+nylb97OherJU0VF0VFKZ12Ytia/B9545Y+0aHXNeK7UzYnOTLCgudD76sKtjmp52cq9sO9rkX4zfrToKjw5dJbVKtvuDFdSuXZ5yeCTTIvM+bCcqWS9bVVYp3b+lYFX4zezrQnGb2WVNcqJcTYWSOop5m8q5kSao5OO0360Mrhb/Nq4S7UQcbp4UvJcp6wfoy/X2lQYgw+sbe/qFNunfv3b9DwWasmt1SkjdVavhNXgplsOXeW1Srbrixy0zl2ecngHrxHh/k2d/wBAiSU7udom/T9B5uKS6yv8UZvXOD6q3k+T7yV2G4wVMDZYnaovFOlPGTGzXV9LNFUU0ropo1RWubxRSjLTcprbUcoxeavhNXgqE8tF8hqYmyRO8adKGZTkxktJcyIzcGUXrHkbQ4WxBb8V219BWxsSp2NJInJuenym/wCdxEMX2Gaxy7aayUcjtI5ETe1ep3b2lc2a+SwVEU8EixyMcitc1d6KXThPFFDiq3vttxZH31saPjXhKnWhfhNw9HkyBuqdb10MZhu+UN4tsmGcTxR1NNO3k2ul4PTqXt6lNXe6Lycq8B3J12tTH1FhqHrsPRNVgX5LvabC4ww9UWOoR8SPloHrzZOmNepfaZWwXuiutrkw1idkdVS1DOTR0qaoqL8V3b1KUX4HlFe8jJ2ftWeBbvR4xfNfvtPz/BcHdAZOV2BLi+6WpklVYZ3askRNVgVfiu+pSnzW7K5Vy3ZHSsXKqyqlbU9UwACgyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAc43bKnAAGVsSUM92pYrlM6CldI1JXtTVWt13qbrVNHQ23LKmosELE62ujRVkiXV0jVTnLr1r0miupZ2TGalxwZVpQ1ivq7LM74WBV1Vn3zepSQwMiFUmprn2kBtzZ12VXGVT4x46dj/wBk7uDkSXgidB545ERNddCwb9YbZie2NxBheaOeOVNpzGab/J0O7CvJ6aWB7mParXNXRUVNFRTPnHR8ORAUXRsjpya5ozWGMS1+Hq9KmhnXZdpysLlXYkTtTr7TN4uwXhvMqjku+HnR0F9a3amp13JIvan1oQJ6Key23KroKuOppZ3wzMXVr2roqFlpNaPkXHXKMusqekvn4la4gtVfY6+S33SkkpqiNdFa9FTXtTrO3C+K7lh2rSSlftwqvPhd4LkNg33DDGYtubZsWU8VNcdNIKxnN1XsXoXsXcUjmjllfsGTrUbDq62KvMqYmqqJ2OToUxp1Tq8+HIlMbNqyv5F60k+x8n4E8tdxsuLqflaB7aau01fTuXivZ1mMuVLNRyqyZitVCorfVzU8rZ6aV8UjV1RWroqFj4ex9DWQtoMRx7XQ2oRN/lMqrKhYtJ8H3mNkbMsx3vVcY93avA91HcZaGtjqqSVYpo11a5FLxwLiqmvVnkqp5YaV9Kid9K5dGtReDk8fUUpcLKj40q7dM2pgdvRWrqdlnrZKW3VdCurUmVir/NVfaX6rbKZcHwInOxKsutd695a+JcwnyNdQ2F7oYl3PqV3Pf4vkoRNlVI/nOerlXiqrxIzSyrt71M1TPRY0KXJy4ssRx40rdijO5jTOXL6woi/GeVzSPbJC+CojSWF/hNX1p1KT/MBdrAViT755X9IiIiqqamLNeeSeJL+T+JH8T4fmoo+/aZzp6Fy6JIib2L8l3UvrMHyaUsSTPTWR37m1fWWrbLrSWaOWtuEDKikVqsfSv3pUap4On19BBZm2u5Vj5XMdRue5dlqauY1OhE6dC1ZVuvgSuNkynHzuS7SJTbTnK5yrqpJsKWuovmG7pb6eN0lRCrJ40RN6prsr60Pf702s0qamqgjo9NeV2uKeJd50VmLqSyUslFhmJY5Ht2ZKl3hOTsPY1KHGb0Rene7lu0rV/BHpgorJgmmSrvbmVl001jpWrqjF++IPirFN0xFUq6olVkCLzIWro1qGNr5p6ud01RI+SRy6qrl1VTO4Qwfcb5KkmwsFKi86VyerrLbnO3+XWuHd+plQqrx1110tZd/d4GEtdsqa+pbBSxOlkcuiIiFlWPDNtwxStuN55OWq01ZGui6L9Z75qqxYPpFpbcxJ61U0c9d669q/UQu53GquNS6eplc9y9a7k8RfjCGPxfGXwRizuty+C82HxZ7sS32qvEit/c4E8GNOBH3Ro3foelHaIcUjlnkSOFiuc5dERE4lmc5WPWXMv1xjXHdjwRnME4kqbJWJHtPkpZF0fHr6UJDmLg+Ortb8RWxqxojOUlYqabl6TuwjhCmtVKt9xHJHDFEm0jH8E8fWvYQ/MrMKpv8AItut6up7XGuiNTcsna72GY5xrx3G7t5LtRHQ3sjLUsbkvSfY/Z7WROCpcxFaq7td5b2R+bc2Eqxtlvb31FiqHab11WnVfjN7OtCkWv366nYsy6acUIuu11veRM5eFVlVuuxapm2GbmW9Je6H3x4ZWOZs7OVVsS6tlau/ab29hS9mvNXY6tbdcNp1Iq7O/iwyeQmbs+Eqptivsj6iwTu0373Uzl+M3s60LazZy5ocQ25MQ4eWGdZmcoiw6KydvHVNPjdnT4yXrcb11tXCS5o1RuzZ1nkuXxrfoyKXxTZEWL3Rtz0fC9NpWt36dqEat9wnoahJI3Kip4SdZm7RXVVhrXUNc176RV0VHJvYp6sR4egniW4W1UdG5NpWt9aFmcOs8+taNc0S9dnVfy7eKfJmbw/emVUTXxv3pxb1KTWyXOeGeOaCV0cjF2mubxRSjKComoKlJI3Kiou9OhSxcPXWOpga+N+i/GbrvQv49u/wlzMDPw1Hzo8jZvBuJaTE9vdbrkyPvzZ0exyc2VvWn1oRfGeHJrPOs8DXPoH7kcnGNepfqUry0XCWKRk0U745WKjmva7RUUunBWKaXEdEtvuPJpWbGy5q+DMnWnb1oStFsqZarkajk47req5GGw9fqKsoFw5iSNlRRVDOSR829FT5LvqU1s7oXJqswRcJLxZon1Fgmdq1yb1gVfiu7OpTYbGOGJLXM6eJHSUMjtUXpjXqX6lPVhvEFLU0jsO4jZHVUFQ3kmPlTVNF+K7s7egs5+JVet6P/Rl7M2jbgT6yvjF813/7NCQXV3Q+TFVgurffLGx9TYZ3a7k1dTqvQvZ1KUqatbVKqW7I6Xh5lWXUranqmAAWzKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB9a5Wrqh8ABOctMw7tgy4pLSSLLSPX4emevNen1L2mxVHLhvMuze6lknjhr2t+GiXwmr1PTpT75DTxNxlsMYiu2HLrFcrRWSU1RGuurV3OTqVOlDMxst1cJcUQm0tjxyf5lT3Zrt7/ABLtvlvq7VVvp6uF0T2r0puVOtF6UMU6VFUnGCcwMNZj29lpvzIqK8aaNRdzXr1scvBewwuMcH3CxSula1ZqXXdI1OHjToJaVUZx6yp6r5GvV3Srs6nIW7P4PwMCx+q6OXcTfCWO6mgpvcy8R+6VtcmyqPRHPY3q3+EnYpXquei7znFI7fztDG3pReqMm3HhbHSSJXjXKmz3+lkvmBamJrnc59JruVepPkr2KUpdKCvtdW+kuNLJTzMXRzXt0UtOzXevtdSlRQ1UkMiLv0Xc5OpU6SauuWFcb0baDFNJHT1mmkdS1NN/Y7o8S7izOmNnGPBlyjNvxPNs8+Hf2r9SgLDiO6WSdH0c7uT+NE7e13kLJsOJ7BiFqRVad4Vi7tV8FV8ftPBj7KC82Rr620L7p2/TaR8ac9qdqJ60K0RssEqska5jkXei7lQojbbQ9JLgZ8qcXaEN+t8e9c/xLwntVRSLtp8JEu9Ht3nqpXIkSKVdhvG93suzG2Xvmm6YpV1TydRPbXiiw36NGxSJQ1i8Y5F5rl7FMuN9c1w4MhsnZ99XFrVd6Jjjxye8OxL1q8rtksUML5Zl0Y30r1ITrMR7qfAOHmv3LtSalSV17ooXryz0le3wI04IWbZqMivZ9Ep1aLvfzO+v77us/KyIkcTdzG67moeR9xtloXVrUqqhOGvgopg7rf6mrRWNXk4/ktMQivkeiNRXuXqMeV3HhzJyvDe7pPgu4y14vdddH61Ey7CcGIuiJ5Dx0dHUVsyQ00TpHrwREJFYMF1tU1tTcHJSU/HneEqeIzk10tVihWmtMLHyaaLJ+k9VcpedNh5EIfy6Vq/gdVgwhbbZG2vxBPG5yb2w67te3rO2/YvlkiWitTUpadE2dWpoqp9RGbhcKuumWSolc9ehOhDoahc67dW7WtPmWvJ3OW/c9X8EfH7b3K97lVV6VODtx26Kq6IS7BOBLjiCVkrkWClVf3RW73djU6SmuqVkt2K4ly7Irohv2PREasdnrrxWNpqOB8jncdE3InWqllxWnD2X9oS63uTlatyfBsTw5F6mIvBPvlMnifEOF8sLWtBQthq7xpup2rtIxflSOTp+9NfcVYjumI7pJcLpVPnlevSu5qdSJ0IXrJV4vBcZ/BGDTXftN6vWNXxl/oyOO8aXLFFZrKvIUbF+Bp2LzWp29a9pFVCrqfCLnOU3rJ8TZKaYUwUILRI+6jVT4Ckun1F0UuLIPNypwbUpZb26Srw/O7RWKurqdV+M360KcOcT9letC5VZKuW9FmNl4lWVU67Vqmbi5pZfW3EtsbiTDToahZmcojol5s7ez771+MpK01dRY6x1LVMV1KrlRzF4sU9ORWbVRg2sbabor6qwVDk241XVYFX4zfYXPmZgWixLbG4jw4+KfvhnKMdH4M6fU4mq5LI/mV8JLmjTJKzZs/J8jjW+T/UpPEVihqI/dC3Ij2OTaVG+sj1vnmoalHxqrVTinWZejudZhu4PpauN60qu0exU3sU91+tEdXTpcrbsvY9NpUb0lMq1ZrOHBrmiThZKrSFnGL5MzVju0VTCjmu0cnhN6iT2m5ci9kkcqskY7VrkXei9ZS0FbNRT7bFVrkXehLbLfmVLE0XRycU14F6nJ1818zDy9n/3R5G0mCsW0WIKT3MuSx99qzZVrk5syab9O3sI5i/Dj7LK6ohRZLe9dWrvVYl6l7OpSpbfeHxPY+NzmPYqK1zXaKip0lt4ezKt1VY5afEELnzNZsqjW7STp9SmdXJ66o1rIxJ0vegtV3HqwtiGCejfYL+xlTbp2LGjpU2kRF3bLuzt6DXbuhsmKnBtVJf7Ax9TYJnbSom9aZV6F629SlptroJ5397wujhc5VYxztpWp1aljZfsqbxY6y3XWnbU2p7ViZyqa7SLxb2p6j3aGFXdDeXArwNo3bNt34+i+a7/APZ+fYLCz6wE/AWOp6GJq+59TrNRuX5Cr4PjRdxXpqE4OEnF80dRx74ZFUbYPgwACkvAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAHZTzPhlbJG9zHNXVHNXRULxyvzkfDBHZsWp33SabDKlU1exOp3ykKKOTXK1dxfx8idEt6DMLNwKc2G5av1RthfMGW28UaXXDM8MkUqbSNY/VjvEvQvYpXdwoamgqHQVMD4pGrorXJopXuBsfX7CNWktuqVdCq/CU8i6senahfWGsbYOzHpWUVfGyguemiRyORFVfvHfUpM03UZXD0ZfBmq5GLl7O4y8+vvXNeJX23onHQ5NqNheJJMXYHuNoc6aBrqmlT47U3tTtQhsu0xdFapTbTKt6SReotrvjvQepMsN44ulkc1kMyzU/TDKurfJ1GWvFBgjHsbnujbabo5PCRERHL29ClZorlXpOxkj2uRU185b39VpJao8liJS363uy70eTGGXl9sDnSJH33S9EsKapp2pxQhciywyfGY5PIXPYMW3GhRIZH98QcFZIuu7xmSr7Lg/FrFcsbbdWu+M1ERFXxcFLbwlZ9W/wAGZNe1LKfNyI6rvX5opesxNfqu0w2ue4TSUsCqsbHLrs68dDEMY96/Gc5SyLnlZc6O4o11VT96LvSbXini6zJ0Vsw3h6Pb0Ssqm/GciLoviLUcKxvz+HiZv8Sx4x/lcde4hFgwhdLnsySN72p+mSRNPN1kup4cN4Wj1ialZWInhuTXRfqPLfcRVdXrHEvJR9TSNyI5zlVyqqr1lzSFXorV95abtyPrHou5GTvOIK+5vVHP2IuhjdyGJ06XLqcmtVF4H1GOcuiIqqW3rJ6svRUYLSPBHFuz1Htt1BUV07YaaB8sjl0RrU1VSSYPwFdL1IyWWJ1PTKvhuTe78FOkn10r8G5ZUCtqEbUXFW7qaNyLK5fv3fFTsTeZlWH5vWWvdiR2RtFKfVULfn3L8zHYTy7pqKnW64hfDHFCm0/lH6Rx/hL0r2IYDMPOCKlppLNgyPkGaLHJXKmj3J1MT4qekr/MHMS94tqdKiXvehYvwVJEukbPJ0r2qQtzlVdVMS/NSW5RwXf2sy8TY8pyV2Y959i7EdtVUS1MzpZpHPe5dXOcuqqp0gEabAlpwQAAPQAAAAADnHIrVLhyJzfqcGVTbPd3Pq8P1DvhI13ugVfjN9nSU2C5VbKqW9ExsrEqyq3XYtUzcjNXANtxbZ24gw7LFO6aPlI3xqmzMnb1OKBttfXYYuT6GrY/vba0kjcm9insyNzarsEViWy5q+ssNQ7SWFV1WJV+Ozq8XSXXmbgS1Yws0eJMOSxVHLM22SR8JU6l6nE3CayV1lfCa5rvNP0s2XPybJ86qXJ93iUxiSyxV9Olytrmva5NVRvSRGCSekn22qrXIu9CR2+asw9Xup543rBtbMkbk3t8R78TWGnrKD3Wtz2q1U2nIn+eJZnX1qc48GuaJSq7qWq5vWL5MWG6MqY0Ta0enFCR00+qtTX0lZ2/lI5WujVUcnUXBlXh+XEdS2orEWKgh0WV/Db7ELuLbOb3dOJh7QqrpTm3wJvlrhea9vSrqEfFb2Lvdrosi9SdnaZ3HeMmUr22GwSJCyFESWWPgiJ8VvtMbirHdDDQLZcOyRsgjTknyRbk3cWt9pXkUzXzuevFTMvm0t1M1qvHd03ZatF2IlPdeWyK65TWnEStRZ6eaPndOzI3f6UQ1CNxu6MqGt7neCN6pq91MjfMqmnJCbRWl34G59F5N4Wnc2AAYBsYAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAOUb3xvR8bla5q6oqLoqHEAFvZc5zXO0sjt2IGOuVCnNR6u+EjTsXpTsUs5LRhPHNK6vw9VxsnVNpzG7lRfvm9HjQ1TMjZrzcbRVsqqCqlp5WLqjmOVCSo2jOK3LPOiQOZsOuyTtx3uS9nJ+KLovmFrjaJFSop3bGu6Ru9q+UwzolT4qoZjBmeEU8Tbfi+jZKxU2e+Y27/5zekmVbhyxYhovdHDVdA9r010Y/VvlTi3ykpXVVkrWiXHu7SFstyMSW7lR09q5FYquyeyhnVHpovSdl8stwtsysqqZ7E6HcUXxKeOibz2ou7eYkoSrlozLThZDVPUlONquRuGKRyPciqqa7+wrxJlk1VVUn+YMWxg+if0bSeoriFxRkuXWaM92dCPU6rvZ2SHW1iuXgZe0WO5XiZI6Kle/fvdwanjUsvDeXtrtlKtxv8AUxKyPe5ZJNiJvjVePiQuUYVlvHku98j3Iz6sfg3q+5cyusP4Wul6kRKWmerNedIqaNTylkW/CGGcIUbbniOqjR6JqnKb9fwGcXePgYXGWcNos0DrbhOljmkYmylU9ujG/gM+tSksQ4kud7q31VfVyzyvXVXPeqizIoxnpDzpd/YU1YeZncbPMh3drLTx/nNM6KS34VhdQQqmytQq6zPTsX4qdiFL1lXUVc7pqiV8j3LqrnLqqnS5Vcuqnwi78my+Ws3qbDh4FGJHdqjoAAY5mAAAAAAAAAAAAAAAH1NxamROalVge494XBX1NhqXfDwquqxr8tvUpVR9RdFLldkq5KUXxMfJxq8mt12LVM3Kx/g20YwsjMS4ZliqklZtNfHwk7F6nIa+3mS42p01vVZIWKukka7t6HPJTNS4YCuqQzbVXZqhUSppXLu0+U3qVC/Ma4Lw7j+iosS2adkkEuj9uP46dLXJ0OQnISWbHWHCfzNQcJ7Is3L/ADqnyfd7CncvMMyXiVKmoRYqRi6vevT2IZvMTMOG30C4aw29Iomt2JJGdXUntOjMu81dqo/e/YqSSCNqbMjkaqeRCqYrfVveqyMerl3qqjItWNHqalx7X+SMzGx1mS8oufm9i/NkqwbcpOTmie9XLrtb1LAwhSVV4vFPRQsVeUcm0vyW9KkAwRhu7VtzbFR0ksiu4qibk7VUvunfY8q8HT3i6ytlq3t0RNedM/oYxOrrU9xIT3N+fCKMTatkFPcq4zlySIJ3XuI4oqK04QpXIiMTviVqLwRE2WJ5tV8prgZfGF/rsTYirL1cJFfPUyK5epqdCJ2IhiCGyruutczZtl4SwsaNXb2+IABjkgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAADK4dxDd8P1baq1V0tO9F3o125fGnSYoHsZOL1TKZwjNbslqi+MKZx2+5RNocV0TGK7cs8bNWL2q3o8hLHYSst9hS4YduELmrv0Y7aZ7W+U1bMpYMQXmw1baq1XCelkavxHaIvjQl6drPTdyI7y+JAZGwYpueLLcfd2GzWOcJXStwjQUMMScryiIrlVNlNE3rqYey5e2m00/ft+ro3MZvcr3bEaeVd6kJbn3iF1nZS1Fuo5apngzqionDireGpXmJsW3/EVQs11uM03yWa6NanUiJuQzLtpYSe/GG9L28kYGLsjaDi6pzUY69nNl1YmzWw/YIHUWGqOKrkbuSRW7MSL2JxXylN4uxnf8TVKy3OvkkZrzYkXRjexGpuQjquVeKnwicraF+Twk+HcuRO4WycbE4xWsu98WfVVV4qfADBJMAAAAAAAAAAAAAAAAAAAAAAAAE1y0zJxFgSqX3OnSaikX4ajm50b/J0L2oQoFcJyrlvRejLV1Nd0HCxapmz9JnBltiSBvu/b5aCoVOckkKSs8jk3nN2Jclofhm11K9eOy2CRV8y7jV0EnHbN6WjSfiiEfRvG18yUku5M2PveeeFrPTup8K2Z9S9E0a+ViRRovXstXVfOUhjjGF8xhdFr71Vulcm6ONNzI06mpwRCPgxMnOuyOE3w7jPw9lY2G96uPHvfFgAGISIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB/9k='
        $logoTag = "<img src='data:image/png;base64,$logoB64' style='height:40px;vertical-align:middle'>"
        $html = @"
<!DOCTYPE html>
<html lang="en"><head><meta charset="UTF-8">
<title>ADDetector Report - $domain</title>
<style>*{box-sizing:border-box;margin:0;padding:0}body{font-family:"Segoe UI",Arial,sans-serif;background:#0d111e;color:#c8d0e0;font-size:14px}.page{max-width:1100px;margin:0 auto;padding:32px 24px}header{display:flex;align-items:center;justify-content:space-between;border-bottom:3px solid #4a9eff;padding-bottom:16px;margin-bottom:28px}.brand{display:flex;align-items:center;gap:14px}.brand h1{font-size:26px;color:#fff;letter-spacing:1px}.meta{text-align:right;color:#7080a0;font-size:12px;line-height:1.8}.section{margin-bottom:32px}.section h2{font-size:15px;color:#4a9eff;text-transform:uppercase;letter-spacing:1px;border-left:4px solid #4a9eff;padding-left:10px;margin-bottom:16px}.cards{display:flex;gap:12px;flex-wrap:wrap}.card{background:#1a1f35;border-radius:8px;padding:16px 20px;min-width:130px;flex:1;border-top:3px solid}.card .num{font-size:32px;font-weight:bold;line-height:1.1}.card .lbl{font-size:11px;color:#7080a0;margin-top:4px;text-transform:uppercase}.findings,.actions,.bar-chart,.env-grid{background:#1a1f35;border-radius:8px;padding:20px}.findings li,.actions li{padding:7px 0;border-bottom:1px solid #252d45;list-style:none}.findings li:last-child,.actions li:last-child{border-bottom:none}.findings li{display:flex;align-items:center;gap:10px}.icon{font-size:18px;width:28px;text-align:center}.actions li{padding-left:20px;position:relative;color:#c8d0e0}.actions li::before{content:"→";position:absolute;left:0;color:#4a9eff}.two-col{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin-bottom:32px}.bar-row{display:flex;align-items:center;gap:12px;margin-bottom:10px}.bar-label{width:80px;font-size:12px;color:#7080a0;text-align:right}.bar-track{flex:1;background:#252d45;border-radius:4px;height:24px}.bar-fill{height:100%;border-radius:4px;display:flex;align-items:center;padding-left:8px;font-size:12px;font-weight:bold;color:#fff;min-width:32px}.bar-count{font-size:12px;color:#7080a0;width:40px}table{width:100%;border-collapse:collapse;background:#1a1f35;border-radius:8px;overflow:hidden;font-size:12px}th{background:#252d45;color:#7080a0;text-transform:uppercase;letter-spacing:.5px;font-size:11px;padding:10px 12px;text-align:left}td{padding:9px 12px;border-bottom:1px solid #252d45;vertical-align:middle}tr:last-child td{border-bottom:none}tr:hover td{background:#1f2640}.badge{padding:2px 8px;border-radius:4px;font-size:10px;font-weight:bold;color:#fff}.yes{color:#2ecc71;font-weight:bold}.no{color:#7080a0}.env-grid{display:grid;grid-template-columns:1fr 1fr;gap:8px}.env-item{display:flex;gap:8px}.env-key{color:#7080a0;min-width:120px;font-size:12px}.env-val{color:#c8d0e0;font-size:12px}footer{text-align:center;color:#3a4460;font-size:11px;margin-top:40px;padding-top:20px;border-top:1px solid #1a2035}</style>
</head><body><div class="page">
<header><div class="brand">$logoTag<div><h1>ADDetector</h1><div style="font-size:12px;color:#4a9eff">Executive Security Report</div></div></div>
<div class="meta">Domain: <b style="color:#c8d0e0">$domain</b><br>Scan Date: $scanDate<br>Generated by ADDetector v1.1</div></header>
<div class="section"><h2>Environment</h2><div class="env-grid">
<div class="env-item"><span class="env-key">Domain</span><span class="env-val">$domain</span></div>
<div class="env-item"><span class="env-key">Total Users</span><span class="env-val">$total</span></div>
<div class="env-item"><span class="env-key">Enabled</span><span class="env-val">$enabled</span></div>
<div class="env-item"><span class="env-key">Disabled</span><span class="env-val">$disabled</span></div>
<div class="env-item"><span class="env-key">Service Accounts</span><span class="env-val">$svcAcc</span></div>
<div class="env-item"><span class="env-key">Scan Date</span><span class="env-val">$scanDate</span></div>
</div></div>
<div class="section"><h2>Executive Summary</h2><div class="cards">
<div class="card" style="border-color:#e74c3c"><div class="num" style="color:#e74c3c">$critical</div><div class="lbl">Critical Risk</div></div>
<div class="card" style="border-color:#e67e22"><div class="num" style="color:#e67e22">$high</div><div class="lbl">High Risk</div></div>
<div class="card" style="border-color:#f1c40f"><div class="num" style="color:#f1c40f">$medium</div><div class="lbl">Medium Risk</div></div>
<div class="card" style="border-color:#2ecc71"><div class="num" style="color:#2ecc71">$low</div><div class="lbl">Low Risk</div></div>
<div class="card" style="border-color:#4a9eff"><div class="num" style="color:#4a9eff">$inactive</div><div class="lbl">Inactive/Stale</div></div>
<div class="card" style="border-color:#9b59b6"><div class="num" style="color:#9b59b6">$dormantVPN</div><div class="lbl">Dormant VPN</div></div>
</div></div>
<div class="section"><h2>Top Findings</h2><div class="findings"><ul>
<li><span class="icon">&#128308;</span><b>$privInact</b> privileged account inactive &gt;30 days &mdash; immediate review required</li>
<li><span class="icon">&#128992;</span><b>$vpnNoMFA</b> VPN account without MFA &mdash; high lateral movement risk</li>
<li><span class="icon">&#128992;</span><b>$dormantVPN</b> dormant account with active VPN access</li>
<li><span class="icon">&#128993;</span><b>$neverLogin</b> account that has never logged in &mdash; potential orphan accounts</li>
<li><span class="icon">&#128993;</span><b>$inactive</b> account inactive for 30+ days</li>
</ul></div></div>
<div class="section"><h2>Recommended Actions</h2><div class="actions"><ul>
<li>Review and disable <b>$privInact</b> inactive privileged accounts</li>
<li>Enforce MFA for <b>$vpnNoMFA</b> VPN users lacking multi-factor authentication</li>
<li>Revoke VPN access from <b>$dormantVPN</b> dormant accounts</li>
<li>Investigate <b>$neverLogin</b> accounts that have never authenticated</li>
<li>Review service account inventory ($svcAcc accounts) for least privilege compliance</li>
</ul></div></div>
<div class="two-col">
<div><h2 class="section" style="font-size:15px;color:#4a9eff;text-transform:uppercase;letter-spacing:1px;border-left:4px solid #4a9eff;padding-left:10px;margin-bottom:16px">Risk Distribution</h2>
<div class="bar-chart">
<div class="bar-row"><span class="bar-label">CRITICAL</span><div class="bar-track"><div class="bar-fill" style="width:${wCrit}px;background:#e74c3c">$critical</div></div></div>
<div class="bar-row"><span class="bar-label">HIGH</span><div class="bar-track"><div class="bar-fill" style="width:${wHigh}px;background:#e67e22">$high</div></div></div>
<div class="bar-row"><span class="bar-label">MEDIUM</span><div class="bar-track"><div class="bar-fill" style="width:${wMed}px;background:#f1c40f;color:#000">$medium</div></div></div>
<div class="bar-row"><span class="bar-label">LOW</span><div class="bar-track"><div class="bar-fill" style="width:${wLow}px;background:#2ecc71;color:#000">$low</div></div></div>
</div></div>
<div><h2 class="section" style="font-size:15px;color:#4a9eff;text-transform:uppercase;letter-spacing:1px;border-left:4px solid #4a9eff;padding-left:10px;margin-bottom:16px">Inactive Distribution</h2>
<div class="bar-chart">
<div class="bar-row"><span class="bar-label">0&ndash;30d</span><div class="bar-track"><div class="bar-fill" style="width:${wi0}px;background:#2ecc71;color:#000">$i0_30</div></div></div>
<div class="bar-row"><span class="bar-label">30&ndash;90d</span><div class="bar-track"><div class="bar-fill" style="width:${wi1}px;background:#f1c40f;color:#000">$i30_90</div></div></div>
<div class="bar-row"><span class="bar-label">90&ndash;180d</span><div class="bar-track"><div class="bar-fill" style="width:${wi2}px;background:#e67e22">$i90_180</div></div></div>
<div class="bar-row"><span class="bar-label">180d+</span><div class="bar-track"><div class="bar-fill" style="width:${wi3}px;background:#e74c3c">$i180p</div></div></div>
</div></div></div>
<div class="section"><h2>Top 20 Critical Accounts</h2>
<table><thead><tr><th>Risk</th><th>Username</th><th>Display Name</th><th>Type</th><th>Inactive</th><th>VPN</th><th>MFA</th><th>Score</th><th>Why Flagged</th></tr></thead>
<tbody>$top20Rows</tbody></table></div>
<footer>Generated by <b>ADDetector v1.1</b> &nbsp;|&nbsp; &copy; 2026 Eren Arslan &nbsp;|&nbsp; <a href="https://github.com/ErenArslann/ADDetector" style="color:#4a9eff;text-decoration:none">github.com/ErenArslann/ADDetector</a></footer>
</div></body></html>
"@
        $enc = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText($path, $html, $enc)
        Write-AppLog -Component 'Export' -Message "HTML report OK | path=$path"
        Set-Status "HTML report exported: $path"
        $result = [System.Windows.Forms.MessageBox]::Show("Report saved:`n$path`n`nOpen in browser?",'ADDetector - HTML Report','YesNo','Information')
        if ($result -eq [System.Windows.Forms.DialogResult]::Yes) { Start-Process $path }
    } catch {
        Write-AppLog -Level ERROR -Component 'Export' -Message "HTML report failed: $_"
        Set-Status "HTML report error: $_"
        [System.Windows.Forms.MessageBox]::Show("Export error:`n$_",'ADDetector','OK','Error') | Out-Null
    }
}

function Export-CSV-View {
    if (-not $script:filteredRows -or $script:filteredRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('No data to export.','ADDetector','OK','Information') | Out-Null; return
    }
    $path = Get-ExportPath 'csv' 'CSV (UTF-8 BOM)|*.csv'
    if (-not $path) { return }
    try {
        Set-Status "Exporting CSV..." $true
        Write-AppLog -Component 'Export' -Message "CSV export start | path=$path"
        $rows = Get-CurrentFilteredView
        $enc = New-Object System.Text.UTF8Encoding($true)   # UTF-8 BOM (Excel-compatible)
        $csv = $rows | ConvertTo-Csv -NoTypeInformation -Delimiter ','
        [System.IO.File]::WriteAllLines($path, $csv, $enc)
        Write-AppLog -Component 'Export' -Message "CSV export OK | rows=$($rows.Count) | path=$path"
        Set-Status "CSV exported: $path  ($($rows.Count) rows)"
        [System.Windows.Forms.MessageBox]::Show("Exported $($rows.Count) rows.`n$path",'Export CSV','OK','Information') | Out-Null
    } catch {
        Write-AppLog -Level ERROR -Component 'Export' -Message "CSV export failed: $_"
        Set-Status "CSV export error: $_"
        [System.Windows.Forms.MessageBox]::Show("Export error:`n$_",'ADDetector','OK','Error') | Out-Null
    } finally {
        $progBar.Visible = $false
    }
}

function Export-XLSX-View {
    if (-not $script:filteredRows -or $script:filteredRows.Count -eq 0) {
        [System.Windows.Forms.MessageBox]::Show('No data to export.','ADDetector','OK','Information') | Out-Null; return
    }
    if (-not (Get-Module -ListAvailable -Name ImportExcel)) {
        Write-AppLog -Level WARN -Component 'Export' -Message 'ImportExcel module not installed'
        $msg = "ImportExcel module not found.`n`nInstall:`n  Install-Module ImportExcel -Scope CurrentUser`n`nFallback to CSV?"
        $r = [System.Windows.Forms.MessageBox]::Show($msg,'ADDetector','YesNo','Question')
        if ($r -eq [System.Windows.Forms.DialogResult]::Yes) { Export-CSV-View }
        return
    }
    $path = Get-ExportPath 'xlsx' 'Excel Workbook|*.xlsx'
    if (-not $path) { return }
    try {
        Set-Status "Exporting XLSX..." $true
        Write-AppLog -Component 'Export' -Message "XLSX export start | path=$path"
        Import-Module ImportExcel -ErrorAction Stop
        $rows = Get-CurrentFilteredView
        if (Test-Path $path) { Remove-Item $path -Force }

        $excel = $rows | Export-Excel -Path $path -WorksheetName 'ADDetector' `
                    -AutoSize -AutoFilter -FreezeTopRow -BoldTopRow `
                    -TableName 'ADDetector' -TableStyle 'Medium2' `
                    -PassThru
        $ws = $excel.Workbook.Worksheets['ADDetector']

        # Risk-based row coloring (basic)
        $lastRow = $ws.Dimension.End.Row
        $lastCol = $ws.Dimension.End.Column
        $riskColIdx = 1
        for ($i = 2; $i -le $lastRow; $i++) {
            $lvl = $ws.Cells[$i, $riskColIdx].Value
            $bg = switch ($lvl) {
                'CRITICAL' { [System.Drawing.Color]::FromArgb(255,200,200) }
                'HIGH'     { [System.Drawing.Color]::FromArgb(255,225,180) }
                'MEDIUM'   { [System.Drawing.Color]::FromArgb(255,245,180) }
                'SVC-ACCT' { [System.Drawing.Color]::FromArgb(210,225,250) }
                'DISABLED' { [System.Drawing.Color]::FromArgb(225,225,225) }
                default    { $null }
            }
            if ($bg) {
                $range = $ws.Cells[$i, 1, $i, $lastCol]
                $range.Style.Fill.PatternType = 'Solid'
                $range.Style.Fill.BackgroundColor.SetColor($bg)
            }
        }
        Close-ExcelPackage $excel

        Write-AppLog -Component 'Export' -Message "XLSX export OK | rows=$($rows.Count) | path=$path"
        Set-Status "XLSX exported: $path  ($($rows.Count) rows)"
        [System.Windows.Forms.MessageBox]::Show("Exported $($rows.Count) rows.`n$path",'Export XLSX','OK','Information') | Out-Null
    } catch {
        Write-AppLog -Level ERROR -Component 'Export' -Message "XLSX export failed: $_"
        Set-Status "XLSX export error: $_"
        [System.Windows.Forms.MessageBox]::Show("Export error:`n$_",'ADDetector','OK','Error') | Out-Null
    } finally {
        $progBar.Visible = $false
    }
}

# ====================================================================
# DETAIL PANEL
# ====================================================================
function Show-Detail {
    param(
        $r,
        [bool]$ExpandOthers = $false
    )

    $script:CurrentDetailRow = $r
    $script:DetailExpandOthers = $ExpandOthers

    $rt = $txtDetail
    $rt.SuspendLayout()
    $rt.Clear()

    # --- Header panel update (username + risk badge) ---
    if (-not $r) {
        $lblDetailUser.Text = 'ACCOUNT DETAIL'
        $lblDetailUser.ForeColor = $script:C.FgPrimary
        $lblDetailMeta.Text = 'Select a user from the grid'
        $lblDetailRisk.Visible = $false
        $detailHdrAccent.BackColor = $script:C.AccentBlue
    } else {
        $lblDetailUser.Text = $r.SamAccountName
        $lblDetailUser.ForeColor = $script:C.FgPrimary
        $metaParts = @()
        if ($r.DisplayName) { $metaParts += $r.DisplayName }
        if ($r.Department)  { $metaParts += $r.Department }
        $lblDetailMeta.Text = if ($metaParts.Count -gt 0) { $metaParts -join '  -  ' } else { '(no display name)' }
        $rc = Get-RiskColor $r.RiskLevel
        $lblDetailRisk.Text = $r.RiskLevel
        $lblDetailRisk.ForeColor = $rc
        $lblDetailRisk.Visible = $true
        $detailHdrAccent.BackColor = $rc
    }

    # Monospace key column for alignment
    $monoFamily = if ([System.Drawing.FontFamily]::Families | Where-Object { $_.Name -eq 'Consolas' }) { 'Consolas' }
                  elseif ([System.Drawing.FontFamily]::Families | Where-Object { $_.Name -eq 'Cascadia Mono' }) { 'Cascadia Mono' }
                  else { 'Courier New' }

    $fontHdr   = New-Object System.Drawing.Font('Segoe UI Semibold', 9, [System.Drawing.FontStyle]::Bold)
    $fontKey   = New-Object System.Drawing.Font($monoFamily, 8.5)
    $fontVal   = New-Object System.Drawing.Font('Segoe UI', 9)
    $fontValB  = New-Object System.Drawing.Font('Segoe UI Semibold', 9, [System.Drawing.FontStyle]::Bold)
    $fontBadge = New-Object System.Drawing.Font('Segoe UI Semibold', 8, [System.Drawing.FontStyle]::Bold)
    $fontSubLbl = New-Object System.Drawing.Font('Segoe UI Semibold', 8, [System.Drawing.FontStyle]::Bold)
    $fontDivider2 = New-Object System.Drawing.Font($monoFamily, 3)

    function _W { param([string]$Text, [System.Drawing.Color]$Color, [System.Drawing.Font]$Font, [System.Drawing.Color]$Back)
        $rt.SelectionStart  = $rt.TextLength
        $rt.SelectionLength = 0
        if ($Font)  { $rt.SelectionFont  = $Font }
        if ($Color) { $rt.SelectionColor = $Color }
        if ($Back)  { $rt.SelectionBackColor = $Back } else { $rt.SelectionBackColor = $script:C.BgDetail }
        $rt.AppendText($Text)
    }
    # Section header - tam genislik renkli bant hissi
    function _Section { param([string]$Title)
        if ($rt.TextLength -gt 0) { _W "`r`n" $script:C.FgPrimary $fontVal }
        _W ("  " + $Title.ToUpper() + "  ") $script:C.AccentBlue $fontHdr $script:C.BgSection
        _W ("`r`n") $script:C.FgPrimary $fontVal
        _W "`r`n" $script:C.FgPrimary $fontDivider2
    }
    function _Row { param([string]$Key, $Val, [System.Drawing.Color]$ValColor, [bool]$Bold=$false)
        if (-not $ValColor) { $ValColor = $script:C.FgPrimary }
        $k = ("   {0,-13} " -f $Key)
        _W $k $script:C.FgSecondary $fontKey
        $vs = if ($null -eq $Val) { '-' } elseif ("$Val" -eq '') { '-' } else { "$Val" }
        $vf = if ($Bold) { $fontValB } else { $fontVal }
        _W ($vs + "`r`n") $ValColor $vf
    }
    # Badge - renkli pill hissi (arka plan bant)
    function _Badge { param([string]$Key, [string]$Label, [System.Drawing.Color]$Color)
        $k = ("   {0,-13} " -f $Key)
        _W $k $script:C.FgSecondary $fontKey
        _W (" " + $Label + " ") $Color $fontBadge $script:C.BgBadge
        _W "`r`n" $script:C.FgPrimary $fontVal
    }
    function _SubLabel { param([string]$Text)
        _W ("   " + $Text + "`r`n") $script:C.FgSecondary $fontSubLbl
    }
    function _Bullet { param([string]$Text, [System.Drawing.Color]$Color)
        if (-not $Color) { $Color = $script:C.FgPrimary }
        _W "      " $Color $fontVal
        _W "* " $Color $fontBadge
        _W ($Text + "`r`n") $Color $fontVal
    }

    if (-not $r) {
        _W "`r`n   No account selected.`r`n" $script:C.FgMuted $fontVal
        _W "   Click any row in the grid to inspect.`r`n" $script:C.FgMuted $fontVal
        $rt.ResumeLayout(); return
    }

    # ============================ IDENTITY ============================
    _Section 'Identity'
    _Row 'Username'    $r.SamAccountName $script:C.FgPrimary $true
    _Row 'Display'     $r.DisplayName
    _Row 'Mail'        $r.Mail
    _Row 'Department'  $r.Department
    _Row 'Description' $r.Description
    $ou = $r.DistinguishedName
    if ($ou -match '(OU=[^,]+(?:,OU=[^,]+)*)') { $ou = $Matches[1] }
    _Row 'OU' $ou

    # ============================ ACCESS ==============================
    _Section 'Access & Privilege'
    _Badge 'VPN'        $(if ($r.HasVPNAccess) {'YES'} else {'NO'}) $(if ($r.HasVPNAccess) {$script:C.RiskHigh} else {$script:C.FgMuted})
    $mfaColor = if ($r.HasMFA) { $script:C.RiskLow }
                elseif ($r.HasVPNAccess) { $script:C.RiskCritical }
                else { $script:C.FgMuted }
    _Badge 'MFA'        $(if ($r.HasMFA) {'YES'} else {'NO'}) $mfaColor
    _Badge 'Remote'     $(if ($r.HasRemoteAccess) {'YES'} else {'NO'}) $(if ($r.HasRemoteAccess) {$script:C.RiskHigh} else {$script:C.FgMuted})
    $vpnRiskColor = switch ($r.VPNRisk) {
        'CRITICAL' { $script:C.RiskCritical } 'HIGH' { $script:C.RiskHigh }
        'MEDIUM'   { $script:C.RiskMedium   } default { $script:C.FgMuted }
    }
    _Badge 'VPN Risk'   $r.VPNRisk $vpnRiskColor
    _Badge 'Privileged' $(if ($r.IsPrivileged) {'YES'} else {'NO'}) $(if ($r.IsPrivileged) {$script:C.RiskHigh} else {$script:C.FgMuted})
    _Row   'AdminCount' $r.AdminCount $(if ($r.AdminCount -eq 1) {$script:C.RiskCritical} else {$script:C.FgPrimary})
    _Row   'SPN Count'  $r.SPNCount

    # ============================ HYGIENE =============================
    _Section 'Account Hygiene'
    _Row 'Last Logon' $r.LastLogon $(if ($r.NeverLoggedIn) {$script:C.RiskCritical} else {$script:C.FgPrimary})
    $inactiveColor = if ($r.InactiveDays -ge 90) { $script:C.RiskCritical }
                    elseif ($r.InactiveDays -ge 60) { $script:C.RiskHigh }
                    elseif ($r.InactiveDays -ge 30) { $script:C.RiskMedium }
                    else { $script:C.FgPrimary }
    _Row 'Inactive'   ("{0} days" -f $r.InactiveDays) $inactiveColor $true
    _Badge 'Never Logon' $(if ($r.NeverLoggedIn) {'YES'} else {'NO'}) $(if ($r.NeverLoggedIn) {$script:C.RiskCritical} else {$script:C.RiskLow})
    _Row 'Pwd Set'    $r.PwdLastSet
    $pwdColor = if ($r.PwdAgeDays -ge 365) { $script:C.RiskCritical }
               elseif ($r.PwdAgeDays -ge 180) { $script:C.RiskMedium }
               else { $script:C.FgPrimary }
    _Row 'Pwd Age'    ("{0} days" -f $r.PwdAgeDays) $pwdColor
    _Row 'Created'    $r.WhenCreated
    $enColor = if ($r.Enabled) { $script:C.RiskLow } else { $script:C.FgMuted }
    _Badge 'Status'   $(if ($r.Enabled) {'ENABLED'} else {'DISABLED'}) $enColor

    # ============================ RISK ================================
    _Section 'Risk Assessment'
    $riskColor = Get-RiskColor $r.RiskLevel
    _Badge 'Level' $r.RiskLevel $riskColor
    $scoreColor = if ($r.RiskScore -ge 80) { $script:C.RiskCritical }
                 elseif ($r.RiskScore -ge 55) { $script:C.RiskHigh }
                 elseif ($r.RiskScore -ge 30) { $script:C.RiskMedium }
                 else { $script:C.RiskLow }
    _Row 'Score' ("{0} / 100" -f $r.RiskScore) $scoreColor $true
    _Row 'Account Type' $r.AccountType

    # --- Attack Surface ---
    $attackSurface = @()
    if ($r.HasVPNAccess -and -not $r.HasMFA)              { $attackSurface += @{T='VPN access WITHOUT MFA';                  C=$script:C.RiskCritical} }
    if ($r.IsPrivileged -and ($r.HasVPNAccess -or $r.HasRemoteAccess)) { $attackSurface += @{T='Privileged + Remote Access'; C=$script:C.RiskCritical} }
    if ($r.NeverLoggedIn -and $r.HasVPNAccess)            { $attackSurface += @{T='Never logged in + VPN provisioned';       C=$script:C.RiskCritical} }
    if ($r.IsPrivileged -and $r.InactiveDays -ge 30)      { $attackSurface += @{T='Dormant privileged account';              C=$script:C.RiskCritical} }
    if ($r.SPNCount -gt 0 -and $r.IsPrivileged)           { $attackSurface += @{T='SPN + Privileged (Kerberoast risk)';      C=$script:C.RiskCritical} }
    if ($r.AdminCount -eq 1 -and $r.InactiveDays -ge 30)  { $attackSurface += @{T='AdminCount=1 + dormant';                  C=$script:C.RiskHigh} }
    if ($r.PwdAgeDays -ge 365 -and $r.Enabled)            { $attackSurface += @{T=("Password age > 365 days ({0}d)" -f $r.PwdAgeDays); C=$script:C.RiskHigh} }
    if ($r.NeverLoggedIn -and $r.Enabled -and $r.IsPrivileged) { $attackSurface += @{T='Privileged + never logged in';      C=$script:C.RiskCritical} }
    if ($r.HasRemoteAccess -and -not $r.HasMFA -and $r.Enabled) { $attackSurface += @{T='Remote access without MFA';        C=$script:C.RiskHigh} }

    if ($attackSurface.Count -gt 0) {
        _W "`r`n" $script:C.FgPrimary $fontDivider2
        _SubLabel 'ATTACK SURFACE'
        foreach ($a in $attackSurface) { _Bullet $a.T $a.C }
    }

    # --- Why Flagged ---
    _W "`r`n" $script:C.FgPrimary $fontDivider2
    _SubLabel 'WHY FLAGGED'
    $reasons = @()
    if ($r.NeverLoggedIn)            { $reasons += @{T='[+50] Never logged in';                       C=$script:C.RiskCritical} }
    if ($r.InactiveDays -ge 90)      { $reasons += @{T="[+70] $($r.InactiveDays)d inactive (>=90)";   C=$script:C.RiskCritical} }
    elseif ($r.InactiveDays -ge 60)  { $reasons += @{T="[+55] $($r.InactiveDays)d inactive (>=60)";   C=$script:C.RiskHigh}     }
    elseif ($r.InactiveDays -ge 30)  { $reasons += @{T="[+40] $($r.InactiveDays)d inactive (>=30)";   C=$script:C.RiskMedium}   }
    if ($r.PwdAgeDays -ge 365)       { $reasons += @{T='[+20] Password age >= 365 days';              C=$script:C.RiskHigh}     }
    elseif ($r.PwdAgeDays -ge 180)   { $reasons += @{T='[+10] Password age >= 180 days';              C=$script:C.RiskMedium}   }
    if ($r.AdminCount -eq 1)         { $reasons += @{T='[x2.0] AdminCount = 1';                       C=$script:C.RiskCritical} }
    if ($r.IsPrivileged)             { $reasons += @{T='[x2.5] Privileged group member';              C=$script:C.RiskHigh}     }
    if ($r.HasVPNAccess)             { $reasons += @{T='[+25] Has VPN access';                        C=$script:C.RiskHigh}     }
    if ($r.HasRemoteAccess)          { $reasons += @{T='[+20] Has remote access (RDS/Citrix/RDGW)';   C=$script:C.RiskHigh}     }
    if ($r.HasVPNAccess -and -not $r.HasMFA) { $reasons += @{T='[+15] VPN WITHOUT MFA';               C=$script:C.RiskCritical} }
    if ($r.HasVPNAccess -and $r.NeverLoggedIn) { $reasons += @{T='[+20] VPN provisioned, never used'; C=$script:C.RiskCritical} }
    if ($r.IsPrivileged -and ($r.HasVPNAccess -or $r.HasRemoteAccess)) {
        $reasons += @{T='[x3.0] Privileged + Remote access (CRITICAL combo)'; C=$script:C.RiskCritical}
    }
    if (-not $r.Enabled)             { $reasons += @{T='[x0.3] Disabled (reducer)';                   C=$script:C.FgMuted}      }
    if ($r.IsServiceAccount)         { $reasons += @{T='[x0.5] Service account (reducer)';            C=$script:C.RiskSA}       }
    if ($reasons.Count -eq 0) {
        _Bullet 'No significant factors' $script:C.FgMuted
    } else {
        foreach ($x in $reasons) { _Bullet $x.T $x.C }
    }

    # ============================ GROUPS ==============================
    $vpnSet  = @{}; $mfaSet = @{}; $raSet = @{}; $privSet = @{}
    foreach ($g in $r.VPNGroups) { $vpnSet[$g.ToLower()]  = $true }
    foreach ($g in $r.MFAGroups) { $mfaSet[$g.ToLower()]  = $true }
    foreach ($g in $r.RAGroups)  { $raSet[$g.ToLower()]   = $true }
    if ($r.MatchedGroups -and $r.MatchedGroups.privileged) {
        foreach ($g in $r.MatchedGroups.privileged) { $privSet[$g.ToLower()] = $true }
    }
    $privList = @()
    if ($r.MatchedGroups -and $r.MatchedGroups.privileged) { $privList = @($r.MatchedGroups.privileged) }
    $otherList = @()
    if ($r.MemberOfFlat) {
        foreach ($g in $r.MemberOfFlat) {
            $k = $g.ToLower()
            if (-not ($vpnSet[$k] -or $mfaSet[$k] -or $raSet[$k] -or $privSet[$k])) {
                $otherList += $g
            }
        }
    }

    $hasAnyImportant = ($privList.Count + $r.VPNGroups.Count + $r.MFAGroups.Count + $r.RAGroups.Count) -gt 0
    if ($hasAnyImportant -or $otherList.Count -gt 0) {
        _Section 'Group Membership'
        if ($privList.Count -gt 0) {
            _SubLabel ("PRIVILEGED ({0})" -f $privList.Count)
            foreach ($g in $privList) { _Bullet $g $script:C.RiskCritical }
        }
        if ($r.VPNGroups.Count -gt 0) {
            _SubLabel ("VPN ({0})" -f $r.VPNGroups.Count)
            foreach ($g in $r.VPNGroups) { _Bullet $g $script:C.RiskHigh }
        }
        if ($r.MFAGroups.Count -gt 0) {
            _SubLabel ("MFA ({0})" -f $r.MFAGroups.Count)
            foreach ($g in $r.MFAGroups) { _Bullet $g $script:C.RiskLow }
        }
        if ($r.RAGroups.Count -gt 0) {
            _SubLabel ("REMOTE ACCESS ({0})" -f $r.RAGroups.Count)
            foreach ($g in $r.RAGroups) { _Bullet $g $script:C.RiskHigh }
        }
        if ($otherList.Count -gt 0) {
            if ($ExpandOthers) {
                _W ("   OTHER ({0})  " -f $otherList.Count) $script:C.FgSecondary $fontSubLbl
                _W " hide " $script:C.AccentBlue $fontBadge $script:C.BgBadge
                _W "`r`n" $script:C.FgPrimary $fontVal
                foreach ($g in $otherList) { _Bullet $g $script:C.FgPrimary }
            } else {
                _W ("   OTHER GROUPS: {0} hidden  " -f $otherList.Count) $script:C.FgSecondary $fontSubLbl
                _W " show all " $script:C.AccentBlue $fontBadge $script:C.BgBadge
                _W "`r`n" $script:C.FgPrimary $fontVal
            }
        }
    }

    $rt.SelectionStart  = 0
    $rt.SelectionLength = 0
    $rt.ScrollToCaret()
    $rt.ResumeLayout()
}

# ====================================================================

# GROUP PICKER DIALOG
# ====================================================================
function Show-GroupPickerDialog {
    $cfg = Get-DetectionConfig
    if (-not $cfg) {
        [System.Windows.Forms.MessageBox]::Show('DetectionConfig not loaded.','ADDetector','OK','Error') | Out-Null
        return
    }

    # Get DC for AD queries
    $dc = $null
    try {
        $selDomain = $cboDomain.SelectedItem
        if ($selDomain -and $script:domains) {
            $domInfo = $script:domains | Where-Object { $_.DomainName -eq $selDomain } | Select-Object -First 1
            if ($domInfo -and $domInfo.DomainControllers.Count -gt 0) {
                $dc = $domInfo.DomainControllers[0]
            }
        }
    } catch { }

    # Working copy of config (deep clone via JSON)
    $workCfg = ($cfg | ConvertTo-Json -Depth 6) | ConvertFrom-Json

    $dlg               = New-Object System.Windows.Forms.Form
    $dlg.Text          = 'Group Picker — Detection Configuration'
    $dlg.Size          = New-Object System.Drawing.Size(920, 620)
    $dlg.MinimumSize   = New-Object System.Drawing.Size(920, 620)
    $dlg.StartPosition = 'CenterParent'
    $dlg.BackColor     = [System.Drawing.Color]::FromArgb(13, 17, 30)
    $dlg.ForeColor     = [System.Drawing.Color]::FromArgb(200, 208, 224)
    $dlg.FormBorderStyle = 'Sizable'
    $dlg.Font          = $script:F.UI

    # Top accent
    $pnlTop            = New-Object System.Windows.Forms.Panel
    $pnlTop.Dock       = 'Top'
    $pnlTop.Height     = 3
    $pnlTop.BackColor  = $script:C.AccentBlue

    # Left panel - category list
    $pnlLeft           = New-Object System.Windows.Forms.Panel
    $pnlLeft.Location  = New-Object System.Drawing.Point(0, 3)
    $pnlLeft.Width     = 200
    $pnlLeft.Anchor    = 'Top,Bottom,Left'
    $pnlLeft.Height    = 577
    $pnlLeft.BackColor = [System.Drawing.Color]::FromArgb(8, 12, 22)

    $lblCatTitle       = New-Object System.Windows.Forms.Label
    $lblCatTitle.Text  = 'CATEGORIES'
    $lblCatTitle.Font  = New-Object System.Drawing.Font('Segoe UI', 7.5, [System.Drawing.FontStyle]::Bold)
    $lblCatTitle.ForeColor = [System.Drawing.Color]::FromArgb(90, 110, 160)
    $lblCatTitle.Location  = New-Object System.Drawing.Point(12, 14)
    $lblCatTitle.AutoSize  = $true

    $lstCat            = New-Object System.Windows.Forms.ListBox
    $lstCat.Location   = New-Object System.Drawing.Point(8, 36)
    $lstCat.Size       = New-Object System.Drawing.Size(184, 530)
    $lstCat.BackColor  = [System.Drawing.Color]::FromArgb(8, 12, 22)
    $lstCat.ForeColor  = [System.Drawing.Color]::FromArgb(200, 208, 224)
    $lstCat.BorderStyle = 'None'
    $lstCat.Font       = New-Object System.Drawing.Font('Segoe UI', 9.5)
    $lstCat.ItemHeight = 32

    $pnlLeft.Controls.AddRange(@($lblCatTitle, $lstCat))

    # Separator
    $pnlSep            = New-Object System.Windows.Forms.Panel
    $pnlSep.Location   = New-Object System.Drawing.Point(200, 3)
    $pnlSep.Width      = 2
    $pnlSep.Anchor     = 'Top,Bottom,Left'
    $pnlSep.Height     = 577
    $pnlSep.BackColor  = [System.Drawing.Color]::FromArgb(30, 40, 70)

    # Right panel
    $pnlRight          = New-Object System.Windows.Forms.Panel
    $pnlRight.Location = New-Object System.Drawing.Point(202, 3)
    $pnlRight.Anchor   = 'Top,Bottom,Left,Right'
    $pnlRight.Size     = New-Object System.Drawing.Size(700, 520)
    $pnlRight.BackColor = [System.Drawing.Color]::FromArgb(13, 17, 30)

    # Category label
    $lblCatName        = New-Object System.Windows.Forms.Label
    $lblCatName.Text   = 'Select a category'
    $lblCatName.Font   = New-Object System.Drawing.Font('Segoe UI', 13, [System.Drawing.FontStyle]::Bold)
    $lblCatName.ForeColor = $script:C.AccentBlue
    $lblCatName.Location  = New-Object System.Drawing.Point(16, 14)
    $lblCatName.AutoSize  = $true

    # Enabled checkbox
    $chkEnabled        = New-Object System.Windows.Forms.CheckBox
    $chkEnabled.Text   = 'Enabled'
    $chkEnabled.Font   = New-Object System.Drawing.Font('Segoe UI', 9)
    $chkEnabled.ForeColor = [System.Drawing.Color]::FromArgb(200, 208, 224)
    $chkEnabled.Location  = New-Object System.Drawing.Point(16, 48)
    $chkEnabled.AutoSize  = $true
    $chkEnabled.Enabled   = $false

    # Regex label + box
    $lblRegex          = New-Object System.Windows.Forms.Label
    $lblRegex.Text     = 'Regex Pattern (fallback if no group match):'
    $lblRegex.Font     = New-Object System.Drawing.Font('Segoe UI', 8)
    $lblRegex.ForeColor = [System.Drawing.Color]::FromArgb(90, 110, 160)
    $lblRegex.Location  = New-Object System.Drawing.Point(16, 78)
    $lblRegex.AutoSize  = $true

    $txtRegex          = New-Object System.Windows.Forms.TextBox
    $txtRegex.Location = New-Object System.Drawing.Point(16, 96)
    $txtRegex.Size     = New-Object System.Drawing.Size(660, 22)
    $txtRegex.BackColor = [System.Drawing.Color]::FromArgb(22, 28, 48)
    $txtRegex.ForeColor = [System.Drawing.Color]::FromArgb(200, 208, 224)
    $txtRegex.BorderStyle = 'FixedSingle'
    $txtRegex.Font     = New-Object System.Drawing.Font('Consolas', 8.5)
    $txtRegex.Enabled  = $false

    # Separator line
    $sep1              = New-Object System.Windows.Forms.Panel
    $sep1.Location     = New-Object System.Drawing.Point(16, 130)
    $sep1.Size         = New-Object System.Drawing.Size(660, 1)
    $sep1.BackColor    = [System.Drawing.Color]::FromArgb(30, 40, 70)

    # Left sub-panel: current groups
    $lblGroups         = New-Object System.Windows.Forms.Label
    $lblGroups.Text    = 'SELECTED GROUPS'
    $lblGroups.Font    = New-Object System.Drawing.Font('Segoe UI', 7.5, [System.Drawing.FontStyle]::Bold)
    $lblGroups.ForeColor = [System.Drawing.Color]::FromArgb(90, 110, 160)
    $lblGroups.Location  = New-Object System.Drawing.Point(16, 142)
    $lblGroups.AutoSize  = $true

    $lstGroups         = New-Object System.Windows.Forms.ListBox
    $lstGroups.Location = New-Object System.Drawing.Point(16, 162)
    $lstGroups.Size    = New-Object System.Drawing.Size(300, 260)
    $lstGroups.BackColor = [System.Drawing.Color]::FromArgb(16, 21, 38)
    $lstGroups.ForeColor = [System.Drawing.Color]::FromArgb(200, 208, 224)
    $lstGroups.BorderStyle = 'FixedSingle'
    $lstGroups.Font    = New-Object System.Drawing.Font('Consolas', 8.5)
    $lstGroups.Enabled = $false

    $btnRemoveGroup    = New-Object System.Windows.Forms.Button
    $btnRemoveGroup.Text = 'Remove Selected'
    $btnRemoveGroup.Location = New-Object System.Drawing.Point(16, 430)
    $btnRemoveGroup.Size = New-Object System.Drawing.Size(130, 26)
    $btnRemoveGroup.FlatStyle = 'Flat'
    $btnRemoveGroup.BackColor = [System.Drawing.Color]::FromArgb(80, 20, 20)
    $btnRemoveGroup.ForeColor = [System.Drawing.Color]::White
    $btnRemoveGroup.FlatAppearance.BorderSize = 0
    $btnRemoveGroup.Enabled = $false

    # Right sub-panel: AD search
    $lblSearch         = New-Object System.Windows.Forms.Label
    $lblSearch.Text    = 'SEARCH AD GROUPS'
    $lblSearch.Font    = New-Object System.Drawing.Font('Segoe UI', 7.5, [System.Drawing.FontStyle]::Bold)
    $lblSearch.ForeColor = [System.Drawing.Color]::FromArgb(90, 110, 160)
    $lblSearch.Location  = New-Object System.Drawing.Point(336, 142)
    $lblSearch.AutoSize  = $true

    $txtADSearch       = New-Object System.Windows.Forms.TextBox
    $txtADSearch.Location = New-Object System.Drawing.Point(336, 162)
    $txtADSearch.Size  = New-Object System.Drawing.Size(240, 22)
    $txtADSearch.BackColor = [System.Drawing.Color]::FromArgb(22, 28, 48)
    $txtADSearch.ForeColor = [System.Drawing.Color]::FromArgb(200, 208, 224)
    $txtADSearch.BorderStyle = 'FixedSingle'
    $txtADSearch.Enabled = $false

    $btnADSearch       = New-Object System.Windows.Forms.Button
    $btnADSearch.Text  = 'Search'
    $btnADSearch.Location = New-Object System.Drawing.Point(584, 161)
    $btnADSearch.Size  = New-Object System.Drawing.Size(70, 24)
    $btnADSearch.FlatStyle = 'Flat'
    $btnADSearch.BackColor = $script:C.AccentBlue
    $btnADSearch.ForeColor = [System.Drawing.Color]::White
    $btnADSearch.FlatAppearance.BorderSize = 0
    $btnADSearch.Enabled = $false

    $lblSearchStatus   = New-Object System.Windows.Forms.Label
    $lblSearchStatus.Text = ''
    $lblSearchStatus.Font = New-Object System.Drawing.Font('Segoe UI', 7.5)
    $lblSearchStatus.ForeColor = [System.Drawing.Color]::FromArgb(90, 110, 160)
    $lblSearchStatus.Location  = New-Object System.Drawing.Point(336, 188)
    $lblSearchStatus.Size      = New-Object System.Drawing.Size(320, 16)

    $lstADResults      = New-Object System.Windows.Forms.ListBox
    $lstADResults.Location = New-Object System.Drawing.Point(336, 206)
    $lstADResults.Size = New-Object System.Drawing.Size(320, 216)
    $lstADResults.BackColor = [System.Drawing.Color]::FromArgb(16, 21, 38)
    $lstADResults.ForeColor = [System.Drawing.Color]::FromArgb(200, 208, 224)
    $lstADResults.BorderStyle = 'FixedSingle'
    $lstADResults.Font = New-Object System.Drawing.Font('Consolas', 8.5)
    $lstADResults.Enabled = $false

    $btnAddGroup       = New-Object System.Windows.Forms.Button
    $btnAddGroup.Text  = '← Add to Selected'
    $btnAddGroup.Location = New-Object System.Drawing.Point(336, 430)
    $btnAddGroup.Size  = New-Object System.Drawing.Size(130, 26)
    $btnAddGroup.FlatStyle = 'Flat'
    $btnAddGroup.BackColor = [System.Drawing.Color]::FromArgb(20, 80, 40)
    $btnAddGroup.ForeColor = [System.Drawing.Color]::White
    $btnAddGroup.FlatAppearance.BorderSize = 0
    $btnAddGroup.Enabled = $false

    $pnlRight.Controls.AddRange(@(
        $lblCatName, $chkEnabled, $lblRegex, $txtRegex, $sep1,
        $lblGroups, $lstGroups, $btnRemoveGroup,
        $lblSearch, $txtADSearch, $btnADSearch, $lblSearchStatus, $lstADResults, $btnAddGroup
    ))

    # Bottom bar
    $pnlBottom         = New-Object System.Windows.Forms.Panel
    $pnlBottom.Dock    = 'Bottom'
    $pnlBottom.Height  = 54
    $pnlBottom.BackColor = [System.Drawing.Color]::FromArgb(8, 12, 22)

    $btnSave           = New-Object System.Windows.Forms.Button
    $btnSave.Text      = 'Save Changes'
    $btnSave.Size      = New-Object System.Drawing.Size(130, 32)
    $btnSave.Location  = New-Object System.Drawing.Point(660, 11)
    $btnSave.FlatStyle = 'Flat'
    $btnSave.BackColor = $script:C.AccentBlue
    $btnSave.ForeColor = [System.Drawing.Color]::White
    $btnSave.FlatAppearance.BorderSize = 0
    $btnSave.Font      = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)

    $btnCancel         = New-Object System.Windows.Forms.Button
    $btnCancel.Text    = 'Cancel'
    $btnCancel.Size    = New-Object System.Drawing.Size(90, 32)
    $btnCancel.Location = New-Object System.Drawing.Point(796, 11)
    $btnCancel.FlatStyle = 'Flat'
    $btnCancel.BackColor = [System.Drawing.Color]::FromArgb(40, 48, 72)
    $btnCancel.ForeColor = [System.Drawing.Color]::White
    $btnCancel.FlatAppearance.BorderSize = 0
    $btnCancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel

    $lblUnsaved        = New-Object System.Windows.Forms.Label
    $lblUnsaved.Text   = ''
    $lblUnsaved.Font   = New-Object System.Drawing.Font('Segoe UI', 8)
    $lblUnsaved.ForeColor = [System.Drawing.Color]::FromArgb(180, 140, 40)
    $lblUnsaved.Location  = New-Object System.Drawing.Point(16, 18)
    $lblUnsaved.AutoSize  = $true

    $pnlBottom.Controls.AddRange(@($btnSave, $btnCancel, $lblUnsaved))

    $dlg.Controls.AddRange(@($pnlTop, $pnlLeft, $pnlSep, $pnlRight, $pnlBottom))
    $dlg.CancelButton = $btnCancel

    # --- Populate category list from config (config-driven) ---
    $catKeys = @($workCfg.patterns.PSObject.Properties.Name)
    foreach ($key in $catKeys) {
        $cat = $workCfg.patterns.$key
        $label = if ($cat.label) { $cat.label } else { $key }
        $enabledIcon = if ($cat.isEnabled) { '[✓]' } else { '[ ]' }
        [void]$lstCat.Items.Add("$enabledIcon  $label")
    }

    # --- Load category into right panel ---
    $script:GPCurrentKey = $null
    $script:GPDirty = $false

    function Load-Category {
        param([string]$Key)
        $script:GPCurrentKey = $Key
        $cat = $workCfg.patterns.$Key
        $label = if ($cat.label) { $cat.label } else { $Key }
        $lblCatName.Text   = $label
        $chkEnabled.Checked = [bool]$cat.isEnabled
        $chkEnabled.Enabled = $true
        $txtRegex.Text     = if ($cat.regex) { $cat.regex } else { '' }
        $txtRegex.Enabled  = $true
        $lstGroups.Items.Clear()
        if ($cat.groups -and $cat.groups.Count -gt 0) {
            foreach ($g in $cat.groups) { [void]$lstGroups.Items.Add($g) }
        }
        $lstGroups.Enabled    = $true
        $btnRemoveGroup.Enabled = $true
        $txtADSearch.Enabled  = $true
        $btnADSearch.Enabled  = $true
        $lstADResults.Enabled = $true
        $btnAddGroup.Enabled  = $true
        $lstADResults.Items.Clear()
        $lblSearchStatus.Text = ''
        $txtADSearch.Text     = ''
    }

    function Refresh-CatList {
        $sel = $lstCat.SelectedIndex
        $lstCat.Items.Clear()
        foreach ($key in $catKeys) {
            $cat = $workCfg.patterns.$key
            $label = if ($cat.label) { $cat.label } else { $key }
            $enabledIcon = if ($cat.isEnabled) { '[✓]' } else { '[ ]' }
            [void]$lstCat.Items.Add("$enabledIcon  $label")
        }
        if ($sel -ge 0 -and $sel -lt $lstCat.Items.Count) { $lstCat.SelectedIndex = $sel }
    }

    function Mark-Dirty {
        $script:GPDirty = $true
        $lblUnsaved.Text = '● Unsaved changes'
    }

    # --- Events ---
    $lstCat.Add_SelectedIndexChanged({
        $idx = $lstCat.SelectedIndex
        if ($idx -ge 0 -and $idx -lt $catKeys.Count) {
            Load-Category $catKeys[$idx]
        }
    })

    $chkEnabled.Add_CheckedChanged({
        if ($script:GPCurrentKey) {
            $workCfg.patterns.($script:GPCurrentKey).isEnabled = $chkEnabled.Checked
            Refresh-CatList
            Mark-Dirty
        }
    })

    $txtRegex.Add_TextChanged({
        if ($script:GPCurrentKey) {
            $workCfg.patterns.($script:GPCurrentKey).regex = $txtRegex.Text
            Mark-Dirty
        }
    })

    $btnRemoveGroup.Add_Click({
        if ($lstGroups.SelectedItem -and $script:GPCurrentKey) {
            $grp = $lstGroups.SelectedItem
            $lstGroups.Items.Remove($grp)
            $newGroups = @($lstGroups.Items | ForEach-Object { "$_" })
            $workCfg.patterns.($script:GPCurrentKey).groups = $newGroups
            Mark-Dirty
        }
    })

    $doSearch = {
        $query = $txtADSearch.Text.Trim()
        if ($query.Length -lt 3) {
            $lblSearchStatus.Text = 'Type at least 3 characters'
            return
        }
        $lblSearchStatus.Text = 'Searching...'
        $lstADResults.Items.Clear()
        try {
            $server = $dc
            $filter = "Name -like '*$query*'"
            $params = @{ Filter = $filter; Properties = @('Name') }
            if ($server) { $params['Server'] = $server }
            $results = Get-ADGroup @params | Select-Object -ExpandProperty Name | Sort-Object | Select-Object -First 100
            $lstADResults.Items.Clear()
            if ($results -and @($results).Count -gt 0) {
                foreach ($r in @($results)) { [void]$lstADResults.Items.Add($r) }
                $lblSearchStatus.Text = "$(@($results).Count) result(s) — max 100"
            } else {
                $lblSearchStatus.Text = 'No results found'
            }
        } catch {
            $lblSearchStatus.Text = "Error: $_"
        }
    }

    $btnADSearch.Add_Click($doSearch)
    $txtADSearch.Add_KeyDown({
        if ($_.KeyCode -eq [System.Windows.Forms.Keys]::Return) { & $doSearch }
    })

    $btnAddGroup.Add_Click({
        if ($lstADResults.SelectedItem -and $script:GPCurrentKey) {
            $grp = "$($lstADResults.SelectedItem)"
            if ($lstGroups.Items -notcontains $grp) {
                [void]$lstGroups.Items.Add($grp)
                $newGroups = @($lstGroups.Items | ForEach-Object { "$_" })
                $workCfg.patterns.($script:GPCurrentKey).groups = $newGroups
                Mark-Dirty
            }
        }
    })

    $lstADResults.Add_DoubleClick({
        & $btnAddGroup.Add_Click
        $btnAddGroup.PerformClick()
    })

    $btnSave.Add_Click({
        try {
            # Write workCfg back to DetectionConfig
            foreach ($key in $catKeys) {
                $cat = $workCfg.patterns.$key
                $groups = if ($cat.groups) { @($cat.groups | ForEach-Object { "$_" }) } else { @() }
                Set-DetectionCategory -Category $key -Groups $groups -Regex $cat.regex -IsEnabled ([bool]$cat.isEnabled)
            }
            Save-DetectionConfig
            $script:GPDirty = $false
            $lblUnsaved.Text = '✓ Saved'
            Write-AppLog -Component 'GroupPicker' -Message 'Detection config saved'
            [System.Windows.Forms.MessageBox]::Show('Configuration saved successfully.','ADDetector','OK','Information') | Out-Null
            $dlg.DialogResult = [System.Windows.Forms.DialogResult]::OK
            $dlg.Close()
        } catch {
            [System.Windows.Forms.MessageBox]::Show("Save failed:`n$_",'ADDetector','OK','Error') | Out-Null
        }
    })

    $dlg.Add_FormClosing({
        if ($script:GPDirty -and $dlg.DialogResult -ne [System.Windows.Forms.DialogResult]::OK) {
            $r = [System.Windows.Forms.MessageBox]::Show(
                'You have unsaved changes. Discard?','ADDetector','YesNo','Warning')
            if ($r -ne [System.Windows.Forms.DialogResult]::Yes) { $_.Cancel = $true }
        }
    })

    [void]$dlg.ShowDialog($form)
    $dlg.Dispose()
}

# ABOUT DIALOG
# ====================================================================
function Show-AboutDialog {
    $commitHash = 'unknown'
    try {
        $gitOut = git -C $script:BasePath rev-parse --short HEAD 2>$null
        if ($gitOut -and $gitOut -notmatch 'fatal') { $commitHash = $gitOut.Trim() }
    } catch { }

    $dlg                 = New-Object System.Windows.Forms.Form
    $dlg.Text            = 'About ADDetector'
    $dlg.Size            = New-Object System.Drawing.Size(560, 460)
    $dlg.MinimumSize     = New-Object System.Drawing.Size(560, 460)
    $dlg.MaximumSize     = New-Object System.Drawing.Size(560, 460)
    $dlg.StartPosition   = 'CenterParent'
    $dlg.BackColor       = [System.Drawing.Color]::FromArgb(13, 17, 30)
    $dlg.ForeColor       = $script:C.FgPrimary
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox     = $false
    $dlg.MinimizeBox     = $false
    $dlg.Font            = $script:F.UI

    # Sol koyu panel
    $pnlLeft             = New-Object System.Windows.Forms.Panel
    $pnlLeft.Location    = New-Object System.Drawing.Point(0, 0)
    $pnlLeft.Size        = New-Object System.Drawing.Size(160, 460)
    $pnlLeft.BackColor   = [System.Drawing.Color]::FromArgb(8, 12, 22)

    # Sol accent
    $pnlLeftAccent       = New-Object System.Windows.Forms.Panel
    $pnlLeftAccent.Location = New-Object System.Drawing.Point(158, 0)
    $pnlLeftAccent.Size  = New-Object System.Drawing.Size(2, 460)
    $pnlLeftAccent.BackColor = $script:C.AccentBlue

    # Logo
    $picAboutLogo        = New-Object System.Windows.Forms.PictureBox
    $picAboutLogo.Location = New-Object System.Drawing.Point(15, 30)
    $picAboutLogo.Size   = New-Object System.Drawing.Size(130, 130)
    $picAboutLogo.SizeMode = 'Zoom'
    $picAboutLogo.BackColor = [System.Drawing.Color]::Transparent
    foreach ($lp in $script:LogoCandidates) {
        if ($lp -and (Test-Path -LiteralPath $lp)) {
            try {
                $bytes = [System.IO.File]::ReadAllBytes($lp)
                $ms    = New-Object System.IO.MemoryStream(,$bytes)
                $picAboutLogo.Image = [System.Drawing.Image]::FromStream($ms)
                break
            } catch { }
        }
    }
    $pnlLeft.Controls.Add($picAboutLogo)

    $lblLeftVer          = New-Object System.Windows.Forms.Label
    $lblLeftVer.Text     = "v1.1`nStable"
    $lblLeftVer.Font     = New-Object System.Drawing.Font('Consolas', 9, [System.Drawing.FontStyle]::Bold)
    $lblLeftVer.ForeColor = $script:C.AccentBlue
    $lblLeftVer.TextAlign = 'MiddleCenter'
    $lblLeftVer.Size     = New-Object System.Drawing.Size(160, 40)
    $lblLeftVer.Location = New-Object System.Drawing.Point(0, 390)
    $pnlLeft.Controls.Add($lblLeftVer)

    $lblLeftCopy         = New-Object System.Windows.Forms.Label
    $lblLeftCopy.Text    = ([char]0x00A9) + " 2026`nEren Arslan"
    $lblLeftCopy.Font    = New-Object System.Drawing.Font('Segoe UI', 7)
    $lblLeftCopy.ForeColor = [System.Drawing.Color]::FromArgb(80, 90, 120)
    $lblLeftCopy.TextAlign = 'MiddleCenter'
    $lblLeftCopy.Size    = New-Object System.Drawing.Size(160, 30)
    $lblLeftCopy.Location = New-Object System.Drawing.Point(0, 426)
    $pnlLeft.Controls.Add($lblLeftCopy)

    # Sag taraf
    $pnlTopAccent        = New-Object System.Windows.Forms.Panel
    $pnlTopAccent.Location = New-Object System.Drawing.Point(160, 0)
    $pnlTopAccent.Size   = New-Object System.Drawing.Size(400, 3)
    $pnlTopAccent.BackColor = $script:C.AccentBlue

    $lblName             = New-Object System.Windows.Forms.Label
    $lblName.Text        = 'ADDetector'
    $lblName.Font        = New-Object System.Drawing.Font('Consolas', 26, [System.Drawing.FontStyle]::Bold)
    $lblName.ForeColor   = $script:C.FgPrimary
    $lblName.AutoSize    = $true
    $lblName.Location    = New-Object System.Drawing.Point(178, 14)

    $lblTagline          = New-Object System.Windows.Forms.Label
    $lblTagline.Text     = 'Active Directory Security Assessment && Exposure Visibility'
    $lblTagline.Font     = New-Object System.Drawing.Font('Segoe UI', 8, [System.Drawing.FontStyle]::Italic)
    $lblTagline.ForeColor = [System.Drawing.Color]::FromArgb(100, 140, 200)
    $lblTagline.AutoSize = $true
    $lblTagline.Location = New-Object System.Drawing.Point(180, 64)

    $sep = New-Object System.Windows.Forms.Panel
    $sep.Location  = New-Object System.Drawing.Point(178, 86)
    $sep.Size      = New-Object System.Drawing.Size(362, 1)
    $sep.BackColor = [System.Drawing.Color]::FromArgb(40, 50, 80)

    $meta = @(
        @{ L = 'Author';    V = 'Eren Arslan';                        C = $script:C.FgPrimary   }
        @{ L = 'Commit';    V = $commitHash;                          C = [System.Drawing.Color]::FromArgb(180,180,100) }
        @{ L = 'Platform';  V = 'PowerShell 5.1 + RSAT (Windows)';   C = $script:C.FgSecondary }
        @{ L = 'License';   V = 'Proprietary';                       C = $script:C.FgSecondary }
        @{ L = 'GitHub';    V = 'github.com/ErenArslann/ADDetector';  C = $script:C.AccentBlue  }

    )

    $y = 98
    foreach ($m in $meta) {
        $lbl = New-Object System.Windows.Forms.Label
        $lbl.Text      = $m.L
        $lbl.Font      = New-Object System.Drawing.Font('Segoe UI', 9, [System.Drawing.FontStyle]::Bold)
        $lbl.ForeColor = [System.Drawing.Color]::FromArgb(90, 110, 160)
        $lbl.Size      = New-Object System.Drawing.Size(70, 22)
        $lbl.Location  = New-Object System.Drawing.Point(178, $y)
        $dlg.Controls.Add($lbl)
        $val = New-Object System.Windows.Forms.Label
        $val.Text      = $m.V
        $val.Font      = New-Object System.Drawing.Font('Consolas', 9)
        $val.ForeColor = $m.C
        $val.AutoSize  = $true
        $val.Location  = New-Object System.Drawing.Point(258, $y)
        $dlg.Controls.Add($val)
        $y += 26
    }

    $sep2 = New-Object System.Windows.Forms.Panel
    $sep2.Location  = New-Object System.Drawing.Point(178, 240)
    $sep2.Size      = New-Object System.Drawing.Size(362, 1)
    $sep2.BackColor = [System.Drawing.Color]::FromArgb(40, 50, 80)

    $pnlBadge            = New-Object System.Windows.Forms.Panel
    $pnlBadge.Location   = New-Object System.Drawing.Point(178, 252)
    $pnlBadge.Size       = New-Object System.Drawing.Size(362, 26)
    $pnlBadge.BackColor  = [System.Drawing.Color]::FromArgb(20, 60, 30)
    $lblBadge            = New-Object System.Windows.Forms.Label
    $lblBadge.Text       = '  READ-ONLY  |  Does not modify or delete any AD objects'
    $lblBadge.Font       = New-Object System.Drawing.Font('Consolas', 7.5)
    $lblBadge.ForeColor  = [System.Drawing.Color]::FromArgb(80, 200, 100)
    $lblBadge.Dock       = 'Fill'
    $lblBadge.TextAlign  = 'MiddleLeft'
    $pnlBadge.Controls.Add($lblBadge)

    $caps = @('AD Dormant Account Detection','Privileged Account Exposure','VPN / MFA Coverage Analysis','Risk Scoring & Attack Surface Map')
    $cy = 292
    foreach ($cap in $caps) {
        $lc = New-Object System.Windows.Forms.Label
        $lc.Text      = '  > ' + $cap
        $lc.Font      = New-Object System.Drawing.Font('Consolas', 7.5)
        $lc.ForeColor = [System.Drawing.Color]::FromArgb(70, 100, 160)
        $lc.AutoSize  = $true
        $lc.Location  = New-Object System.Drawing.Point(178, $cy)
        $dlg.Controls.Add($lc)
        $cy += 18
    }

    # LinkedIn clickable link
    $lblLinkedIn         = New-Object System.Windows.Forms.Label
    $lblLinkedIn.Text    = 'LinkedIn  ↗'
    $lblLinkedIn.Font    = New-Object System.Drawing.Font('Segoe UI', 8.5, [System.Drawing.FontStyle]::Underline)
    $lblLinkedIn.ForeColor = [System.Drawing.Color]::FromArgb(0, 160, 220)
    $lblLinkedIn.AutoSize  = $true
    $lblLinkedIn.Location  = New-Object System.Drawing.Point(178, ($cy + 4))
    $lblLinkedIn.Cursor    = [System.Windows.Forms.Cursors]::Hand
    $lblLinkedIn.Add_Click({ Start-Process 'https://www.linkedin.com/in/erenarslan0/' })
    $dlg.Controls.Add($lblLinkedIn)

    $btnClose            = New-Object System.Windows.Forms.Button
    $btnClose.Text       = 'Close'
    $btnClose.Size       = New-Object System.Drawing.Size(90, 28)
    $btnClose.Location   = New-Object System.Drawing.Point(450, 412)
    $btnClose.FlatStyle  = 'Flat'
    $btnClose.BackColor  = [System.Drawing.Color]::FromArgb(30, 40, 70)
    $btnClose.ForeColor  = $script:C.FgPrimary
    $btnClose.FlatAppearance.BorderColor = $script:C.AccentBlue
    $btnClose.FlatAppearance.BorderSize  = 1
    $btnClose.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $dlg.Controls.AddRange(@($pnlLeft,$pnlLeftAccent,$pnlTopAccent,$lblName,$lblTagline,$sep,$sep2,$pnlBadge,$btnClose))
    $dlg.AcceptButton = $btnClose
    [void]$dlg.ShowDialog($form)
    $dlg.Dispose()
}

# ====================================================================
# EVENTS
# ====================================================================
$btnSettings.Add_Click({ Show-GroupPickerDialog })
$btnAbout.Add_Click({ Show-AboutDialog })

$btnDiscover.Add_Click({
    $btnDiscover.Enabled = $false
    $btnScan.Enabled     = $false
    $cboDomain.Items.Clear()
    Set-Status 'Discovering domains...' $true
    Write-AppLog -Component 'Discover' -Message "Discover started | manual='$($txtManual.Text)'"
    try {
        $manual = $txtManual.Text.Trim()
        $script:domains = if ($manual) { @(Get-ManualDomainInfo -DomainFQDN $manual) }
                          else          { @(Invoke-DomainDiscovery) }
        # Her zaman array olsun ki .Count guvenilir calissin
        $script:domains = @($script:domains)
        if (-not $script:domains -or $script:domains.Count -eq 0) {
            Set-Status 'No domains found. Enter manually.'
            Write-AppLog -Level WARN -Component 'Discover' -Message 'No domains returned'
            return
        }
        foreach ($d in $script:domains) { [void]$cboDomain.Items.Add($d.DomainName) }
        $cboDomain.SelectedIndex = 0
        $btnScan.Enabled = $true
        Set-Status "$($script:domains.Count) domain(s) loaded."
        Write-AppLog -Component 'Discover' -Message "Discover OK | count=$($script:domains.Count)"
    } catch {
        $errLine = if ($_.InvocationInfo) { $_.InvocationInfo.ScriptLineNumber } else { '?' }
        $errCmd  = if ($_.InvocationInfo) { $_.InvocationInfo.MyCommand } else { '?' }
        $full = ($_ | Out-String) + "`n" + ($_.ScriptStackTrace) + "`n" + ($_.InvocationInfo.PositionMessage)
        Write-AppLog -Level ERROR -Component 'Discover' -Message "FAILED at line $errLine ($errCmd): $full"
        Set-Status "Discover error (see log): $_"
        [System.Windows.Forms.MessageBox]::Show(
            "Discover failed:`n`n$_`n`nDetails written to:`n$script:LogFile",
            'ADDetector','OK','Error') | Out-Null
    } finally {
        $btnDiscover.Enabled = $true
        $progBar.Visible     = $false
    }
})

$btnScan.Add_Click({
    $sel = $cboDomain.SelectedItem
    if (-not $sel) { Set-Status 'Select a domain.'; return }
    $domObj = $script:domains | Where-Object { $_.DomainName -eq $sel } | Select-Object -First 1

    # Parse threshold (0=all, empty=30 default, 1-3650=days)
    $thrNum = Get-ThresholdDays $cboThreshold.Text
    if ($null -eq $thrNum) {
        [System.Windows.Forms.MessageBox]::Show(
            "Invalid threshold value: '$($cboThreshold.Text)'`n`nAllowed:`n  0 or 'all'  = no inactivity filter (all users)`n  1-3650      = days inactive",
            'ADDetector','OK','Warning') | Out-Null
        $cboThreshold.Focus(); return
    }
    $script:InactiveThreshold = $thrNum
    $thrLabel = if ($thrNum -eq 0) { 'ALL users (no filter)' } else { "inactive >= $thrNum days" }
    Write-AppLog -Component 'Scan' -Message "Scan requested | domain=$sel | mode=$thrLabel"

    $grid.Rows.Clear()
    # Deterministik startup: yeni scan'de eski sort state'i temizle.
    try {
        foreach ($col in $grid.Columns) { $col.HeaderCell.SortGlyphDirection = 'None' }
    } catch { }
    $lblEmpty.Visible    = $false
    $script:allRows      = @()
    $script:filteredRows = @()
    Reset-Cards
    $txtDetail.Text      = 'Scanning...'
    $btnScan.Enabled     = $false
    $btnDiscover.Enabled = $false
    Set-Status "[$sel] Scanning ($thrLabel)..." $true

    try {
        if (-not (Get-Command Get-ADUser -ErrorAction SilentlyContinue)) {
            [System.Windows.Forms.MessageBox]::Show('RSAT / ActiveDirectory module not found.','ADDetector','OK','Warning')
            Set-Status 'RSAT missing!'; return
        }

        Initialize-Columns

        $server = if ($domObj -and $domObj.PDCEmulator) { $domObj.PDCEmulator } else { $sel }
        Set-Status "[$sel] Querying AD ($server)..." $true

        $props = @('SamAccountName','DisplayName','Enabled','LastLogonDate',
                   'PasswordLastSet','WhenCreated','Department','Mail',
                   'Description','DistinguishedName','AdminCount',
                   'ServicePrincipalName','MemberOf')

        $allUsers = Get-ADUser -Server $server -Filter * -Properties $props -ErrorAction Stop
        $total    = @($allUsers).Count
        Set-Status "[$sel] $total users - computing risk..." $true

        $now            = Get-Date
        $cutoffActive   = $now.AddDays(-$thrNum)
        $cutoffDisabled = $now.AddDays(-([Math]::Max($thrNum, 90)))

        $script:allRows = @(
            $allUsers | Where-Object {
                if ($thrNum -eq 0) { return $true }   # 0 = no inactivity filter
                ($_.Enabled -and ($_.LastLogonDate -eq $null -or $_.LastLogonDate -lt $cutoffActive)) -or
                (-not $_.Enabled -and ($_.LastLogonDate -eq $null -or $_.LastLogonDate -lt $cutoffDisabled))
            } | ForEach-Object { New-UserRow -u $_ -Now $now }
        )

        Set-Card 'Total'      $total
        $rows = $script:allRows
        foreach ($k in @('Inactive','Critical','Privileged','NeverLogon','SvcAcc','Disabled','RemoteAcc','DormantVPN')) {
            $pred = $script:CardPredicates[$k]
            $cnt  = @($rows | Where-Object { & $pred $_ }).Count
            Set-Card $k $cnt
        }

        # Deterministik render: card filter state'i temizle, filtreleri default'a al.
        $script:ActiveCardFilter = $null
        $script:TypeFilter = @()
        $script:DeptFilter = @()
        Update-MultiBtn $script:TypeDD 'Type'
        Update-MultiBtn $script:DeptDD 'Dept'
        # Dept dropdown'u scan sonrasi doldur
        Populate-DeptDropdown
        # CheckedListBox secimleri temizle
        for ($i = 0; $i -lt $script:TypeDD.Clb.Items.Count; $i++) { $script:TypeDD.Clb.SetItemChecked($i, $false) }
        for ($i = 0; $i -lt $script:DeptDD.Clb.Items.Count; $i++) { $script:DeptDD.Clb.SetItemChecked($i, $false) }
        try { Update-CardHighlight } catch { }

        $script:filteredRows = $script:allRows
        Apply-Filters
        Show-Detail $null
        $btnCSV.Enabled  = $true
        $btnXLSX.Enabled = $true
        $btnHTML.Enabled = $true
        Set-Status "[$sel]  Stale: $($script:allRows.Count)  |  Critical: $($script:metricLabels['Critical'].Text)  |  Privileged: $($script:metricLabels['Privileged'].Text)  |  Never Logon: $($script:metricLabels['NeverLogon'].Text)  |  Total: $total"
        Write-AppLog -Component 'Scan' -Message "Scan complete | domain=$sel | total=$total | stale=$($script:allRows.Count)"
        $btnScan.BackColor = [System.Drawing.Color]::FromArgb(0, 155, 70)  # green = fresh
        $btnScan.Text      = 'SCAN'
        $statusLabel.ForeColor = $script:C.FgSecondary

        # Force tek seferlik repaint - UI/backend state sync garantisi
        try {
            $grid.Refresh()
            $form.Refresh()
            [System.Windows.Forms.Application]::DoEvents()
        } catch { }

    } catch {
        Write-AppLog -Level ERROR -Component 'Scan' -Message ("Scan failed: " + ($_ | Out-String))
        Set-Status "Scan error: $_"
        [System.Windows.Forms.MessageBox]::Show("Error:`n$_",'ADDetector','OK','Error') | Out-Null
    } finally {
        $btnScan.Enabled     = $true
        $btnDiscover.Enabled = $true
        $progBar.Visible     = $false
    }
})

$grid.Add_SelectionChanged({
    if ($grid.SelectedRows.Count -gt 0 -and $grid.SelectedRows[0].Tag) {
        Show-Detail $grid.SelectedRows[0].Tag
    }
})

# Fix: tek sonucta tiklama sorunu — CellClick her zaman tetiklenir,
# SelectionChanged bazen tek-satirda calismiyor
$grid.Add_CellClick({
    param($sender, $e)
    if ($e.RowIndex -ge 0 -and $e.RowIndex -lt $grid.Rows.Count) {
        $row = $grid.Rows[$e.RowIndex]
        if ($row.Tag) { Show-Detail $row.Tag }
    }
})

# Update-Grid'den sonra tek satir varsa otomatik sec
function Select-FirstRowIfSingle {
    if ($grid.Rows.Count -eq 1) {
        try {
            $grid.ClearSelection()
            $grid.Rows[0].Selected = $true
            $grid.CurrentCell = $grid.Rows[0].Cells[0]
            if ($grid.Rows[0].Tag) { Show-Detail $grid.Rows[0].Tag }
        } catch { }
    }
}

# Custom sort: RiskLevel kolonu Get-RiskOrder ile siralanir (alfabetik DEGIL).
# Global sira: CRITICAL > HIGH > MEDIUM > LOW > SVC-ACCT > DISABLED
$grid.Add_SortCompare({
    param($sender, $e)
    try {
        if ($e.Column.Name -eq 'RiskLevel') {
            $o1 = Get-RiskOrder ([string]$e.CellValue1)
            $o2 = Get-RiskOrder ([string]$e.CellValue2)
            $e.SortResult = $o1.CompareTo($o2)
            # Esitse RiskScore'a gore (yuksek once) tie-break
            if ($e.SortResult -eq 0) {
                $s1 = [int]($sender.Rows[$e.RowIndex1].Cells['RiskScore'].Value)
                $s2 = [int]($sender.Rows[$e.RowIndex2].Cells['RiskScore'].Value)
                $e.SortResult = $s2.CompareTo($s1)
            }
            $e.Handled = $true
        } elseif ($e.Column.Name -in @('RiskScore','InactiveDays','PwdAgeDays','AdminCount')) {
            # Numerik kolonlar string degil sayi olarak siralansin
            $v1 = 0; $v2 = 0
            [void][int]::TryParse([string]$e.CellValue1, [ref]$v1)
            [void][int]::TryParse([string]$e.CellValue2, [ref]$v2)
            $e.SortResult = $v1.CompareTo($v2)
            $e.Handled = $true
        }
    } catch {
        $e.Handled = $false
    }
})

# Detail panel: click on "show all" / "hide" to toggle Other Groups expansion
$txtDetail.Add_MouseDown({
    param($sender, $e)
    try {
        if ($e.Button -ne [System.Windows.Forms.MouseButtons]::Left) { return }
        if (-not $script:CurrentDetailRow) { return }
        $idx = $sender.GetCharIndexFromPosition($e.Location)
        if ($idx -lt 0) { return }
        $allText = $sender.Text
        if (-not $allText) { return }

        $tolerance = 30
        $found = $false

        # "show all" - sadece collapsed durumda anlamli
        if (-not $script:DetailExpandOthers) {
            $pos = $allText.IndexOf('show all', [System.StringComparison]::OrdinalIgnoreCase)
            while ($pos -ge 0 -and -not $found) {
                if ([Math]::Abs($pos - $idx) -le $tolerance -or ($idx -ge $pos -and $idx -le $pos + 10)) {
                    Show-Detail $script:CurrentDetailRow -ExpandOthers $true
                    $found = $true
                    break
                }
                $pos = $allText.IndexOf('show all', $pos + 1, [System.StringComparison]::OrdinalIgnoreCase)
            }
        }

        # "hide" - sadece expanded durumda anlamli (OTHER (N) hide formatinda)
        if (-not $found -and $script:DetailExpandOthers) {
            # "OTHER" satirindaki "hide" - "hidden" ile karismasin diye exact " hide " ara
            $pos = $allText.IndexOf(' hide ', [System.StringComparison]::OrdinalIgnoreCase)
            while ($pos -ge 0 -and -not $found) {
                if ([Math]::Abs($pos - $idx) -le $tolerance -or ($idx -ge $pos -and $idx -le $pos + 6)) {
                    Show-Detail $script:CurrentDetailRow -ExpandOthers $false
                    $found = $true
                    break
                }
                $pos = $allText.IndexOf(' hide ', $pos + 1, [System.StringComparison]::OrdinalIgnoreCase)
            }
        }
    } catch {
        Write-AppLog -Level WARN -Component 'DetailClick' -Message "Click handler error: $_"
    }
})

# Hand cursor when hovering over "show all" / "hide"
$txtDetail.Add_MouseMove({
    param($sender, $e)
    try {
        $idx = $sender.GetCharIndexFromPosition($e.Location)
        if ($idx -lt 0) { $sender.Cursor = [System.Windows.Forms.Cursors]::IBeam; return }
        $allText = $sender.Text
        if (-not $allText) { return }
        $needle = if ($script:DetailExpandOthers) { ' hide ' } else { 'show all' }
        $pos = $allText.IndexOf($needle, [System.StringComparison]::OrdinalIgnoreCase)
        $isOnLink = $false
        while ($pos -ge 0) {
            if ($idx -ge $pos -and $idx -le ($pos + $needle.Length)) { $isOnLink = $true; break }
            $pos = $allText.IndexOf($needle, $pos + 1, [System.StringComparison]::OrdinalIgnoreCase)
        }
        $sender.Cursor = if ($isOnLink) { [System.Windows.Forms.Cursors]::Hand } else { [System.Windows.Forms.Cursors]::IBeam }
    } catch { }
})

$btnDetail.Add_Click({
    try {
        $mainSplit.Panel2Collapsed = -not $mainSplit.Panel2Collapsed
        $btnDetail.Text = if ($mainSplit.Panel2Collapsed) { 'Details >' } else { 'Details <' }
        if (-not $mainSplit.Panel2Collapsed) { Set-SafeSplitter }
    } catch { }
})

$cboRisk.Add_SelectedIndexChanged({
    if ($script:allRows.Count) {
        if ($script:ActiveCardFilter) { $script:ActiveCardFilter = $null; Update-CardHighlight }
        Apply-Filters
    }
})

# Threshold degisince scan butonu flash + kalici kirmizi + belirgin status
$script:ThresholdFlashTimer = $null
function Start-ScanFlash {
    if (-not $script:allRows -or $script:allRows.Count -eq 0) { return }
    $btnScan.BackColor = [System.Drawing.Color]::FromArgb(220, 50, 50)
    $btnScan.Text      = '! SCAN !'
    $statusLabel.ForeColor = [System.Drawing.Color]::FromArgb(255, 180, 0)
    Set-Status "⚠  Threshold changed — press SCAN to refresh results."
    # Flash: kirmizi <-> amber 3 kez
    if ($script:ThresholdFlashTimer) { try { $script:ThresholdFlashTimer.Stop(); $script:ThresholdFlashTimer.Dispose() } catch { } }
    $script:FlashCount = 0
    $script:ThresholdFlashTimer = New-Object System.Windows.Forms.Timer
    $script:ThresholdFlashTimer.Interval = 300
    $script:ThresholdFlashTimer.Add_Tick({
        $script:FlashCount++
        if ($script:FlashCount % 2 -eq 0) {
            $btnScan.BackColor = [System.Drawing.Color]::FromArgb(220, 50, 50)
        } else {
            $btnScan.BackColor = [System.Drawing.Color]::FromArgb(200, 140, 0)
        }
        if ($script:FlashCount -ge 6) {
            $script:ThresholdFlashTimer.Stop()
            $btnScan.BackColor = [System.Drawing.Color]::FromArgb(220, 50, 50)  # kirmizi kal
        }
    })
    $script:ThresholdFlashTimer.Start()
}

$cboThreshold.Add_SelectedIndexChanged({ Start-ScanFlash })
$cboThreshold.Add_TextChanged({          Start-ScanFlash })
$chkPrivOnly.Add_CheckedChanged({  if ($script:allRows.Count) { Apply-Filters } })
$chkNeverOnly.Add_CheckedChanged({ if ($script:allRows.Count) { Apply-Filters } })
$chkHideSA.Add_CheckedChanged({    if ($script:allRows.Count) { Apply-Filters } })
$chkHideDis.Add_CheckedChanged({   if ($script:allRows.Count) { Apply-Filters } })
function Set-TriState {
    param($btn, [string]$VarName, [string]$Label)
    $states = @('All','Yes','No')
    $colors = @{ 'All'=[System.Drawing.Color]::FromArgb(60,65,90); 'Yes'=[System.Drawing.Color]::FromArgb(20,80,40); 'No'=[System.Drawing.Color]::FromArgb(80,20,20) }
    $cur = $btn.Tag
    $next = $states[($states.IndexOf($cur) + 1) % 3]
    $btn.Tag = $next
    $btn.Text = "${Label}: $next"
    $btn.BackColor = $colors[$next]
    Set-Variable -Name $VarName -Value $next -Scope Script
    if ($script:allRows.Count) { Apply-Filters }
}

$btnVPNFilter.Add_Click({    Set-TriState $btnVPNFilter    'VPNFilter'    'VPN'    })
$btnMFAFilter.Add_Click({    Set-TriState $btnMFAFilter    'MFAFilter'    'MFA'    })
$btnRemoteFilter.Add_Click({ Set-TriState $btnRemoteFilter 'RemoteFilter' 'Remote' })
$txtSearch.Add_TextChanged({       if ($script:allRows.Count) { Apply-Filters } })

$btnClear.Add_Click({
    $grid.Rows.Clear()
    $lblEmpty.Visible    = $true
    $script:allRows      = @()
    $script:filteredRows = @()
    $script:domains      = @()
    $cboDomain.Items.Clear()
    $btnScan.Enabled     = $false
    $btnCSV.Enabled      = $false
    $btnXLSX.Enabled     = $false
    $btnHTML.Enabled     = $false
    Show-Detail $null
    Reset-Cards
    Set-Status 'Cleared.'
})

$btnCSV.Add_Click({  Export-CSV-View  })
$btnXLSX.Add_Click({ Export-XLSX-View })
$btnHTML.Add_Click({  Export-HTML-Report })

# ====================================================================
# LAUNCH
# ====================================================================
# Splitter management: runtime calculation, debounced, exception-proof.
$script:SplitterTimer = New-Object System.Windows.Forms.Timer
$script:SplitterTimer.Interval = 80
$script:SplitterTimer.Add_Tick({
    $script:SplitterTimer.Stop()
    Set-SafeSplitter
})

function Set-SafeSplitter {
    try {
        if (-not $mainSplit -or $mainSplit.IsDisposed) { return }
        if ($mainSplit.Panel2Collapsed) { return }   # nothing to size when hidden
        $w = $mainSplit.ClientSize.Width
        if ($w -lt 120) { return }   # too small to do anything safely

        # Detail panel CAP: max 320px, min 220px.
        # Grid (Panel1) gets the rest -> tum kolonlar gorunur kalsin, horizontal scroll yok.
        $detailMax = 320
        $detailMin = 220
        $gridMin   = 560   # 9 kolon icin guvenli minimum

        # Panel2 (detail) target = min(320, %22 of width)
        $targetDetail = [int]([Math]::Min($detailMax, [Math]::Floor($w * 0.22)))
        if ($targetDetail -lt $detailMin) { $targetDetail = $detailMin }

        # Eger ekran cok darsa detail kucult ama grid'i koru
        if (($w - $targetDetail) -lt $gridMin) {
            $targetDetail = $w - $gridMin
            if ($targetDetail -lt 180) { $targetDetail = 180 }
        }

        # MinSize'lari guvenli sirayla ayarla
        $safeMin1 = [Math]::Min(500, $w - $targetDetail - 10)
        if ($safeMin1 -lt 50) { $safeMin1 = 50 }
        $safeMin2 = [Math]::Min(180, $targetDetail)
        if ($safeMin2 -lt 50) { $safeMin2 = 50 }

        try { $mainSplit.Panel1MinSize = $safeMin1 } catch { }
        try { $mainSplit.Panel2MinSize = $safeMin2 } catch { }

        # SplitterDistance = Panel1 (grid) genisligi
        $desired = $w - $targetDetail
        $maxAllowed = $w - $mainSplit.Panel2MinSize - 1
        if ($desired -lt $mainSplit.Panel1MinSize) { $desired = $mainSplit.Panel1MinSize }
        if ($desired -gt $maxAllowed)              { $desired = $maxAllowed }

        try { $mainSplit.SplitterDistance = $desired } catch { }
    } catch {
        # never crash the UI thread
    }
}

# Debounced resize: many Resize events per drag, run once after settle
$btnUpdateNotify.Add_Click({
    Write-AppLog -Component 'Update' -Message 'Update clicked'
    if (-not $script:LatestZipUrl) {
        Start-Process 'https://github.com/ErenArslann/ADDetector/releases/latest'
        return
    }
    try {
        $installDir = $script:BasePath
        $zipName    = 'ADDetector-' + $script:LatestVersion + '.zip'
        $savePath   = Join-Path $installDir $zipName
        Set-Status 'Guncelleme indiriliyor...' $true
        $wc2 = New-Object System.Net.WebClient
        $wc2.Headers.Add('User-Agent', 'ADDetector-Updater')
        $wc2.DownloadFile($script:LatestZipUrl, $savePath)
        $wc2.Dispose()
        Write-AppLog -Component 'Update' -Message ('Downloaded: ' + $savePath)
        $updaterExe = Join-Path $installDir 'Updater.exe'
        $exePath    = Join-Path $installDir 'ADDetector.exe'
        if (Test-Path $updaterExe) {
            $args = '-ZipPath "' + $savePath + '" -InstallDir "' + $installDir + '" -ExePath "' + $exePath + '"'
            Start-Process $updaterExe $args -WindowStyle Hidden
            $form.Close()
        } else {
            [System.Windows.Forms.MessageBox]::Show('Guncelleme indirildi. Updater.exe bulunamadi - lutfen ZIP dosyasini klasore manuel cikartin.','ADDetector','OK','Warning') | Out-Null
            Start-Process 'explorer.exe' $installDir
            $form.Close()
        }
    } catch {
        Write-AppLog -Level ERROR -Component 'Update' -Message ('Download failed: ' + $_)
        Set-Status 'Indirme basarisiz'
        Start-Process 'https://github.com/ErenArslann/ADDetector/releases/latest'
    }
})

$form.Add_Load({  Set-SafeSplitter })
$form.Add_Shown({
    Set-SafeSplitter
    if ($script:AutoStartDone) { return }
    $script:AutoStartDone = $true
    if ($script:UpdateAvailable -and $script:LatestVersion) {
        $btnUpdateNotify.Text    = [char]0x2b06 + '  ' + $script:LatestVersion + ' mevcut  -  Guncellemek icin tiklayin'
        $btnUpdateNotify.Visible = $true
    }

    try {
        Write-AppLog -Component 'AutoStart' -Message 'Auto-discover triggered'
        $btnDiscover.PerformClick()
    } catch {
        Write-AppLog -Level WARN -Component 'AutoStart' -Message "Auto-discover failed: $($_ | Out-String)"
    }

    # Timer-based deferred auto-scan: Discover tamamlandiktan sonra
    # message pump'un settle etmesini bekle (100ms), sonra scan karar ver.
    # PerformClick+DoEvents race'ini ortadan kaldirir.
    $script:AutoScanTimer = New-Object System.Windows.Forms.Timer
    $script:AutoScanTimer.Interval = 120
    $script:AutoScanTimer.Add_Tick({
        $script:AutoScanTimer.Stop()
        $script:AutoScanTimer.Dispose()
        try {
            if ($script:domains -and @($script:domains).Count -ge 1) {
                # Her zaman ilk domain'i sec ve auto-scan yap
                # DomainDiscovery current domain'i zaten ilk siraya koyuyor
                if ($cboDomain.Items.Count -gt 0) {
                    $cboDomain.SelectedIndex = 0
                }
                Write-AppLog -Component 'AutoStart' -Message "Auto-scan -> $($cboDomain.SelectedItem)"
                Set-Status "Auto-scanning: $($cboDomain.SelectedItem)..." $true
                $btnScan.PerformClick()
            }
        } catch {
            Write-AppLog -Level WARN -Component 'AutoStart' -Message "Auto-scan failed: $($_ | Out-String)"
        }
    })
    $script:AutoScanTimer.Start()
})
$form.Add_Resize({
    try {
        $script:SplitterTimer.Stop()
        $script:SplitterTimer.Start()
    } catch { }
})

[void]$form.ShowDialog()

