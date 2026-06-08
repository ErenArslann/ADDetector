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
$form.Text          = 'ADDetector v1.0'
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

# Window/taskbar icon - .ico veya PNG'den runtime convert
$script:IconCandidates = @(
    (Join-Path $script:BasePath 'ADDetector.ico'),
    (Join-Path $script:BasePath 'MA_Cyber_Logo.ico'),
    (Join-Path $script:BasePath 'assets\ADDetector.ico'),
    (Join-Path (Split-Path $script:BasePath -Parent) 'ADDetector.ico'),
    (Join-Path (Get-Location).Path 'ADDetector.ico'),
    'C:\ADDetector\ADDetector.ico',
    'C:\ADDetector\MA_Cyber_Logo.ico'
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
# PNG fallback -> runtime ICO synthesis
if (-not $iconLoaded) {
    $pngCandidates = @(
        (Join-Path $script:BasePath 'MA_Cyber_Logo.png'),
        (Join-Path (Split-Path $script:BasePath -Parent) 'MA_Cyber_Logo.png'),
        'C:\ADDetector\MA_Cyber_Logo.png',
        'C:\ADDetector\dist\ADDetector\MA_Cyber_Logo.png'
    )
    $pngForIcon = $pngCandidates | Where-Object { $_ -and (Test-Path -LiteralPath $_) } | Select-Object -First 1
    if ($pngForIcon) {
        try {
            $bytes = [System.IO.File]::ReadAllBytes($pngForIcon)
            $ms = New-Object System.IO.MemoryStream(,$bytes)
            $bmp = [System.Drawing.Bitmap]::FromStream($ms)
            $iconBmp = New-Object System.Drawing.Bitmap($bmp, (New-Object System.Drawing.Size(32,32)))
            $hIcon = $iconBmp.GetHicon()
            $form.Icon = [System.Drawing.Icon]::FromHandle($hIcon)
            Write-AppLog -Component 'Branding' -Message "Icon synthesized from PNG: $pngForIcon"
        } catch {
            Write-AppLog -Level WARN -Component 'Branding' -Message "PNG->Icon failed: $_"
        }
    }
}

# ?? TOP BAR ??????????????????????????????????????????????????????????????????
$topBar            = New-Object System.Windows.Forms.Panel
$topBar.Dock       = 'Top'
$topBar.Height     = 52
$topBar.BackColor  = $C.BgMid
$topBar.AutoScroll = $true   # narrow screens: horizontal scroll

$lblTitle         = New-Object System.Windows.Forms.Label
$lblTitle.Text    = 'ADDetector v1.0'
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
$script:LogoCandidates = @(
    (Join-Path $script:BasePath 'MA_Cyber_Logo.png'),
    (Join-Path $script:BasePath 'assets\MA_Cyber_Logo.png'),
    (Join-Path (Split-Path $script:BasePath -Parent) 'MA_Cyber_Logo.png'),
    (Join-Path (Get-Location).Path 'MA_Cyber_Logo.png'),
    'C:\ADDetector\MA_Cyber_Logo.png',
    'C:\ADDetector\dist\ADDetector\MA_Cyber_Logo.png'
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
    Write-AppLog -Level WARN -Component 'Branding' -Message "Logo not found in candidates"
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
$btnCSV.Enabled  = $false
$btnXLSX.Enabled = $false

$btnAbout    = New-Btn '?' 1276 ([System.Drawing.Color]::FromArgb(50, 55, 80)) 28
$btnAbout.Font = New-Object System.Drawing.Font('Segoe UI', 10, [System.Drawing.FontStyle]::Bold)
$btnAbout.FlatAppearance.BorderSize = 1
$btnAbout.FlatAppearance.BorderColor = $C.Border

$topBar.Controls.AddRange(@($picLogo,$lblTitle,$lblSub,$topDivider,$lblDomLbl,$cboDomain,$lblManLbl,$txtManual,$lblThrLbl,$cboThreshold,$btnDiscover,$btnScan,$btnClear,$btnCSV,$btnXLSX,$btnAbout))

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
    $chkVPNOnly.Checked      = $false
    $chkRAOnly.Checked       = $false
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

$chkPrivOnly  = New-Chk 'Privileged only'    152
$chkNeverOnly = New-Chk 'Never logged in'    280
$chkHideSA    = New-Chk 'Hide svc accts'     408
$chkHideDis   = New-Chk 'Hide disabled'      533
$chkVPNOnly   = New-Chk 'VPN/MFA only'       650
$chkRAOnly    = New-Chk 'Remote access only' 750

$lblSrch      = New-Object System.Windows.Forms.Label
$lblSrch.Text = ''
$lblSrch.AutoSize  = $true
$lblSrch.Location  = New-Object System.Drawing.Point(-100, -100)
$lblSrch.Visible = $false

$txtSearch         = New-Object System.Windows.Forms.TextBox
$txtSearch.Location = New-Object System.Drawing.Point(880, 7)
$txtSearch.Size     = New-Object System.Drawing.Size(282, 22)
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
$btnDetail.Location = New-Object System.Drawing.Point(1175, 7)
$btnDetail.FlatStyle = 'Flat'
$btnDetail.BackColor = $C.BgCard
$btnDetail.ForeColor = $C.FgSecondary
$btnDetail.Font   = $F.UISm
$btnDetail.FlatAppearance.BorderSize = 1
$btnDetail.FlatAppearance.BorderColor = $C.Border

$filterBar.Controls.AddRange(@($cboRisk,$chkPrivOnly,$chkNeverOnly,$chkHideSA,$chkHideDis,$chkVPNOnly,$chkRAOnly,$lblSrch,$txtSearch,$btnDetail))

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

$script:TypeDD = New-MultiDropdown 'Type' 860
$script:DeptDD = New-MultiDropdown 'Dept' 975

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
    $script:TypeFilter = @()
    # ItemCheck fires before state updates — handle via timer
    $t = New-Object System.Windows.Forms.Timer; $t.Interval = 30
    $t.Add_Tick({
        $t.Stop(); $t.Dispose()
        $script:TypeFilter = @($script:TypeDD.Clb.CheckedItems | ForEach-Object { "$_" })
        Update-MultiBtn $script:TypeDD 'Type'
        if ($script:allRows.Count) { Apply-Filters }
    })
    $t.Start()
})

$script:DeptDD.Clb.Add_ItemCheck({
    $t = New-Object System.Windows.Forms.Timer; $t.Interval = 30
    $t.Add_Tick({
        $t.Stop(); $t.Dispose()
        $script:DeptFilter = @($script:DeptDD.Clb.CheckedItems | ForEach-Object { "$_" })
        Update-MultiBtn $script:DeptDD 'Dept'
        if ($script:allRows.Count) { Apply-Filters }
    })
    $t.Start()
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
        if ($chkVPNOnly.Checked   -and -not ($r.HasVPNAccess -or $r.HasMFA)) { return $false }
        if ($chkRAOnly.Checked    -and -not $r.HasRemoteAccess)  { return $false }
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
# ABOUT DIALOG
# ====================================================================
function Show-AboutDialog {
    $dlg               = New-Object System.Windows.Forms.Form
    $dlg.Text          = 'About ADDetector'
    $dlg.Size          = New-Object System.Drawing.Size(420, 310)
    $dlg.MinimumSize   = New-Object System.Drawing.Size(420, 310)
    $dlg.MaximumSize   = New-Object System.Drawing.Size(420, 310)
    $dlg.StartPosition = 'CenterParent'
    $dlg.BackColor     = $script:C.BgMid
    $dlg.ForeColor     = $script:C.FgPrimary
    $dlg.FormBorderStyle = 'FixedDialog'
    $dlg.MaximizeBox   = $false
    $dlg.MinimizeBox   = $false
    $dlg.Font          = $script:F.UI

    $pnlAccent         = New-Object System.Windows.Forms.Panel
    $pnlAccent.Dock    = 'Top'
    $pnlAccent.Height  = 5
    $pnlAccent.BackColor = $script:C.AccentBlue

    $lblName           = New-Object System.Windows.Forms.Label
    $lblName.Text      = 'ADDetector v1.0'
    $lblName.Font      = New-Object System.Drawing.Font('Segoe UI Semibold', 16, [System.Drawing.FontStyle]::Bold)
    $lblName.ForeColor = $script:C.AccentBlue
    $lblName.AutoSize  = $true
    $lblName.Location  = New-Object System.Drawing.Point(24, 24)

    $lblTagline        = New-Object System.Windows.Forms.Label
    $lblTagline.Text   = 'IAM Hygiene & Dormant Account Detection'
    $lblTagline.Font   = $script:F.UISm
    $lblTagline.ForeColor = $script:C.FgSecondary
    $lblTagline.AutoSize  = $true
    $lblTagline.Location  = New-Object System.Drawing.Point(24, 58)

    $sep               = New-Object System.Windows.Forms.Panel
    $sep.Location      = New-Object System.Drawing.Point(24, 82)
    $sep.Size          = New-Object System.Drawing.Size(368, 1)
    $sep.BackColor     = $script:C.Border

    $lblDev            = New-Object System.Windows.Forms.Label
    $lblDev.Text       = 'Developed by  MA Cyber Security Team'
    $lblDev.Font       = New-Object System.Drawing.Font('Segoe UI Semibold', 9.5, [System.Drawing.FontStyle]::Bold)
    $lblDev.ForeColor  = $script:C.FgPrimary
    $lblDev.AutoSize   = $true
    $lblDev.Location   = New-Object System.Drawing.Point(24, 98)

    $lblDetails        = New-Object System.Windows.Forms.Label
    $lblDetails.Text   = "Purpose  :  AD dormant / orphan account detection`nTarget    :  SOC / IAM Security Operations`nPlatform  :  PowerShell 5.1 + RSAT (Windows)`nLicense   :  Internal use only - MA Cyber"
    $lblDetails.Font   = $script:F.UISm
    $lblDetails.ForeColor = $script:C.FgSecondary
    $lblDetails.AutoSize  = $true
    $lblDetails.Location  = New-Object System.Drawing.Point(24, 126)

    $sep2              = New-Object System.Windows.Forms.Panel
    $sep2.Location     = New-Object System.Drawing.Point(24, 210)
    $sep2.Size         = New-Object System.Drawing.Size(368, 1)
    $sep2.BackColor    = $script:C.Border

    $lblCopy           = New-Object System.Windows.Forms.Label
    $lblCopy.Text      = [char]0x00A9 + " 2026 MA Cyber Security Team. All rights reserved."
    $lblCopy.Font      = New-Object System.Drawing.Font('Segoe UI', 7.5)
    $lblCopy.ForeColor = $script:C.FgMuted
    $lblCopy.AutoSize  = $true
    $lblCopy.Location  = New-Object System.Drawing.Point(24, 220)

    $btnClose          = New-Object System.Windows.Forms.Button
    $btnClose.Text     = 'Close'
    $btnClose.Size     = New-Object System.Drawing.Size(80, 26)
    $btnClose.Location = New-Object System.Drawing.Point(316, 242)
    $btnClose.FlatStyle = 'Flat'
    $btnClose.BackColor = $script:C.BgCard
    $btnClose.ForeColor = $script:C.FgPrimary
    $btnClose.FlatAppearance.BorderColor = $script:C.Border
    $btnClose.DialogResult = [System.Windows.Forms.DialogResult]::OK

    $dlg.Controls.AddRange(@($pnlAccent,$lblName,$lblTagline,$sep,$lblDev,$lblDetails,$sep2,$lblCopy,$btnClose))
    $dlg.AcceptButton = $btnClose
    [void]$dlg.ShowDialog($form)
    $dlg.Dispose()
}

# ====================================================================
# EVENTS
# ====================================================================
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
$chkVPNOnly.Add_CheckedChanged({   if ($script:allRows.Count) { Apply-Filters } })
$chkRAOnly.Add_CheckedChanged({    if ($script:allRows.Count) { Apply-Filters } })
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
    Show-Detail $null
    Reset-Cards
    Set-Status 'Cleared.'
})

$btnCSV.Add_Click({  Export-CSV-View  })
$btnXLSX.Add_Click({ Export-XLSX-View })

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
$form.Add_Load({  Set-SafeSplitter })
$form.Add_Shown({
    Set-SafeSplitter
    if ($script:AutoStartDone) { return }
    $script:AutoStartDone = $true

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
