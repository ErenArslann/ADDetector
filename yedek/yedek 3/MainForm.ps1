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
$form.BackColor     = $C.BgDark
$form.Font          = $F.UI
$form.ForeColor     = $C.FgPrimary

# Window/taskbar icon - .ico veya PNG'den runtime convert
$script:IconCandidates = @(
    (Join-Path $script:BasePath 'ADDetector.ico'),
    (Join-Path $script:BasePath 'MA_Cyber_Logo.ico'),
    (Join-Path (Split-Path $script:BasePath -Parent) 'ADDetector.ico'),
    (Join-Path $script:BasePath 'assets\ADDetector.ico')
)
$iconLoaded = $false
foreach ($icoPath in $script:IconCandidates) {
    if (Test-Path -LiteralPath $icoPath) {
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
# PNG fallback -> runtime ICO conversion (portable, build sirasinda bagimsiz)
if (-not $iconLoaded) {
    $pngForIcon = @(
        (Join-Path $script:BasePath 'MA_Cyber_Logo.png'),
        (Join-Path (Split-Path $script:BasePath -Parent) 'MA_Cyber_Logo.png')
    ) | Where-Object { Test-Path -LiteralPath $_ } | Select-Object -First 1
    if ($pngForIcon) {
        try {
            $bmp = New-Object System.Drawing.Bitmap($pngForIcon)
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
$lblTitle.Font    = New-Object System.Drawing.Font('Segoe UI', 14, [System.Drawing.FontStyle]::Bold)
$lblTitle.ForeColor = $C.AccentBlue
$lblTitle.AutoSize  = $true
$lblTitle.Location  = New-Object System.Drawing.Point(14, 14)

# Logo PictureBox - file exists ise lblTitle gizlenir, logo gosterilir
$picLogo          = New-Object System.Windows.Forms.PictureBox
$picLogo.Location = New-Object System.Drawing.Point(10, 6)
$picLogo.Size     = New-Object System.Drawing.Size(280, 40)
$picLogo.SizeMode = 'Zoom'
$picLogo.BackColor = $C.BgMid
$picLogo.Visible  = $false

# Logo dosyasi: ayni klasor veya parent
$script:LogoCandidates = @(
    (Join-Path $script:BasePath 'MA_Cyber_Logo.png'),
    (Join-Path (Split-Path $script:BasePath -Parent) 'MA_Cyber_Logo.png'),
    (Join-Path $script:BasePath 'assets\MA_Cyber_Logo.png')
)
foreach ($logoPath in $script:LogoCandidates) {
    if (Test-Path -LiteralPath $logoPath) {
        try {
            $picLogo.Image   = [System.Drawing.Image]::FromFile($logoPath)
            $picLogo.Visible = $true
            $lblTitle.Visible = $false
            Write-AppLog -Component 'Branding' -Message "Logo loaded: $logoPath"
            break
        } catch {
            Write-AppLog -Level WARN -Component 'Branding' -Message "Logo load failed: $logoPath | $_"
        }
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

$cboDomain             = New-Object System.Windows.Forms.ComboBox
$cboDomain.Location    = New-Object System.Drawing.Point(315, 24)
$cboDomain.Size        = New-Object System.Drawing.Size(240, 22)
$cboDomain.DropDownStyle = 'DropDownList'
$cboDomain.FlatStyle   = 'Flat'
$cboDomain.BackColor   = $C.BgCard
$cboDomain.ForeColor   = $C.FgPrimary

$lblManLbl        = New-Object System.Windows.Forms.Label
$lblManLbl.Text   = 'MANUEL'
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
$cboThreshold.SelectedIndex = 0  # default: All users (0)

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

$topBar.Controls.AddRange(@($picLogo,$lblTitle,$lblSub,$lblDomLbl,$cboDomain,$lblManLbl,$txtManual,$lblThrLbl,$cboThreshold,$btnDiscover,$btnScan,$btnClear,$btnCSV,$btnXLSX))

# ?? METRIC CARDS ?????????????????????????????????????????????????????????????
$cardBar           = New-Object System.Windows.Forms.Panel
$cardBar.Dock      = 'Top'
$cardBar.Height    = 92
$cardBar.BackColor = $C.BgDark
$cardBar.AutoScroll = $true   # narrow screens: horizontal scroll

$script:metricLabels = @{}

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

    # Hover effect
    $hoverIn = { try { $this.BackColor = $script:C.BgRowAlt } catch { } }
    $hoverOut = { try { $this.BackColor = $script:C.BgCard } catch { } }
    $card.Add_MouseEnter($hoverIn)
    $card.Add_MouseLeave($hoverOut)
}

# Quick-filter dispatcher - card key -> filter state
function Invoke-CardFilter {
    param([string]$CardKey)

    # Once tum filter'lari sifirla
    $cboRisk.SelectedIndex   = 0
    $chkPrivOnly.Checked     = $false
    $chkNeverOnly.Checked    = $false
    $chkHideSA.Checked       = $true   # default davranis
    $chkHideDis.Checked      = $false
    $chkVPNOnly.Checked      = $false
    $chkRAOnly.Checked       = $false
    $txtSearch.Text          = ''

    switch ($CardKey) {
        'Total'      { $chkHideSA.Checked = $false; Set-Status 'Filter: ALL users (reset).' }
        'Inactive'   { Set-Status 'Filter: Inactive/Stale users.' }
        'Critical'   { $cboRisk.SelectedIndex = 1; Set-Status 'Filter: CRITICAL risk.' }
        'Privileged' { $chkPrivOnly.Checked = $true; Set-Status 'Filter: Privileged accounts.' }
        'NeverLogon' { $chkNeverOnly.Checked = $true; Set-Status 'Filter: Never logged in.' }
        'SvcAcc'     { $chkHideSA.Checked = $false; $cboRisk.SelectedIndex = 5; Set-Status 'Filter: Service accounts.' }
        'Disabled'   { $cboRisk.SelectedIndex = 6; Set-Status 'Filter: Disabled stale.' }
        'RemoteAcc'  { $chkRAOnly.Checked = $true; Set-Status 'Filter: Remote access users.' }
        'DormantVPN' { $chkVPNOnly.Checked = $true; Set-Status 'Filter: VPN/MFA users.' }
    }
    Apply-Filters
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
$lblSrch.Text = 'SEARCH'
$lblSrch.Font = $F.CardLbl
$lblSrch.ForeColor = $C.FgSecondary
$lblSrch.AutoSize  = $true
$lblSrch.Location  = New-Object System.Drawing.Point(890, 12)

$txtSearch         = New-Object System.Windows.Forms.TextBox
$txtSearch.Location = New-Object System.Drawing.Point(942, 7)
$txtSearch.Size     = New-Object System.Drawing.Size(220, 22)
$txtSearch.BackColor = $C.BgCard
$txtSearch.ForeColor = $C.FgPrimary
$txtSearch.BorderStyle = 'FixedSingle'

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

$lblDetailHdr     = New-Object System.Windows.Forms.Label
$lblDetailHdr.Text    = 'ACCOUNT DETAIL'
$lblDetailHdr.Dock    = 'Top'
$lblDetailHdr.Height  = 28
$lblDetailHdr.Font    = $F.Header
$lblDetailHdr.ForeColor = $C.AccentBlue
$lblDetailHdr.BackColor = $C.BgMid
$lblDetailHdr.TextAlign = 'MiddleLeft'
$lblDetailHdr.Padding   = New-Object System.Windows.Forms.Padding(10,0,0,0)

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

$detailOuter.Controls.AddRange(@($txtDetail, $lblDetailHdr))
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
    $matched = Get-MatchedGroupsByCategory -MemberOfFlat $memberOfFlat
    $r.MatchedGroups   = $matched
    $r.VPNGroups       = @($matched.vpn)
    $r.MFAGroups       = @($matched.mfa)
    $r.RAGroups        = @($matched.remoteAccess)
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
    $grid.SuspendLayout()

    # Preserve current sort state (so filter changes don't reset user's column sort)
    $sortCol = $null
    $sortDir = 'Descending'
    if ($grid.SortedColumn) {
        $sortCol = $grid.SortedColumn.Name
        $sortDir = $grid.SortOrder
    }

    $grid.Rows.Clear()

    # Default sort: InactiveDays ASC (least inactive first; oldest at bottom)
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
}

# ====================================================================
# FILTER
# ====================================================================
function Apply-Filters {
    $rf     = $cboRisk.SelectedItem
    $srch   = $txtSearch.Text.Trim().ToLower()

    $script:filteredRows = $script:allRows | Where-Object {
        $r = $_
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
    }
    Update-Grid
    Set-Status "Showing $($script:filteredRows.Count) of $($script:allRows.Count) accounts"
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

    # Remember last shown row so the "Show more" link can re-render with expansion.
    $script:CurrentDetailRow = $r
    $script:DetailExpandOthers = $ExpandOthers

    # --- inner helpers (closure over $txtDetail + palette) ---
    $rt = $txtDetail
    $rt.SuspendLayout()
    $rt.Clear()

    $fontHdr   = New-Object System.Drawing.Font($F.UIBold.FontFamily, 9.5, [System.Drawing.FontStyle]::Bold)
    $fontKey   = New-Object System.Drawing.Font($F.UISm.FontFamily,   8.75)
    $fontVal   = New-Object System.Drawing.Font($F.UI.FontFamily,     9.25)
    $fontBadge = New-Object System.Drawing.Font($F.UIBold.FontFamily, 8.75, [System.Drawing.FontStyle]::Bold)

    function _W { param([string]$Text, [System.Drawing.Color]$Color, [System.Drawing.Font]$Font)
        $rt.SelectionStart  = $rt.TextLength
        $rt.SelectionLength = 0
        if ($Font)  { $rt.SelectionFont  = $Font }
        if ($Color) { $rt.SelectionColor = $Color }
        $rt.AppendText($Text)
    }
    function _Section { param([string]$Title)
        if ($rt.TextLength -gt 0) { _W "`r`n" $script:C.FgPrimary $fontVal }
        _W ("  " + $Title.ToUpper() + "`r`n") $script:C.AccentBlue $fontHdr
        _W ("  " + ("-" * 38) + "`r`n") $script:C.Border $fontKey
    }
    function _Row { param([string]$Key, $Val, [System.Drawing.Color]$ValColor)
        if (-not $ValColor) { $ValColor = $script:C.FgPrimary }
        $k = ("    {0,-13}: " -f $Key)
        _W $k $script:C.FgSecondary $fontKey
        $vs = if ($null -eq $Val) { '-' } elseif ("$Val" -eq '') { '-' } else { "$Val" }
        _W ($vs + "`r`n") $ValColor $fontVal
    }
    function _Badge { param([string]$Key, [string]$Label, [System.Drawing.Color]$Color)
        $k = ("    {0,-13}: " -f $Key)
        _W $k $script:C.FgSecondary $fontKey
        _W ("[" + $Label + "]`r`n") $Color $fontBadge
    }
    function _Bullet { param([string]$Text, [System.Drawing.Color]$Color)
        if (-not $Color) { $Color = $script:C.FgPrimary }
        _W ("      - " + $Text + "`r`n") $Color $fontVal
    }

    if (-not $r) {
        _W "  Select a user from the grid to view details." $script:C.FgMuted $fontVal
        $rt.ResumeLayout(); return
    }

    # ============================ IDENTITY ============================
    _Section 'Identity'
    _Row 'Username'   $r.SamAccountName
    _Row 'Display'    $r.DisplayName
    _Row 'Mail'       $r.Mail
    _Row 'Department' $r.Department
    _Row 'Description' $r.Description
    # Extract OU from DN
    $ou = $r.DistinguishedName
    if ($ou -match '(OU=[^,]+(?:,OU=[^,]+)*)') { $ou = $Matches[1] }
    _Row 'OU' $ou
    _Row 'DN' $r.DistinguishedName

    # ============================ ACCESS ==============================
    _Section 'Access'
    _Badge 'VPN'        $(if ($r.HasVPNAccess) {'YES'} else {'NO'}) $(if ($r.HasVPNAccess) {$script:C.RiskHigh} else {$script:C.FgMuted})
    $mfaColor = if ($r.HasMFA) { $script:C.RiskLow }
                elseif ($r.HasVPNAccess) { $script:C.RiskCritical }   # VPN without MFA = red flag
                else { $script:C.FgMuted }
    _Badge 'MFA'        $(if ($r.HasMFA) {'YES'} else {'NO'}) $mfaColor
    _Badge 'RemoteAcc'  $(if ($r.HasRemoteAccess) {'YES'} else {'NO'}) $(if ($r.HasRemoteAccess) {$script:C.RiskHigh} else {$script:C.FgMuted})
    $vpnRiskColor = switch ($r.VPNRisk) {
        'CRITICAL' { $script:C.RiskCritical } 'HIGH' { $script:C.RiskHigh }
        'MEDIUM'   { $script:C.RiskMedium   } default { $script:C.FgMuted }
    }
    _Badge 'VPN Risk'   $r.VPNRisk $vpnRiskColor
    _Badge 'Privileged' $(if ($r.IsPrivileged) {'YES'} else {'NO'}) $(if ($r.IsPrivileged) {$script:C.RiskHigh} else {$script:C.FgMuted})
    _Row   'AdminCount' $r.AdminCount $(if ($r.AdminCount -eq 1) {$script:C.RiskCritical} else {$script:C.FgPrimary})
    _Row   'SPN Count'  $r.SPNCount

    # ============================ HYGIENE =============================
    _Section 'Hygiene'
    _Row 'Last Logon' $r.LastLogon $(if ($r.NeverLoggedIn) {$script:C.RiskCritical} else {$script:C.FgPrimary})
    $inactiveColor = if ($r.InactiveDays -ge 90) { $script:C.RiskCritical }
                    elseif ($r.InactiveDays -ge 60) { $script:C.RiskHigh }
                    elseif ($r.InactiveDays -ge 30) { $script:C.RiskMedium }
                    else { $script:C.FgPrimary }
    _Row 'Inactive'   ("{0} days" -f $r.InactiveDays) $inactiveColor
    _Row 'Never Logon' $r.NeverLoggedIn $(if ($r.NeverLoggedIn) {$script:C.RiskCritical} else {$script:C.FgPrimary})
    _Row 'Pwd Set'    $r.PwdLastSet
    $pwdColor = if ($r.PwdAgeDays -ge 365) { $script:C.RiskCritical }
               elseif ($r.PwdAgeDays -ge 180) { $script:C.RiskMedium }
               else { $script:C.FgPrimary }
    _Row 'Pwd Age'    ("{0} days" -f $r.PwdAgeDays) $pwdColor
    _Row 'Created'    $r.WhenCreated
    $enColor = if ($r.Enabled) { $script:C.RiskLow } else { $script:C.FgMuted }
    _Badge 'Enabled'  $(if ($r.Enabled) {'ENABLED'} else {'DISABLED'}) $enColor

    # ============================ RISK ================================
    _Section 'Risk'
    $riskColor = Get-RiskColor $r.RiskLevel
    _Badge 'Level' $r.RiskLevel $riskColor
    $scoreColor = if ($r.RiskScore -ge 80) { $script:C.RiskCritical }
                 elseif ($r.RiskScore -ge 55) { $script:C.RiskHigh }
                 elseif ($r.RiskScore -ge 30) { $script:C.RiskMedium }
                 else { $script:C.RiskLow }
    _Row 'Score' ("{0} / 100" -f $r.RiskScore) $scoreColor
    _Row 'Account Type' $r.AccountType

    # --- Attack Surface Summary: short analyst-readable risk headlines ---
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
        _W "`r`n    Attack Surface:`r`n" $script:C.FgSecondary $fontKey
        foreach ($a in $attackSurface) { _Bullet $a.T $a.C }
    }

    # Why flagged - bullet list of triggered conditions
    _W "`r`n    Why Flagged:`r`n" $script:C.FgSecondary $fontKey
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
    # Categorize all groups: priv + vpn + mfa + ra are "important", rest go to "Other"
    $vpnSet  = @{}
    $mfaSet  = @{}
    $raSet   = @{}
    $privSet = @{}
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
        _Section 'Groups'

        if ($privList.Count -gt 0) {
            _W ("    Privileged ({0}):`r`n" -f $privList.Count) $script:C.FgSecondary $fontKey
            foreach ($g in $privList) { _Bullet $g $script:C.RiskCritical }
        }
        if ($r.VPNGroups.Count -gt 0) {
            _W ("    VPN ({0}):`r`n" -f $r.VPNGroups.Count) $script:C.FgSecondary $fontKey
            foreach ($g in $r.VPNGroups) { _Bullet $g $script:C.RiskHigh }
        }
        if ($r.MFAGroups.Count -gt 0) {
            _W ("    MFA ({0}):`r`n" -f $r.MFAGroups.Count) $script:C.FgSecondary $fontKey
            foreach ($g in $r.MFAGroups) { _Bullet $g $script:C.RiskLow }
        }
        if ($r.RAGroups.Count -gt 0) {
            _W ("    Remote Access ({0}):`r`n" -f $r.RAGroups.Count) $script:C.FgSecondary $fontKey
            foreach ($g in $r.RAGroups) { _Bullet $g $script:C.RiskHigh }
        }

        if ($otherList.Count -gt 0) {
            if ($ExpandOthers) {
                _W ("    Other ({0}):  " -f $otherList.Count) $script:C.FgSecondary $fontKey
                _W "[hide]`r`n" $script:C.AccentBlue $fontBadge
                foreach ($g in $otherList) { _Bullet $g $script:C.FgPrimary }
            } else {
                _W ("    Other Groups: {0} hidden  " -f $otherList.Count) $script:C.FgSecondary $fontKey
                _W "[show all]`r`n" $script:C.AccentBlue $fontBadge
            }
        }
    }

    $rt.SelectionStart  = 0
    $rt.SelectionLength = 0
    $rt.ScrollToCaret()
    $rt.ResumeLayout()
}

# ====================================================================
# EVENTS
# ====================================================================
$btnDiscover.Add_Click({
    $btnDiscover.Enabled = $false
    $btnScan.Enabled     = $false
    $cboDomain.Items.Clear()
    Set-Status 'Discovering domains...' $true
    Write-AppLog -Component 'Discover' -Message "Discover started | manual='$($txtManual.Text)'"
    try {
        $manual = $txtManual.Text.Trim()
        $script:domains = if ($manual) { @(Get-ManualDomainInfo -DomainFQDN $manual) }
                          else          { Invoke-DomainDiscovery }
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
        Set-Card 'Inactive'   $script:allRows.Count
        Set-Card 'Critical'   (@($script:allRows | Where-Object { $_.RiskLevel -eq 'CRITICAL' }).Count)
        Set-Card 'Privileged' (@($script:allRows | Where-Object { $_.IsPrivileged }).Count)
        Set-Card 'NeverLogon' (@($script:allRows | Where-Object { $_.NeverLoggedIn }).Count)
        Set-Card 'SvcAcc'     (@($script:allRows | Where-Object { $_.IsServiceAccount }).Count)
        Set-Card 'Disabled'   (@($script:allRows | Where-Object { -not $_.Enabled }).Count)
        Set-Card 'RemoteAcc'  (@($script:allRows | Where-Object { $_.HasVPNAccess -or $_.HasRemoteAccess }).Count)
        Set-Card 'DormantVPN' (@($script:allRows | Where-Object { $_.HasVPNAccess -and $_.InactiveDays -ge 30 }).Count)

        $script:filteredRows = $script:allRows
        Apply-Filters
        Show-Detail $null
        $btnCSV.Enabled  = $true
        $btnXLSX.Enabled = $true
        Set-Status "[$sel]  Stale: $($script:allRows.Count)  |  Critical: $($script:metricLabels['Critical'].Text)  |  Privileged: $($script:metricLabels['Privileged'].Text)  |  Never Logon: $($script:metricLabels['NeverLogon'].Text)  |  Total: $total"
        Write-AppLog -Component 'Scan' -Message "Scan complete | domain=$sel | total=$total | stale=$($script:allRows.Count)"

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
        # If detail panel is collapsed, leave it - user toggles manually.
    }
})

# Detail panel: click on "[show all]" / "[hide]" to toggle Other Groups expansion
$txtDetail.Add_MouseDown({
    param($sender, $e)
    try {
        if ($e.Button -ne [System.Windows.Forms.MouseButtons]::Left) { return }
        if (-not $script:CurrentDetailRow) { return }
        $idx = $sender.GetCharIndexFromPosition($e.Location)
        if ($idx -lt 0) { return }
        $allText = $sender.Text
        if (-not $allText) { return }

        # Tum [show all] / [hide] substring konumlarini bul
        # Click karakter index'inden +/- 15 karakter tolerans ile match
        $tolerance = 30
        $found = $false

        # [show all] - sadece collapsed durumda anlamli
        if (-not $script:DetailExpandOthers) {
            $pos = $allText.IndexOf('[show all]', [System.StringComparison]::OrdinalIgnoreCase)
            while ($pos -ge 0 -and -not $found) {
                if ([Math]::Abs($pos - $idx) -le $tolerance -or ($idx -ge $pos -and $idx -le $pos + 10)) {
                    Show-Detail $script:CurrentDetailRow -ExpandOthers $true
                    $found = $true
                    break
                }
                $pos = $allText.IndexOf('[show all]', $pos + 1, [System.StringComparison]::OrdinalIgnoreCase)
            }
        }

        # [hide] - sadece expanded durumda anlamli
        if (-not $found -and $script:DetailExpandOthers) {
            $pos = $allText.IndexOf('[hide]', [System.StringComparison]::OrdinalIgnoreCase)
            while ($pos -ge 0 -and -not $found) {
                if ([Math]::Abs($pos - $idx) -le $tolerance -or ($idx -ge $pos -and $idx -le $pos + 6)) {
                    Show-Detail $script:CurrentDetailRow -ExpandOthers $false
                    $found = $true
                    break
                }
                $pos = $allText.IndexOf('[hide]', $pos + 1, [System.StringComparison]::OrdinalIgnoreCase)
            }
        }
    } catch {
        Write-AppLog -Level WARN -Component 'DetailClick' -Message "Click handler error: $_"
    }
})

# Hand cursor when hovering over [show all] / [hide]
$txtDetail.Add_MouseMove({
    param($sender, $e)
    try {
        $idx = $sender.GetCharIndexFromPosition($e.Location)
        if ($idx -lt 0) { $sender.Cursor = [System.Windows.Forms.Cursors]::IBeam; return }
        $allText = $sender.Text
        if (-not $allText) { return }
        $needle = if ($script:DetailExpandOthers) { '[hide]' } else { '[show all]' }
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

$cboRisk.Add_SelectedIndexChanged({ if ($script:allRows.Count) { Apply-Filters } })
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
    # AUTO-DISCOVER on startup, sonra Timer ile delayed auto-scan
    try {
        Write-AppLog -Component 'AutoStart' -Message 'Auto-discover triggered'
        $btnDiscover.PerformClick()
        [System.Windows.Forms.Application]::DoEvents()

        # Discover bittikten 250ms sonra scan tetiklenir - race condition korumasi
        if ($script:domains -and $script:domains.Count -ge 1) {
            $script:AutoScanTimer = New-Object System.Windows.Forms.Timer
            $script:AutoScanTimer.Interval = 250
            $script:AutoScanTimer.Add_Tick({
                $script:AutoScanTimer.Stop()
                $script:AutoScanTimer.Dispose()
                if ($script:domains.Count -eq 1) {
                    Write-AppLog -Component 'AutoStart' -Message 'Single domain detected -> auto-scan firing'
                    Set-Status 'Single domain detected. Auto-scanning...' $true
                    if ($btnScan.Enabled) { $btnScan.PerformClick() }
                } else {
                    Set-Status "Multiple domains found ($($script:domains.Count)). Select one and press SCAN."
                }
            })
            $script:AutoScanTimer.Start()
        }
    } catch {
        Write-AppLog -Level WARN -Component 'AutoStart' -Message "Auto-start failed: $_"
    }
})
$form.Add_Resize({
    try {
        $script:SplitterTimer.Stop()
        $script:SplitterTimer.Start()
    } catch { }
})

[void]$form.ShowDialog()
