#Requires -Version 5.1
<#
.SYNOPSIS
    ADDetector - Detection Config module
.DESCRIPTION
    Pattern-based detection config loader/saver.
    Match priority: groups (exact, case-insensitive) > regex (fallback)
    isEnabled=false  -> category disabled, always returns no match.

    Public functions:
      Initialize-DetectionConfig      Load (auto-create if missing)
      Save-DetectionConfig            Persist current $script:DetectionConfig to disk
      Get-DetectionConfig             Return current config object
      Set-DetectionCategory           Update a single category (groups, regex, isEnabled)
      Test-GroupMatch                 Match a single AD group name against a category
      Get-MatchedGroupsByCategory     Returns matched groups from a flat list, per category
#>

# Default config - mirrors config/detection-groups.json
function Get-DefaultDetectionConfig {
    return [PSCustomObject]@{
        version     = 1
        description = 'ADDetector detection patterns. Edit via GUI or directly.'
        patterns    = [PSCustomObject]@{
            vpn = [PSCustomObject]@{
                isEnabled = $true
                label     = 'VPN Access'
                regex     = 'vpn|globalprotect|anyconnect|fortivpn|fortinet|forticlient|cisco.?vpn|sslvpn|alwayson.?vpn|directaccess|pulse.?secure|openvpn|wireguard|zscaler|netscaler.?gateway|paloalto'
                groups    = @()
            }
            mfa = [PSCustomObject]@{
                isEnabled = $true
                label     = 'MFA Enrollment'
                regex     = 'mfa|2fa|two.?factor|multi.?factor|duo|azure.?mfa|authenticator|rsa.?token|securid|yubikey|fido|passwordless|conditional.?access'
                groups    = @()
            }
            remoteAccess = [PSCustomObject]@{
                isEnabled = $true
                label     = 'Remote Access'
                regex     = 'remote.?access|rd.?gateway|rdgateway|rds.?users|terminal.?services|citrix|xenapp|xendesktop|rdweb|workspace|tsgateway|jump.?server|bastion'
                groups    = @()
            }
            privileged = [PSCustomObject]@{
                isEnabled = $true
                label     = 'Privileged Groups'
                regex     = ''
                groups    = @('Domain Admins','Enterprise Admins','Schema Admins',
                              'Administrators','Account Operators','Backup Operators',
                              'Print Operators','Server Operators','Group Policy Creator Owners')
            }
            serviceAccount = [PSCustomObject]@{
                isEnabled = $true
                label     = 'Service Accounts'
                regex     = 'svc|service|sql|backup|scan|nps|adfs|krbtgt|_svc|\.svc'
                groups    = @()
            }
        }
    }
}

# Validate / normalize a loaded config (fills missing fields with defaults).
function Repair-DetectionConfig {
    param([PSCustomObject]$Loaded)
    $def = Get-DefaultDetectionConfig
    if (-not $Loaded)           { return $def }
    if (-not $Loaded.patterns)  { return $def }

    $warnings = @()

    # Ensure all categories exist
    foreach ($catName in @('vpn','mfa','remoteAccess','privileged','serviceAccount')) {
        if (-not $Loaded.patterns.PSObject.Properties[$catName]) {
            $warnings += "Missing category '$catName' - restored from defaults."
            $Loaded.patterns | Add-Member -NotePropertyName $catName `
                -NotePropertyValue ($def.patterns.$catName) -Force
        } else {
            $cat = $Loaded.patterns.$catName
            $defCat = $def.patterns.$catName
            # Ensure required fields
            foreach ($f in @('isEnabled','label','regex','groups')) {
                if (-not $cat.PSObject.Properties[$f]) {
                    $cat | Add-Member -NotePropertyName $f -NotePropertyValue $defCat.$f -Force
                    $warnings += "Category '$catName' missing '$f' - filled from default."
                }
            }
            # Normalize groups to array
            if ($cat.groups -isnot [array]) {
                if ($null -eq $cat.groups) { $cat.groups = @() }
                else                       { $cat.groups = @($cat.groups) }
            }
        }
    }

    if (-not $Loaded.PSObject.Properties['version']) {
        $Loaded | Add-Member -NotePropertyName version -NotePropertyValue 1 -Force
    }

    if ($warnings.Count -gt 0) {
        Write-Warning "DetectionConfig repaired:"
        $warnings | ForEach-Object { Write-Warning "  $_" }
    }
    return $Loaded
}

function Initialize-DetectionConfig {
    [CmdletBinding()]
    param(
        [string]$Path
    )
    if (-not $Path) {
        $here = if ($PSScriptRoot) { Split-Path -Parent $PSScriptRoot } else { (Get-Location).Path }
        $Path = Join-Path $here 'config\detection-groups.json'
    }

    $script:DetectionConfigPath = $Path
    $configDir = Split-Path -Parent $Path

    if (-not (Test-Path $configDir)) {
        New-Item -ItemType Directory -Path $configDir -Force | Out-Null
    }

    if (-not (Test-Path $Path)) {
        Write-Warning "DetectionConfig not found at: $Path - creating default."
        $def = Get-DefaultDetectionConfig
        $script:DetectionConfig = $def
        Save-DetectionConfig
        return $def
    }

    try {
        $raw = Get-Content -Path $Path -Raw -Encoding UTF8 -ErrorAction Stop
        $obj = $raw | ConvertFrom-Json -ErrorAction Stop
        $script:DetectionConfig = Repair-DetectionConfig $obj
        return $script:DetectionConfig
    } catch {
        Write-Warning "DetectionConfig parse failed: $_ - falling back to defaults (file NOT overwritten)."
        $script:DetectionConfig = Get-DefaultDetectionConfig
        return $script:DetectionConfig
    }
}

function Save-DetectionConfig {
    [CmdletBinding()]
    param(
        [string]$Path
    )
    if (-not $Path) { $Path = $script:DetectionConfigPath }
    if (-not $Path) { throw 'Save-DetectionConfig: no path resolved. Call Initialize-DetectionConfig first.' }
    if (-not $script:DetectionConfig) { throw 'No config in memory.' }

    $json = $script:DetectionConfig | ConvertTo-Json -Depth 6
    $enc  = New-Object System.Text.UTF8Encoding($false)   # JSON: no BOM
    [System.IO.File]::WriteAllText($Path, $json, $enc)
    return $Path
}

function Get-DetectionConfig {
    if (-not $script:DetectionConfig) { Initialize-DetectionConfig | Out-Null }
    return $script:DetectionConfig
}

function Set-DetectionCategory {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][ValidateSet('vpn','mfa','remoteAccess','privileged','serviceAccount')]
        [string]$Category,
        [string[]]$Groups,
        [string]$Regex,
        [Nullable[bool]]$IsEnabled
    )
    if (-not $script:DetectionConfig) { Initialize-DetectionConfig | Out-Null }
    $cat = $script:DetectionConfig.patterns.$Category
    if (-not $cat) { throw "Unknown category: $Category" }

    if ($PSBoundParameters.ContainsKey('Groups'))    { $cat.groups    = @($Groups) }
    if ($PSBoundParameters.ContainsKey('Regex'))     { $cat.regex     = $Regex }
    if ($PSBoundParameters.ContainsKey('IsEnabled') -and $null -ne $IsEnabled) {
        $cat.isEnabled = [bool]$IsEnabled
    }
    return $cat
}

# Match a single group name against a category.
# Priority: exact group match (case-insensitive) > regex (if no exact match found).
function Test-GroupMatch {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$GroupName,
        [Parameter(Mandatory)][ValidateSet('vpn','mfa','remoteAccess','privileged','serviceAccount')]
        [string]$Category
    )
    if (-not $script:DetectionConfig) { Initialize-DetectionConfig | Out-Null }
    $cat = $script:DetectionConfig.patterns.$Category
    if (-not $cat -or -not $cat.isEnabled) { return $false }

    # Exact match priority (case-insensitive)
    if ($cat.groups -and $cat.groups.Count -gt 0) {
        foreach ($g in $cat.groups) {
            if ([string]::Equals($g, $GroupName, [System.StringComparison]::OrdinalIgnoreCase)) {
                return $true
            }
        }
    }

    # Regex fallback (only if not matched by exact list)
    if ($cat.regex) {
        if ($GroupName -match $cat.regex) { return $true }
    }
    return $false
}

# Returns matched groups from a flat list, for each category.
# Output: hashtable @{ vpn = @(...); mfa = @(...); ... }
function Get-MatchedGroupsByCategory {
    [CmdletBinding()]
    param([string[]]$MemberOfFlat)

    $result = @{
        vpn            = @()
        mfa            = @()
        remoteAccess   = @()
        privileged     = @()
        serviceAccount = @()
    }
    if (-not $MemberOfFlat -or $MemberOfFlat.Count -eq 0) { return $result }

    foreach ($g in $MemberOfFlat) {
        foreach ($cat in @('vpn','mfa','remoteAccess','privileged','serviceAccount')) {
            if (Test-GroupMatch -GroupName $g -Category $cat) {
                $result[$cat] += $g
            }
        }
    }
    return $result
}
