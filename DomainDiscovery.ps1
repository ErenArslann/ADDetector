#Requires -Version 5.1
<#
.SYNOPSIS
    AD Forest/Domain/DC discovery module -- ADDetector
.DESCRIPTION
    Layer 1 : .NET DirectoryServices.ActiveDirectory (RSAT-independent)
    Layer 2 : RSAT Get-ADDomain (cross-validate, optional)
    Layer 3 : DNS SRV + manual entry fallback

    PS5.1 compat: PSCustomObject factory, no class keyword, no Export-ModuleMember.
    Dot-source safe: . .\DomainDiscovery.ps1
#>

Add-Type -AssemblyName System.DirectoryServices
Add-Type -AssemblyName System.DirectoryServices.AccountManagement

# ── Factory: DomainInfo ──────────────────────────────────────────────────────

function New-DomainInfo {
    param(
        [string]   $DomainName           = '',
        [string]   $NetBIOSName          = '',
        [string]   $ForestName           = '',
        [string]   $PDCEmulator          = '',
        [string[]] $DomainControllers    = @(),
        [string]   $DistinguishedName    = '',
        [bool]     $IsForestRoot         = $false,
        [string]   $FunctionalLevel      = '',
        [string]   $DiscoveryMethod      = 'Unknown'
    )
    [PSCustomObject]@{
        DomainName        = $DomainName
        NetBIOSName       = $NetBIOSName
        ForestName        = $ForestName
        PDCEmulator       = $PDCEmulator
        DomainControllers = $DomainControllers
        DistinguishedName = $DistinguishedName
        IsForestRoot      = $IsForestRoot
        FunctionalLevel   = $FunctionalLevel
        DiscoveredAt      = (Get-Date)
        DiscoveryMethod   = $DiscoveryMethod
    }
}

# ── Logger ───────────────────────────────────────────────────────────────────

function Write-DDLog {
    param(
        [ValidateSet('INFO','WARN','ERROR','DEBUG')]
        [string]$Level,
        [string]$Message
    )
    $ts   = Get-Date -Format 'yyyy-MM-dd HH:mm:ss'
    $line = "[$ts][$Level][DomainDiscovery] $Message"

    if (Get-Command Write-AppLog -ErrorAction SilentlyContinue) {
        Write-AppLog -Level $Level -Module 'DomainDiscovery' -Message $Message
        return
    }
    switch ($Level) {
        'ERROR' { Write-Host $line -ForegroundColor Red    }
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'INFO'  { Write-Host $line -ForegroundColor Cyan   }
        default { Write-Host $line }
    }
}

# ── Helpers ──────────────────────────────────────────────────────────────────

function ConvertTo-DN {
    param([string]$DomainFQDN)
    'DC=' + ($DomainFQDN -replace '\.', ',DC=')
}

function Get-NetBIOSName {
    param([string]$DomainFQDN)

    if (Get-Command Get-ADDomain -ErrorAction SilentlyContinue) {
        try {
            $nb = (Get-ADDomain -Identity $DomainFQDN -ErrorAction Stop).NetBIOSName
            if ($nb) { return $nb }
        } catch { }
    }

    try {
        $rootDSE  = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$DomainFQDN/RootDSE")
        $configNC = $rootDSE.Properties['configurationNamingContext'].Value
        $rootDSE.Dispose()

        $configEntry = New-Object System.DirectoryServices.DirectoryEntry(
            "LDAP://$DomainFQDN/CN=Partitions,$configNC"
        )
        $searcher = New-Object System.DirectoryServices.DirectorySearcher($configEntry)
        $searcher.Filter = "(&(objectClass=crossRef)(dnsRoot=$DomainFQDN)(netBIOSName=*))"
        [void]$searcher.PropertiesToLoad.Add('netBIOSName')
        $result = $searcher.FindOne()
        $configEntry.Dispose()

        if ($result) {
            return $result.Properties['netBIOSName'][0]
        }
    } catch {
        Write-DDLog 'WARN' "NetBIOS LDAP basarisiz ($DomainFQDN): $_"
    }

    return ($DomainFQDN -split '\.')[0].ToUpper()
}

# ── Forest Discovery ─────────────────────────────────────────────────────────

function Get-ForestDomains {
    [CmdletBinding()]
    param([string]$ForestFQDN = '')

    $results = New-Object System.Collections.Generic.List[PSObject]

    try {
        Write-DDLog 'INFO' 'Forest discovery baslatiliyor...'

        if ($ForestFQDN) {
            $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
                [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Forest,
                $ForestFQDN
            )
        } else {
            $ctx = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext(
                [System.DirectoryServices.ActiveDirectory.DirectoryContextType]::Forest
            )
        }

        $forest = [System.DirectoryServices.ActiveDirectory.Forest]::GetForest($ctx)
        Write-DDLog 'INFO' "Forest: $($forest.Name) | Domain sayisi: $($forest.Domains.Count)"

        foreach ($dom in $forest.Domains) {
            $info = New-DomainInfo `
                -DomainName        $dom.Name `
                -ForestName        $forest.Name `
                -IsForestRoot      ($dom.Name -eq $forest.Name) `
                -DiscoveryMethod   'Forest' `
                -DistinguishedName (ConvertTo-DN $dom.Name)

            try   { $info.PDCEmulator = $dom.PdcRoleOwner.Name }
            catch { Write-DDLog 'WARN' "PDC alinamadi ($($dom.Name)): $_" }

            try {
                $info.DomainControllers = @($dom.DomainControllers | ForEach-Object { $_.Name })
                Write-DDLog 'INFO' "$($dom.Name) | DC: $($info.DomainControllers.Count)"
            } catch {
                Write-DDLog 'WARN' "DC listesi alinamadi ($($dom.Name)): $_"
                $info.DomainControllers = @()
            }

            try {
                $de = New-Object System.DirectoryServices.DirectoryEntry("LDAP://$($dom.Name)")
                $info.DistinguishedName = $de.Properties['distinguishedName'].Value
                $info.FunctionalLevel   = $de.Properties['domainFunctionality'].Value
                $de.Dispose()
            } catch {
                Write-DDLog 'WARN' "LDAP DN alinamadi ($($dom.Name)), fallback kullaniliyor."
            }

            $info.NetBIOSName = Get-NetBIOSName -DomainFQDN $dom.Name
            $results.Add($info)
        }
    } catch [System.DirectoryServices.ActiveDirectory.ActiveDirectoryObjectNotFoundException] {
        Write-DDLog 'ERROR' 'Forest bulunamadi. Machine domain-joined degil ya da DNS sorunu.'
        throw
    } catch {
        Write-DDLog 'ERROR' "Forest discovery hatasi: $_"
        throw
    }

    return $results.ToArray()
}

# ── Manual / DNS-SRV Discovery ───────────────────────────────────────────────

function Get-ManualDomainInfo {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$DomainFQDN,
        [string]$PreferredDC = ''
    )

    Write-DDLog 'INFO' "Manuel entry: $DomainFQDN"

    $info = New-DomainInfo `
        -DomainName        $DomainFQDN `
        -DistinguishedName (ConvertTo-DN $DomainFQDN) `
        -ForestName        $DomainFQDN `
        -DiscoveryMethod   'Manual'

    try {
        $srvRecs = Resolve-DnsName -Name "_ldap._tcp.$DomainFQDN" -Type SRV -ErrorAction Stop
        $dcList  = @(
            $srvRecs |
            Where-Object { $_.Type -eq 'SRV' } |
            Select-Object -ExpandProperty NameTarget |
            Sort-Object -Unique
        )
        if ($dcList.Count -gt 0) {
            $info.DomainControllers = $dcList
            $info.PDCEmulator       = $dcList[0]
            $info.DiscoveryMethod   = 'DNS-SRV'
            Write-DDLog 'INFO' "$DomainFQDN | SRV ile $($dcList.Count) DC bulundu"
        }
    } catch {
        Write-DDLog 'WARN' "DNS SRV basarisiz ($DomainFQDN): $_"
        if ($PreferredDC) {
            $info.DomainControllers = @($PreferredDC)
            $info.PDCEmulator       = $PreferredDC
        } else {
            $info.DomainControllers = @()
        }
    }

    $info.NetBIOSName = Get-NetBIOSName -DomainFQDN $DomainFQDN
    return $info
}

# ── DC Reachability ──────────────────────────────────────────────────────────

function Test-DCReachability {
    [CmdletBinding()]
    param(
        [string[]]$DomainControllers,
        [int]$TimeoutMs = 3000,
        [int]$LDAPPort  = 389
    )

    $reachable = New-Object System.Collections.Generic.List[string]

    foreach ($dc in $DomainControllers) {
        $tcp = $null
        try {
            $tcp = New-Object System.Net.Sockets.TcpClient
            $ar  = $tcp.BeginConnect($dc, $LDAPPort, $null, $null)
            $ok  = $ar.AsyncWaitHandle.WaitOne($TimeoutMs)

            if ($ok -and $tcp.Connected) {
                $reachable.Add($dc)
                Write-DDLog 'INFO' "Erisilebilir: $dc"
            } else {
                Write-DDLog 'WARN' "Timeout: $dc"
            }
        } catch {
            Write-DDLog 'WARN' "DC test hatasi ($dc): $_"
        } finally {
            if ($tcp) { $tcp.Close() }
        }
    }

    if ($reachable.Count -eq 0) {
        Write-DDLog 'ERROR' 'Hicbir DC erisilebilir degil!'
    }

    return $reachable.ToArray()
}

# ── Trust Discovery ──────────────────────────────────────────────────────────

function Get-TrustedDomains {
    [CmdletBinding()]
    param()

    $results = New-Object System.Collections.Generic.List[PSObject]

    try {
        Write-DDLog 'INFO' 'Trust discovery baslatiliyor (nltest)...'

        $currentDomain = ''
        try { $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name } catch { }

        $nltestOutput = nltest /domain_trusts 2>&1

        foreach ($line in $nltestOutput) {
            if ($line -match '^\s+\d+:\s+(\S+)\s+(\S+\.\S+)\s+\(') {
                $netbios = $Matches[1]
                $fqdn    = $Matches[2]

                if ($fqdn -eq $currentDomain) { continue }

                Write-DDLog 'INFO' "Trust bulundu: $fqdn ($netbios)"

                try {
                    $info = Get-ManualDomainInfo -DomainFQDN $fqdn
                    $info.NetBIOSName     = $netbios
                    $info.DiscoveryMethod = 'Trust'
                    $results.Add($info)
                } catch {
                    Write-DDLog 'WARN' "Trust domain bilgisi alinamadi ($fqdn): $_"
                }
            }
        }
    } catch {
        Write-DDLog 'WARN' "Trust discovery hatasi: $_"
    }

    return $results.ToArray()
}

# ── Public Entry Point ───────────────────────────────────────────────────────

function Invoke-DomainDiscovery {
    <#
    .SYNOPSIS
        GUI dropdown icin DomainInfo[] dondurur.
        Forest -> Trust -> CurrentDomain sirasiyla dener.
        Siralama: current domain en basta, gerisi alfabetik.
    .PARAMETER ManualDomain
        Belirtilirse discovery atlanir.
    #>
    [CmdletBinding()]
    param([string]$ManualDomain = '')

    if ($ManualDomain) {
        return @(Get-ManualDomainInfo -DomainFQDN $ManualDomain)
    }

    $allDomains = New-Object System.Collections.Generic.List[PSObject]

    # 1. Forest
    try {
        $domains = Get-ForestDomains
        if ($domains) { foreach ($d in $domains) { $allDomains.Add($d) } }
    } catch {
        Write-DDLog 'WARN' "Forest discovery basarisiz: $_"
    }

    # 2. Trust'li domain'ler
    try {
        $trusted = Get-TrustedDomains
        if ($trusted) {
            foreach ($t in $trusted) {
                $exists = $allDomains | Where-Object { $_.DomainName -eq $t.DomainName }
                if (-not $exists) { $allDomains.Add($t) }
            }
        }
    } catch {
        Write-DDLog 'WARN' "Trust discovery basarisiz: $_"
    }

    # 3. Fallback
    if ($allDomains.Count -eq 0) {
        try {
            $cur = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            Write-DDLog 'INFO' "CurrentDomain fallback: $($cur.Name)"
            $allDomains.Add((Get-ManualDomainInfo -DomainFQDN $cur.Name))
        } catch {
            Write-DDLog 'ERROR' "CurrentDomain alinamadi: $_"
            return @()
        }
    }

    # Siralama: current machine'in join oldugu domain EN BASTA,
    # gerisi alfabetik. Boylece motorasin.com her zaman ilk gelir.
    $currentDomain = ''
    try { $currentDomain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name } catch { }

    $sorted = $allDomains.ToArray() | Sort-Object {
        if ($_.DomainName -eq $currentDomain) { '000' } else { $_.DomainName }
    }

    Write-DDLog 'INFO' "Discovery tamamlandi | toplam=$($sorted.Count) | ilk=$($sorted[0].DomainName)"
    return $sorted
}

# ── Entrypoint: script dogrudan calistirilinca burasi execute edilir ─────────
# Dot-source ile yuklenirse ( . .\DomainDiscovery.ps1 ) bu blok da calisir
# ama fonksiyonlar yuklenecegi icin sorun olmaz.

Write-Host "`n=== DomainDiscovery - Test Modu ===" -ForegroundColor Green
Write-Host "Mevcut fonksiyonlar:" -ForegroundColor Gray
Write-Host "  Invoke-DomainDiscovery  [ana entrypoint]"
Write-Host "  Get-ForestDomains       [forest enumeration]"
Write-Host "  Get-TrustedDomains      [trust discovery - nltest]"
Write-Host "  Get-ManualDomainInfo    [manuel domain entry]"
Write-Host "  Test-DCReachability     [DC port testi]"
Write-Host "  Get-NetBIOSName         [NetBIOS resolution]"
Write-Host ""

try {
    Write-Host "Invoke-DomainDiscovery cagiriliyor..." -ForegroundColor Cyan

    $domains = Invoke-DomainDiscovery

    if (-not $domains -or $domains.Count -eq 0) {
        Write-Host "SONUC: Hicbir domain bulunamadi." -ForegroundColor Yellow
        Write-Host "       Manuel girmek icin: Invoke-DomainDiscovery -ManualDomain 'corp.local'" -ForegroundColor Gray
    } else {
        Write-Host "SONUC: $($domains.Count) domain bulundu.`n" -ForegroundColor Green

        $domains | Format-List `
            DomainName, NetBIOSName, ForestName, PDCEmulator,
            @{ N = 'DC Count'; E = { $_.DomainControllers.Count } },
            DistinguishedName, IsForestRoot, FunctionalLevel,
            DiscoveryMethod, DiscoveredAt

        Write-Host "--- DC Reachability Testi ---" -ForegroundColor Green
        foreach ($d in $domains) {
            if ($d.DomainControllers.Count -gt 0) {
                Write-Host "[$($d.DomainName)]" -ForegroundColor Cyan
                $reachable = Test-DCReachability -DomainControllers $d.DomainControllers
                Write-Host "  Erisilebilir: $($reachable.Count) / $($d.DomainControllers.Count) DC"
            } else {
                Write-Host "[$($d.DomainName)] DC listesi bos." -ForegroundColor Yellow
            }
        }
    }
} catch {
    Write-Host "HATA: $_" -ForegroundColor Red
}

Write-Host "`n=== Tamamlandi ===" -ForegroundColor Green
