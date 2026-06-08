```
███████╗██████╗ ███████╗███╗   ██╗
██╔════╝██╔══██╗██╔════╝████╗  ██║
█████╗  ██████╔╝█████╗  ██╔██╗ ██║
██╔══╝  ██╔══██╗██╔══╝  ██║╚██╗██║
███████╗██║  ██║███████╗██║ ╚████║
╚══════╝╚═╝  ╚═╝╚══════╝╚═╝  ╚═══╝
```
> **ADDetector v1.0** — Active Directory Security Assessment & Exposure Visibility Tool  
> by [Eren Arslan](https://github.com/ErenArslann)

---

# 🇹🇷 Türkçe

## Ne Yapar?

Active Directory ortamlarında güvenlik açıklarını ve riskli hesapları tespit eder.

- Uzun süredir aktif olmayan (dormant) hesaplar
- Hiç giriş yapılmamış hesaplar
- Privileged + inactive kombinasyonları **(CRITICAL risk)**
- VPN / Remote Access yetkisi olan ama inactive hesaplar
- MFA kaydı olmayan kullanıcılar
- Servis hesabı tespiti ve false positive önleme
- Risk skorlama: **CRITICAL / HIGH / MEDIUM / LOW**

## Gereksinimler

| Gereksinim | Detay |
|---|---|
| İşletim Sistemi | Windows 10/11 veya Windows Server |
| PowerShell | 5.1+ |
| RSAT | Active Directory modülü (otomatik kurulur) |
| Ağ | Domain Controller'a LDAP (389) erişimi |
| İzin | Domain Users veya üzeri (read-only yeterli) |

## Kurulum

1. [Releases](https://github.com/ErenArslann/ADDetector/releases) sayfasından `ADDetector-v1.0.0.zip` indir
2. İstediğin klasöre çıkart
3. `ADDetector.exe` çalıştır — bitti

> Installer yok. Registry'e dokunmaz. Sadece kendi klasöründe `logs/` ve `exports/` oluşturur.

## Kullanım

```
ADDetector.exe açılır
  → Domain otomatik keşfedilir
  → Tek domain varsa tarama otomatik başlar
  → Grid dolar, risk renkleri görünür
  → Satıra tıkla → sağda detay paneli açılır
  → Export: CSV veya XLSX
```

**Filtreler**
- Risk dropdown: CRITICAL / HIGH / MEDIUM / LOW / SVC-ACCT / DISABLED
- Metric kartlara tıkla → anlık filtrele
- Arama kutusu: kullanıcı adı, mail, departman, DN
- Checkboxlar: Privileged only, Never logged in, VPN only...

---

# 🇬🇧 English

## What does it do?

Detects security risks and vulnerable accounts in Active Directory environments.

- Dormant accounts (inactive for 30+ days)
- Accounts that have never logged in
- Privileged + inactive combinations **(CRITICAL risk)**
- Accounts with VPN/Remote Access but inactive
- Users without MFA enrollment
- Service account detection with false positive prevention
- Risk scoring: **CRITICAL / HIGH / MEDIUM / LOW**

## Requirements

| Requirement | Detail |
|---|---|
| OS | Windows 10/11 or Windows Server |
| PowerShell | 5.1+ |
| RSAT | Active Directory module (auto-installed if missing) |
| Network | LDAP (389) access to Domain Controller |
| Permission | Domain Users or higher (read-only is sufficient) |

## Installation

1. Download `ADDetector-v1.0.0.zip` from [Releases](https://github.com/ErenArslann/ADDetector/releases)
2. Extract to any folder
3. Run `ADDetector.exe` — that's it

> No installer. Does not touch the registry. Only creates `logs/` and `exports/` in its own folder.

## Usage

```
Launch ADDetector.exe
  → Domain is automatically discovered
  → Scan starts automatically if single domain
  → Grid populates with color-coded risk levels
  → Click any row → detail panel opens on the right
  → Export: CSV or XLSX
```

**Filters**
- Risk dropdown: CRITICAL / HIGH / MEDIUM / LOW / SVC-ACCT / DISABLED
- Click metric cards → instant filter
- Search box: username, mail, department, DN
- Checkboxes: Privileged only, Never logged in, VPN only...

## Folder Structure

```
ADDetector/
├── ADDetector.exe              ← Executable
├── ADDetector.png              ← Application logo
├── ADDetector.ico              ← Application icon
├── MainForm.ps1                ← Main application UI
├── DomainDiscovery.ps1         ← AD domain/DC enumeration
├── modules/
│   └── DetectionConfig.ps1    ← Detection group logic
├── config/
│   └── detection-groups.json  ← VPN/MFA/Privileged group definitions
├── logs/                       ← Auto-created (7-day rotation)
├── exports/                    ← CSV/XLSX export output
└── README.md
```

## detection-groups.json Configuration

Edit group definitions to match your environment:

```json
{
  "patterns": {
    "vpn": {
      "isEnabled": true,
      "groups": ["VPN-Users", "GlobalProtect-Users"],
      "regex": "vpn|remote.access"
    },
    "privileged": {
      "isEnabled": true,
      "groups": ["Domain Admins", "Enterprise Admins", "Schema Admins"]
    }
  }
}
```

## Security Note

ADDetector is **read-only**. It does not modify, disable, or delete any AD objects.  
Only performs `Get-ADUser` and `Get-ADGroup` queries.

---

## License

© 2026 Eren Arslan. All Rights Reserved.  
This software is proprietary. Unauthorized distribution is prohibited.

---

*Built with ❤️ by [Eren Arslan](https://github.com/ErenArslann)*
