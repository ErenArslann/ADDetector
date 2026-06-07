# ADDetector v1.0
**IAM Hygiene & Dormant Account Detection Tool**

> Developed by **MA Cyber Security Team**  
> © 2026 MA Cyber Security. Internal use only.

---

## Ne Yapar?

Active Directory ortamlarında **dormant (uykuda) ve orphan (sahipsiz) hesapları** tespit eder.  
SOC/IAM operasyonları için tasarlanmıştır.

- 30+ gün inactive enabled hesaplar
- Hiç login olmamış hesaplar  
- Privileged + inactive kombinasyonları (CRITICAL risk)
- VPN/Remote access yetkisi olan ama inactive hesaplar
- Service account tespiti ve false positive önleme
- Risk scoring (CRITICAL / HIGH / MEDIUM / LOW)

---

## Gereksinimler

| Gereksinim | Detay |
|---|---|
| PowerShell | 5.1+ |
| RSAT | ActiveDirectory modülü kurulu olmalı |
| Ağ | Domain Controller'a LDAP (389) erişimi |
| İzin | Domain Users veya üzeri (read-only yeterli) |

RSAT kurulu değilse:
```powershell
Add-WindowsFeature RSAT-AD-PowerShell   # Server
# veya
Get-WindowsCapability -Online -Name RSAT* | Add-WindowsCapability -Online  # Windows 10/11
```

---

## Kurulum (Portable)

1. `ADDetector-v1.0.0.zip` dosyasını indir
2. İstediğin klasöre çıkart
3. `ADDetector.exe` çalıştır — bitti.

Installer yok. Registry'e dokunmaz. Sadece kendi klasöründe `logs/` ve `exports/` oluşturur.

---

## Kullanım

```
ADDetector.exe açılır
  → Otomatik domain discover
  → Domain seç (tek domain varsa otomatik scan başlar)
  → Grid dolar, risk renkleri görünür
  → Detail panel için herhangi bir satıra tıkla
  → Export: CSV veya XLSX
```

### Filtreler
- **Risk dropdown**: CRITICAL / HIGH / MEDIUM / LOW / SVC-ACCT / DISABLED
- **Metric card'lara tıkla**: Tek tıkla o kategoriye filtrele
- **Search box**: Username, mail, department, DN üzerinde anlık arama
- **Checkboxlar**: Privileged only, Never logged in, Hide SvcAcct, VPN only...

---

## Dağıtım Yapısı

```
ADDetector/
├── ADDetector.exe              ← Çalıştırılabilir (Launcher.ps1 compile)
├── MainForm.ps1                ← Ana uygulama
├── DomainDiscovery.ps1         ← AD domain/DC enumeration
├── modules/
│   └── DetectionConfig.ps1    ← Group detection logic
├── config/
│   └── detection-groups.json  ← VPN/MFA/Privileged grup tanımları
├── logs/                       ← Otomatik oluşur (günlük log)
├── exports/                    ← CSV/XLSX export çıktıları
└── README.md
```

---

## detection-groups.json Yapılandırması

VPN, MFA, Remote Access ve Privileged gruplarını kendi ortamınıza göre düzenleyin:

```json
{
  "patterns": {
    "vpn": {
      "isEnabled": true,
      "groups": ["VPN-Users", "GlobalProtect-Users"],
      "regex": "vpn|remote.access"
    },
    "mfa": {
      "isEnabled": true,
      "groups": ["MFA-Enabled", "DUO-Users"]
    },
    "privileged": {
      "isEnabled": true,
      "groups": ["Domain Admins", "Enterprise Admins", "Schema Admins"]
    }
  }
}
```

---

## Log Konumu

```
ADDetector\logs\addetector-YYYYMMDD.log
```

Hata ayıklama için bu dosyayı incele.

---

## Güvenlik Notu

Bu tool **read-only** çalışır. Hiçbir AD objesi değiştirmez, disable etmez, silmez.  
Sadece `Get-ADUser` sorgusu yapar.

---

*Motor Asin Cyber Security Team — Internal Tool*
