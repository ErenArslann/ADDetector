# Changelog

All notable changes to ADDetector will be documented here.

## [v1.0.0] - 2026-06-09

### Added
- Active Directory domain auto-discovery (Forest + Trust)
- Automatic scan on single-domain environments
- Risk scoring engine: CRITICAL / HIGH / MEDIUM / LOW
- Detail panel: Identity, Access & Privilege, Risk Assessment, Why Flagged, Group Membership
- VPN / MFA / Remote Access tri-state filters (All / Yes / No)
- Type and Department multi-select dropdown filters
- Metric cards with click-to-filter
- Export: CSV and XLSX
- RSAT auto-install on launch
- 7-day log rotation (`logs\ADDetector.log`)
- Trust discovery via `nltest /domain_trusts`
- EA monogram icon (taskbar + window)
- Professional About dialog with GitHub and LinkedIn links
- Proprietary branding: Eren Arslan

### Technical
- ps2exe packaging via `Build.ps1`
- Portable deployment — no installer, no registry
- PowerShell 5.1 compatible
- Encoding-safe MainForm loading via `ScriptBlock::Create`

---

## Roadmap

### [v1.1.0] — Planned
- Group Picker: GUI-based management of `detection-groups.json`
- HTML Executive Report
- Multi-DC LastLogon aggregation (real dormant detection)
- Auto-update via GitHub Releases API

### [v1.2.0] — Future
- Kerberoastable account detection
- ASREPRoast exposure
- AdminCount drift analysis
- Password Never Expires exposure
- Tier0 / Shadow Admin detection
