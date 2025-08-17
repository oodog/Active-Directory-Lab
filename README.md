# Contoso Active Directory Lab Builder

A PowerShell script to automatically build a **complete Active Directory lab** for `contoso.com`.  
This project is designed for testing, training, and demonstration of **enterprise-scale AD DS best practices** in a safe lab environment.

---

## Features

- **Domain Setup**
  - Creates a new AD forest `contoso.com` with DNS.
  - Installs GPMC, RSAT-AD-Tools, and Print Server role.

- **Organizational Structure**
  - OU hierarchy: `Corp` → `Users/Departments`, `Groups (Global/DomainLocal)`, `ServiceAccounts`, `Computers`, `Servers`, `Offices`.
  - Offices: Brisbane, Sydney, Melbourne, London, New York, Singapore.
  - Departments: IT, HR, Finance, Accounting, Sales, Marketing, Engineering, Operations, Legal, etc.

- **Users & Groups**
  - ~120 randomized lab users spread across departments and offices.
  - Admin accounts (added to **Domain Admins** for lab).
  - Service accounts (e.g., SQL, Backup).
  - AGDLP model:  
    - `GG_<Dept>` → Department Global Groups.  
    - `DL_Sh_<Dept>_RW` → Domain Local groups tied to file shares.  
    - Membership chaining ensures best practice for access control.

- **File Shares**
  - Departmental shares (`\\DC\SH-<Dept>`), with NTFS + share permissions via DL groups.
  - `\\DC\SH-Public` for all users (read-only).
  - `\\DC\Users` for home directories.
  - Automatic creation of user home folders with NTFS security.

- **Printers**
  - One printer per office (`PRN-<Office>-01`) using generic TCP/IP ports.
  - Shared from the domain controller for testing.

- **Group Policies**
  - `GPO-User-Run-MapScript`: Runs a SYSVOL logon script that maps:
    - Department drives (e.g., Finance → F:, HR → R:, Sales → Z:, etc.).
    - Office printers depending on office membership.
  - `GPO-Workstation-Baseline`: Basic screen lock after 15 minutes.

- **Logon Script**
  - PowerShell script stored in `SYSVOL\scripts`.
  - Maps drives and printers dynamically based on user’s AD group membership.

---

## Requirements

- Windows Server (2019/2022 recommended).
- Run as **Administrator** on a clean server.
- At least 4 GB RAM and 1 vCPU (lab scale).
- No existing domain on the machine (script installs a new forest).

---

## Usage

1. Clone or download this repository.
2. Copy the script to your Windows Server.
3. Run PowerShell as Administrator:
   ```powershell
   Set-ExecutionPolicy Bypass -Scope Process -Force
   .\Build-ContosoLab.ps1
