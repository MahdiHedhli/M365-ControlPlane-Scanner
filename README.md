# 🚨 M365 Control Plane Scanner

![Status](https://img.shields.io/badge/status-active%20starter-0b7285)
![Focus](https://img.shields.io/badge/focus-Entra%20ID%20%7C%20Intune%20%7C%20M365-1d3557)
![Content](https://img.shields.io/badge/content-PowerShell%20%2B%20KQL-6c584c)
![Maintained](https://img.shields.io/badge/updated-2026--03--23-588157)
![Author](https://img.shields.io/badge/author-Mahdi%20Hedhli-8d99ae)
![Org](https://img.shields.io/badge/org-42%20Corp-264653)

> A read-only PowerShell assessment tool for quickly identifying Microsoft 365 control-plane exposure that can turn privileged access into tenant-wide destructive impact.

This repository is built to help defenders, admins, and security teams answer a hard question quickly: if an attacker lands privileged access in Entra ID or Intune, how much of the tenant can they control, disrupt, or destroy?

Maintained by **Mahdi Hedhli** and **42 Corp**.

## 🎯 Why This Exists

Modern attacks do not need exploits.

They often:

- Compromise an account
- Escalate privileges
- Abuse the control plane

And in minutes they can:

- Wipe or retire devices
- Lock out users
- Grant persistent access
- Disrupt business operations

## 💥 The Question This Tool Answers

> If an attacker gets admin access, how bad does it get?

This starter repo is designed to make that blast-radius question measurable instead of theoretical.

## 🔍 What The Expanded Scanner Checks

| Area | Current checks | Why it matters |
| --- | --- | --- |
| `Standing Privileged Access` | Standing privileged Entra role assignments across high-value admin roles | Permanent admin access increases blast radius and removes friction attackers would otherwise face |
| `Global Administrator Count` | Excessive Global Administrator membership | Too many Global Admins makes tenant-wide destructive actions easier after compromise |
| `Conditional Access Coverage` | Whether enabled Conditional Access policies clearly require MFA or strong auth for privileged roles | Admin protection is weak if privileged users are not explicitly covered by strong authentication controls |
| `Application / Service Principal Risk` | Dangerous Microsoft Graph permissions such as `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, `Policy.ReadWrite.ConditionalAccess`, and `DeviceManagementManagedDevices.PrivilegedOperations.All` | Apps can become durable control-plane backdoors with tenant-wide impact |
| `Intune RBAC Exposure` | Intune RBAC assignments that include destructive remote actions like wipe, retire, delete, or remote operations | Endpoint control can become the delivery path for destructive actions at scale |
| `Recent Destructive Or Privilege-Altering Activity` | Recent audit events tied to device destruction, privilege escalation, app consent, and role changes | Fast visibility into recent high-impact actions helps separate historic risk from active abuse |
| `Manual Review Gaps` | Intune Multi Admin Approval, mass-wipe approval gates, and break-glass account hygiene | Some of the most important blast-radius controls still require human validation and process checks |

> Some Conditional Access and Intune RBAC checks currently rely on Microsoft Graph beta endpoints because v1.0 coverage is still incomplete for the full blast-radius workflow.

## 🚨 Included Detection Pack

The repository also includes ready-to-deploy KQL queries in [`detections/`](detections/) for:

- Global Administrator assignment activity
- Privileged role assignment and activation events
- High-risk admin consent or app permission changes
- High-impact Intune destructive actions

## 🧠 Recommended Controls

- Enforce Microsoft Entra PIM for all privileged roles
- Require MFA and Conditional Access for every admin workflow
- Reduce standing Global Administrator assignments to a tightly controlled minimum
- Separate Intune administration from tenant-wide identity administration where possible
- Audit service principals and enterprise applications on a recurring schedule
- Monitor all role changes, app consents, and device management mass-action events
- Enable layered approval controls such as Multi Admin Approval where supported

## 🧰 Install Requirements

Make sure **PowerShell 7+** and **Microsoft Graph PowerShell** are installed before running the scanner.

### 🪟 Windows

```powershell
winget install --id Microsoft.PowerShell --source winget
pwsh -NoLogo -NoProfile -Command "Set-PSRepository PSGallery -InstallationPolicy Trusted; Install-Module Microsoft.Graph -Scope CurrentUser"
```

### 🍎 macOS

```bash
brew install powershell
pwsh -NoLogo -NoProfile -Command "Set-PSRepository PSGallery -InstallationPolicy Trusted; Install-Module Microsoft.Graph -Scope CurrentUser"
```

### 🐧 Linux

Install PowerShell first using Microsoft's distro-specific instructions:

- [Install PowerShell on Linux](https://learn.microsoft.com/powershell/scripting/install/installing-powershell-on-linux)

```bash
pwsh -NoLogo -NoProfile -Command "Set-PSRepository PSGallery -InstallationPolicy Trusted; Install-Module Microsoft.Graph -Scope CurrentUser"
```

## ⚡ Quick Start

Connect to Microsoft Graph with the current read-only scopes used by the scanner:

### 🪟 Windows

```powershell
Connect-MgGraph -Scopes @(
  "Directory.Read.All",
  "RoleManagement.Read.Directory",
  "Application.Read.All",
  "Policy.Read.All",
  "AuditLog.Read.All",
  "DeviceManagementRBAC.Read.All",
  "DeviceManagementManagedDevices.Read.All"
)
```

Run the assessment:

```powershell
./scanner/M365-ControlPlane-Scanner.ps1 -OutputPath ./reports/M365-ControlPlane-Scanner
```

Optionally change the audit lookback window:

```powershell
./scanner/M365-ControlPlane-Scanner.ps1 -OutputPath ./reports/M365-ControlPlane-Scanner -RecentAuditDays 30
```

### 🍎 macOS / 🐧 Linux

Enter PowerShell first:

```bash
pwsh
```

Then connect and run:

```powershell
Connect-MgGraph -Scopes @(
  "Directory.Read.All",
  "RoleManagement.Read.Directory",
  "Application.Read.All",
  "Policy.Read.All",
  "AuditLog.Read.All",
  "DeviceManagementRBAC.Read.All",
  "DeviceManagementManagedDevices.Read.All"
)

./scanner/M365-ControlPlane-Scanner.ps1 -OutputPath ./reports/M365-ControlPlane-Scanner
```

Or use the connection one-liner:

```bash
pwsh -Command 'Connect-MgGraph -Scopes @("Directory.Read.All", "RoleManagement.Read.Directory", "Application.Read.All", "Policy.Read.All", "AuditLog.Read.All", "DeviceManagementRBAC.Read.All", "DeviceManagementManagedDevices.Read.All")'
```

## 🔐 Authentication Notes

The current scanner uses these delegated Microsoft Graph scopes:

- `Directory.Read.All`
- `RoleManagement.Read.Directory`
- `Application.Read.All`
- `Policy.Read.All`
- `AuditLog.Read.All`
- `DeviceManagementRBAC.Read.All`
- `DeviceManagementManagedDevices.Read.All`

Older snippets that include `AppRoleAssignment.Read.All` or `DelegatedPermissionGrant.Read.All` can fail. Those are not used by the current scanner.

The signed-in account also needs supported role coverage for Entra role data, Conditional Access, applications, Intune RBAC, and audit logs. The exact least-privileged combination varies by tenant and API surface, so use a dedicated assessment account with approved read access if a narrow reader account cannot complete the full scan.

## 📦 Output Artifacts

Each run writes a report folder containing:

- `Findings.csv`
- `Findings.json`
- `PrivilegedRoleAssignments.csv`
- `StandingPrivilegedAssignments.csv`
- `ConditionalAccessPolicies.csv`
- `DangerousServicePrincipalPermissions.csv`
- `IntuneHighRiskRoleAssignments.csv`
- `RecentDestructiveAuditEvents.csv`
- `ManualReviewItems.json`
- `Summary.json`

## 🛠️ Practical Follow-Up Actions

1. Move standing privileged admins to Entra PIM with approval and MFA.
2. Reduce Global Administrator count.
3. Separate Intune wipe, retire, delete, and remote actions from broad operations roles.
4. Remove dangerous app permissions that are not explicitly required.
5. Use Intune Multi Admin Approval wherever it is supported in your tenant.
6. Build a custom approval workflow for mass wipe actions above a safe threshold because a standard tenant-wide batch kill switch is not exposed here.

## 📡 Detection Queries Included

Start with the packaged query index here:

- [`detections/README.md`](detections/README.md)

Direct query links:

- [`detections/global-admin-role-assignment.kql`](detections/global-admin-role-assignment.kql)
- [`detections/privileged-role-assignment-activity.kql`](detections/privileged-role-assignment-activity.kql)
- [`detections/admin-consent-high-risk-apps.kql`](detections/admin-consent-high-risk-apps.kql)
- [`detections/intune-destructive-actions.kql`](detections/intune-destructive-actions.kql)

## 📂 Repository Layout

| Path | What it contains |
| --- | --- |
| `scanner/` | The PowerShell assessment script |
| `detections/` | KQL detections for high-risk control-plane activity |
| `README.md` | Repository overview, quick start, and navigation |
| `LICENSE` | Repository license |

## 🛑 Disclaimer

This tool does **not** modify tenant configuration.

It is intended for assessment, validation, awareness, and defensive hardening workflows. Validate all findings in the context of your tenant before taking remediation action.

## 👤 Credits

- Author: **Mahdi Hedhli**
- Organization: **42 Corp**
- Focus: Practical Microsoft cloud defense, threat hunting, and control-plane risk reduction

## 🧩 Related Work

- [Cloud Threat Hunting Playbook](https://github.com/MahdiHedhli/cloud-threat-hunting-playbook)
- [Identity Attack Paths](https://github.com/MahdiHedhli/identity-attack-paths)
- [KQL Detection Lab](https://github.com/MahdiHedhli/kql-detection-lab)

## 💬 Final Thought

> Because "we trust our admins" is not a security control.
>
> And neither is "we would have noticed."
