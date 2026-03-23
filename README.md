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

## 🔍 What The Starter Scanner Checks

| Area | Current checks | Why it matters |
| --- | --- | --- |
| `Identity & Privileged Access` | Global Administrator sprawl, privileged role membership counts, overlap between Global Admin and Intune Admin | Too many standing admins increases blast radius and weakens separation of duties |
| `Recent Privileged Activity` | Recent directory audit events tied to role assignment and activation activity | Fast visibility into recent privilege changes helps identify active abuse paths |
| `Application / Service Principal Risk` | High-risk Microsoft Graph application permissions such as `Directory.ReadWrite.All`, `RoleManagement.ReadWrite.Directory`, and `DeviceManagementManagedDevices.PrivilegedOperations.All` | Apps and service principals can become durable control-plane backdoors |
| `Admin Consent Exposure` | Tenant-wide delegated grants (`AllPrincipals`) with risky scopes | Admin-consented apps can quietly expand attacker reach across the tenant |

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

Install Microsoft Graph PowerShell before running the scanner.

### 🪟 Windows

```powershell
Set-PSRepository PSGallery -InstallationPolicy Trusted; Install-Module Microsoft.Graph -Scope CurrentUser
```

### 🍎 macOS

```bash
pwsh -NoLogo -NoProfile -Command "Set-PSRepository PSGallery -InstallationPolicy Trusted; Install-Module Microsoft.Graph -Scope CurrentUser"
```

### 🐧 Linux

```bash
pwsh -NoLogo -NoProfile -Command "Set-PSRepository PSGallery -InstallationPolicy Trusted; Install-Module Microsoft.Graph -Scope CurrentUser"
```

## ⚡ Quick Start

Connect to Microsoft Graph with the read-only scopes used by the starter scanner:

```powershell
Connect-MgGraph -Scopes @(
  "Directory.Read.All",
  "AuditLog.Read.All",
  "RoleManagement.Read.Directory",
  "Application.Read.All",
  "AppRoleAssignment.Read.All",
  "DelegatedPermissionGrant.Read.All",
  "DeviceManagementManagedDevices.Read.All",
  "DeviceManagementRBAC.Read.All"
)
```

Run the assessment:

```powershell
./scanner/M365-ControlPlane-Scanner.ps1
```

Optionally export the findings to JSON:

```powershell
./scanner/M365-ControlPlane-Scanner.ps1 -OutputPath ./reports/control-plane-findings.json
```

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
