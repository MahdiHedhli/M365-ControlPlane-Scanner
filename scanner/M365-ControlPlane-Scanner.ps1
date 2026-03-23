[CmdletBinding()]
param(
    [ValidateRange(1, 720)]
    [int]$RecentAuditHours = 72,

    [string]$OutputPath,

    [switch]$SkipConnect
)

$ErrorActionPreference = "Stop"

$RequiredScopes = @(
    "Directory.Read.All",
    "AuditLog.Read.All",
    "RoleManagement.Read.Directory",
    "Application.Read.All",
    "AppRoleAssignment.Read.All",
    "DelegatedPermissionGrant.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "DeviceManagementRBAC.Read.All"
)

$RiskyGraphPermissions = @(
    "Directory.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "DeviceManagementManagedDevices.PrivilegedOperations.All"
)

$Findings = [System.Collections.Generic.List[object]]::new()

function Write-Section {
    param(
        [string]$Message
    )

    Write-Host "`n[*] $Message" -ForegroundColor Yellow
}

function Add-Finding {
    param(
        [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
        [string]$Severity,

        [string]$Category,

        [string]$Title,

        [string]$Details,

        [string]$Recommendation
    )

    $Findings.Add([PSCustomObject]@{
            Severity       = $Severity
            Category       = $Category
            Title          = $Title
            Details        = $Details
            Recommendation = $Recommendation
        })
}

function Ensure-GraphModule {
    if (-not (Get-Command -Name Connect-MgGraph -ErrorAction SilentlyContinue)) {
        throw "Microsoft Graph PowerShell is not installed. Install it with: Install-Module Microsoft.Graph -Scope CurrentUser"
    }

    if (-not (Get-Command -Name Invoke-MgGraphRequest -ErrorAction SilentlyContinue)) {
        throw "Invoke-MgGraphRequest is unavailable. Make sure the Microsoft.Graph.Authentication module is installed."
    }
}

function Ensure-GraphConnection {
    if ($SkipConnect) {
        return
    }

    $context = Get-MgContext -ErrorAction SilentlyContinue
    if ($null -eq $context -or [string]::IsNullOrWhiteSpace($context.Account)) {
        Write-Host "[+] Connecting to Microsoft Graph..." -ForegroundColor Cyan
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome | Out-Null
        return
    }

    $missingScopes = @()
    foreach ($scope in $RequiredScopes) {
        if ($context.Scopes -notcontains $scope) {
            $missingScopes += $scope
        }
    }

    if ($missingScopes.Count -gt 0) {
        Write-Host "[!] Reconnecting to Microsoft Graph to ensure required read scopes are present..." -ForegroundColor Yellow
        Connect-MgGraph -Scopes $RequiredScopes -NoWelcome | Out-Null
    }
}

function Invoke-GraphCollection {
    param(
        [Parameter(Mandatory)]
        [string]$Uri
    )

    $items = @()
    $next = $Uri

    while (-not [string]::IsNullOrWhiteSpace($next)) {
        $response = Invoke-MgGraphRequest -Method GET -Uri $next -OutputType PSObject

        if ($null -ne $response.value) {
            $items += $response.value
            $next = $response.'@odata.nextLink'
        }
        else {
            $items += $response
            $next = $null
        }
    }

    return @($items)
}

function Get-DisplayLabel {
    param(
        [Parameter(Mandatory)]
        $Object
    )

    if ($null -eq $Object) {
        return "Unknown"
    }

    if ($Object.userPrincipalName) {
        return "$($Object.displayName) <$($Object.userPrincipalName)>"
    }

    if ($Object.displayName) {
        return [string]$Object.displayName
    }

    if ($Object.id) {
        return [string]$Object.id
    }

    return "Unknown"
}

function Get-AuditActor {
    param(
        [Parameter(Mandatory)]
        $AuditEvent
    )

    if ($AuditEvent.initiatedBy.user.userPrincipalName) {
        return [string]$AuditEvent.initiatedBy.user.userPrincipalName
    }

    if ($AuditEvent.initiatedBy.user.displayName) {
        return [string]$AuditEvent.initiatedBy.user.displayName
    }

    if ($AuditEvent.initiatedBy.app.displayName) {
        return [string]$AuditEvent.initiatedBy.app.displayName
    }

    return "Unknown"
}

function Join-UniqueValues {
    param(
        [Parameter(Mandatory)]
        [string[]]$Values
    )

    return (($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) -join ", ")
}

Write-Host "`n[+] Starting M365 Control Plane Assessment..." -ForegroundColor Cyan
Write-Host "[+] Author: Mahdi Hedhli | 42 Corp" -ForegroundColor Cyan

Ensure-GraphModule
Ensure-GraphConnection

$context = Get-MgContext -ErrorAction SilentlyContinue
if ($null -eq $context -or [string]::IsNullOrWhiteSpace($context.Account)) {
    throw "No active Microsoft Graph context was found. Connect-MgGraph first or rerun without -SkipConnect."
}

$tenantLabel = if ($context.TenantId) { $context.TenantId } else { "Unknown tenant" }
Write-Host "[+] Connected tenant: $tenantLabel" -ForegroundColor Cyan

Write-Section -Message "Enumerating activated directory roles"
$directoryRoles = Invoke-GraphCollection -Uri "https://graph.microsoft.com/v1.0/directoryRoles?`$select=id,displayName,roleTemplateId"
$roleMembersByName = @{}

foreach ($role in $directoryRoles) {
    $members = Invoke-GraphCollection -Uri "https://graph.microsoft.com/v1.0/directoryRoles/$($role.id)/members?`$select=id,displayName,userPrincipalName"
    $roleMembersByName[$role.displayName] = @($members)
    if ($role.displayName -eq "Company Administrator") {
        $roleMembersByName["Global Administrator"] = @($members)
    }
}

$highRiskRoles = @(
    "Global Administrator",
    "Privileged Role Administrator",
    "Intune Administrator",
    "Security Administrator"
)

foreach ($roleName in $highRiskRoles) {
    $members = @()
    if ($roleMembersByName.ContainsKey($roleName)) {
        $members = @($roleMembersByName[$roleName])
    }

    if ($roleName -eq "Global Administrator" -and $members.Count -gt 3) {
        $labels = Join-UniqueValues -Values ($members | ForEach-Object { Get-DisplayLabel -Object $_ })
        Add-Finding -Severity Critical -Category "Identity & Privileged Access" -Title "Global Administrator sprawl" -Details "$($members.Count) active Global Administrators detected: $labels" -Recommendation "Reduce standing Global Administrators to a tightly controlled break-glass set and move privileged workflows into Entra PIM."
    }
    elseif ($roleName -ne "Global Administrator" -and $members.Count -gt 0) {
        $labels = Join-UniqueValues -Values ($members | ForEach-Object { Get-DisplayLabel -Object $_ })
        Add-Finding -Severity High -Category "Identity & Privileged Access" -Title "$roleName has standing or currently active assignments" -Details "$($members.Count) principals currently hold $roleName: $labels" -Recommendation "Review every assignment, enforce just-in-time activation where possible, and document business justification for each principal."
    }
}

$globalAdmins = @()
if ($roleMembersByName.ContainsKey("Global Administrator")) {
    $globalAdmins = @($roleMembersByName["Global Administrator"])
}

$intuneAdmins = @()
if ($roleMembersByName.ContainsKey("Intune Administrator")) {
    $intuneAdmins = @($roleMembersByName["Intune Administrator"])
}

if ($globalAdmins.Count -gt 0 -and $intuneAdmins.Count -gt 0) {
    $globalAdminIds = @($globalAdmins | ForEach-Object { $_.id })
    $overlap = @($intuneAdmins | Where-Object { $globalAdminIds -contains $_.id })
    if ($overlap.Count -gt 0) {
        $labels = Join-UniqueValues -Values ($overlap | ForEach-Object { Get-DisplayLabel -Object $_ })
        Add-Finding -Severity High -Category "Intune Risk Exposure" -Title "Separation of duties gap between Global Admin and Intune Admin" -Details "The following principals hold both Global Administrator and Intune Administrator: $labels" -Recommendation "Separate tenant-wide identity administration from device management administration wherever possible."
    }
}

Write-Section -Message "Reviewing recent privileged activity in directory audit logs"
$since = (Get-Date).ToUniversalTime().AddHours(-1 * $RecentAuditHours).ToString("o")
$recentAuditFilter = [System.Uri]::EscapeDataString("activityDateTime ge $since")
$recentAudits = Invoke-GraphCollection -Uri "https://graph.microsoft.com/v1.0/auditLogs/directoryAudits?`$filter=$recentAuditFilter&`$top=200"
$recentPrivilegedEvents = @(
    $recentAudits | Where-Object {
        $_.activityDisplayName -match "Add member to role|Add eligible member to role|Add member to directory role|Activate eligible assignment|Add eligible assignment"
    }
)

if ($recentPrivilegedEvents.Count -gt 0) {
    $sampleEvents = $recentPrivilegedEvents | Sort-Object activityDateTime -Descending | Select-Object -First 5
    $sampleText = $sampleEvents | ForEach-Object {
        $targetNames = @($_.targetResources | ForEach-Object { $_.displayName } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        "$($_.activityDateTime): $($_.activityDisplayName) by $(Get-AuditActor -AuditEvent $_) targeting $(Join-UniqueValues -Values $targetNames)"
    }

    Add-Finding -Severity High -Category "Recent Privileged Activity" -Title "Recent privileged role change activity detected" -Details "$($recentPrivilegedEvents.Count) role-management events were logged in the last $RecentAuditHours hours. Examples: $($sampleText -join ' | ')" -Recommendation "Validate whether each assignment or activation was expected, correlate with change records, and alert on unscheduled role changes."
}

Write-Section -Message "Checking Microsoft Graph application permissions"
$graphServicePrincipalFilter = [System.Uri]::EscapeDataString("appId eq '00000003-0000-0000-c000-000000000000'")
$graphServicePrincipal = Invoke-GraphCollection -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$graphServicePrincipalFilter&`$select=id,appId,displayName,appRoles"

if ($graphServicePrincipal.Count -eq 0) {
    Add-Finding -Severity Medium -Category "Application / Service Principal Risk" -Title "Microsoft Graph service principal lookup failed" -Details "The scanner could not resolve the Microsoft Graph service principal in the tenant, so application permission checks were skipped." -Recommendation "Verify Microsoft Graph connectivity and rerun the assessment."
}
else {
    $graphSp = $graphServicePrincipal[0]
    $graphRoleMap = @{}
    foreach ($appRole in $graphSp.appRoles) {
        if ($appRole.id -and $appRole.value) {
            $graphRoleMap[[string]$appRole.id] = [string]$appRole.value
        }
    }

    $servicePrincipals = Invoke-GraphCollection -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,appId,displayName&`$top=999"
    $servicePrincipalById = @{}
    foreach ($servicePrincipal in $servicePrincipals) {
        $servicePrincipalById[$servicePrincipal.id] = $servicePrincipal
    }

    $riskyApps = @{}
    foreach ($servicePrincipal in $servicePrincipals) {
        $assignments = Invoke-GraphCollection -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.id)/appRoleAssignments?`$select=id,appRoleId,resourceId"
        foreach ($assignment in $assignments) {
            if ([string]$assignment.resourceId -ne [string]$graphSp.id) {
                continue
            }

            $permissionName = $null
            $appRoleId = [string]$assignment.appRoleId
            if ($graphRoleMap.ContainsKey($appRoleId)) {
                $permissionName = $graphRoleMap[$appRoleId]
            }

            if ($RiskyGraphPermissions -notcontains $permissionName) {
                continue
            }

            if (-not $riskyApps.ContainsKey($servicePrincipal.id)) {
                $riskyApps[$servicePrincipal.id] = [PSCustomObject]@{
                    DisplayName  = if ($servicePrincipal.displayName) { [string]$servicePrincipal.displayName } else { [string]$servicePrincipal.id }
                    Permissions  = @()
                    ServiceAppId = [string]$servicePrincipal.appId
                }
            }

            $riskyApps[$servicePrincipal.id].Permissions += $permissionName
        }
    }

    foreach ($riskyApp in $riskyApps.Values) {
        $permissionList = Join-UniqueValues -Values $riskyApp.Permissions
        Add-Finding -Severity High -Category "Application / Service Principal Risk" -Title "Application with high-risk Microsoft Graph permissions" -Details "$($riskyApp.DisplayName) has application permissions: $permissionList" -Recommendation "Review app ownership, remove unnecessary Graph permissions, rotate secrets or certificates if exposure is suspected, and monitor app-only authentication closely."
    }

    Write-Section -Message "Checking for risky admin-consented delegated grants"
    $delegatedGrantFilter = [System.Uri]::EscapeDataString("consentType eq 'AllPrincipals'")
    $delegatedGrants = Invoke-GraphCollection -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=$delegatedGrantFilter&`$select=clientId,consentType,scope,resourceId"
    foreach ($grant in $delegatedGrants) {
        $scopes = @([string]$grant.scope -split " " | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $matchedScopes = @($scopes | Where-Object { $RiskyGraphPermissions -contains $_ })
        if ($matchedScopes.Count -eq 0) {
            continue
        }

        $appName = if ($servicePrincipalById.ContainsKey($grant.clientId)) { [string]$servicePrincipalById[$grant.clientId].displayName } else { [string]$grant.clientId }
        $scopeLabel = Join-UniqueValues -Values $matchedScopes
        Add-Finding -Severity High -Category "Admin Consent Exposure" -Title "Risky tenant-wide delegated consent detected" -Details "Application $appName has tenant-wide delegated consent for: $scopeLabel" -Recommendation "Review whether the consent is still required, verify publisher trust, and revoke unnecessary tenant-wide grants."
    }
}

Write-Host "`n==== Summary ====" -ForegroundColor Cyan
$severityOrder = @("Critical", "High", "Medium", "Low", "Info")
$summary = foreach ($severity in $severityOrder) {
    [PSCustomObject]@{
        Severity = $severity
        Count    = @($Findings | Where-Object { $_.Severity -eq $severity }).Count
    }
}

$summary | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "==== Findings ====" -ForegroundColor Cyan
if ($Findings.Count -eq 0) {
    Write-Host "[OK] No major control-plane risks were identified by the starter checks." -ForegroundColor Green
}
else {
    foreach ($finding in $Findings) {
        $color = switch ($finding.Severity) {
            "Critical" { "Red" }
            "High" { "Red" }
            "Medium" { "Yellow" }
            "Low" { "Yellow" }
            default { "Cyan" }
        }

        Write-Host "[$($finding.Severity)] $($finding.Title)" -ForegroundColor $color
        Write-Host "  Category: $($finding.Category)" -ForegroundColor Gray
        Write-Host "  Details : $($finding.Details)" -ForegroundColor Gray
        Write-Host "  Action  : $($finding.Recommendation)`n" -ForegroundColor Gray
    }
}

if (-not [string]::IsNullOrWhiteSpace($OutputPath)) {
    $parent = Split-Path -Path $OutputPath -Parent
    if (-not [string]::IsNullOrWhiteSpace($parent) -and -not (Test-Path -Path $parent)) {
        New-Item -Path $parent -ItemType Directory -Force | Out-Null
    }

    $report = [PSCustomObject]@{
        GeneratedAtUtc = (Get-Date).ToUniversalTime().ToString("o")
        TenantId       = $context.TenantId
        Account        = $context.Account
        Author         = "Mahdi Hedhli"
        Organization   = "42 Corp"
        Findings       = @($Findings)
    }

    $report | ConvertTo-Json -Depth 6 | Set-Content -Path $OutputPath -Encoding utf8
    Write-Host "[+] Findings exported to $OutputPath" -ForegroundColor Cyan
}

Write-Host "[+] Assessment complete.`n" -ForegroundColor Cyan
