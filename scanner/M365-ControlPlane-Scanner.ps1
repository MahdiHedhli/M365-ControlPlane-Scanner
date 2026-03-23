[CmdletBinding()]
param(
    [ValidateRange(1, 365)]
    [int]$RecentAuditDays = 30,

    [string]$OutputPath = "./reports/M365-ControlPlane-Scanner",

    [switch]$SkipConnect,

    [switch]$SkipAuditLogCheck
)

$ErrorActionPreference = "Stop"

$RequiredScopes = @(
    "Directory.Read.All",
    "RoleManagement.Read.Directory",
    "Application.Read.All",
    "Policy.Read.All",
    "AuditLog.Read.All",
    "DeviceManagementRBAC.Read.All",
    "DeviceManagementManagedDevices.Read.All"
)

$PrivilegedRoleNames = @(
    "Global Administrator",
    "Company Administrator",
    "Privileged Role Administrator",
    "Intune Administrator",
    "Cloud Device Administrator",
    "Helpdesk Administrator",
    "Security Administrator",
    "Conditional Access Administrator",
    "Application Administrator",
    "Cloud Application Administrator",
    "User Administrator",
    "Authentication Administrator"
)

$DangerousGraphPermissions = @(
    "DeviceManagementManagedDevices.PrivilegedOperations.All",
    "DeviceManagementConfiguration.ReadWrite.All",
    "DeviceManagementManagedDevices.ReadWrite.All",
    "RoleManagement.ReadWrite.Directory",
    "Directory.ReadWrite.All",
    "AppRoleAssignment.ReadWrite.All",
    "Application.ReadWrite.All",
    "Policy.ReadWrite.ConditionalAccess"
)

$Findings = [System.Collections.Generic.List[object]]::new()
$PrivilegedRoleAssignments = [System.Collections.Generic.List[object]]::new()
$StandingPrivilegedAssignments = [System.Collections.Generic.List[object]]::new()
$ConditionalAccessPolicies = [System.Collections.Generic.List[object]]::new()
$DangerousServicePrincipalPermissions = [System.Collections.Generic.List[object]]::new()
$IntuneHighRiskRoleAssignments = [System.Collections.Generic.List[object]]::new()
$RecentDestructiveAuditEvents = [System.Collections.Generic.List[object]]::new()
$ManualReviewItems = [System.Collections.Generic.List[object]]::new()

function Write-Section {
    param(
        [string]$Message
    )

    Write-Host "`n[*] $Message" -ForegroundColor Yellow
}

function Format-Details {
    param(
        $Details
    )

    if ($null -eq $Details) {
        return ""
    }

    if ($Details -is [string]) {
        return $Details
    }

    return ($Details | ConvertTo-Json -Depth 8 -Compress)
}

function Add-Finding {
    param(
        [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
        [string]$Severity,

        [string]$Category,

        [string]$Title,

        $Details,

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

function Add-ManualReviewItem {
    param(
        [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
        [string]$Severity,

        [string]$Title,

        [string]$Recommendation,

        $Details
    )

    $item = [PSCustomObject]@{
        Severity       = $Severity
        Title          = $Title
        Recommendation = $Recommendation
        Details        = $Details
    }

    $ManualReviewItems.Add($item)
    Add-Finding -Severity $Severity -Category "Manual Review" -Title $Title -Details $Details -Recommendation $Recommendation
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

function Export-ReportCsv {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        [AllowNull()]
        [AllowEmptyCollection()]
        [object[]]$Items
    )

    if (@($Items).Count -gt 0) {
        $Items | Export-Csv -Path $Path -NoTypeInformation -Encoding utf8
    }
    else {
        Set-Content -Path $Path -Value "" -Encoding utf8
    }
}

function Export-ReportJson {
    param(
        [Parameter(Mandatory)]
        [string]$Path,

        [Parameter(Mandatory)]
        $Data
    )

    $Data | ConvertTo-Json -Depth 10 | Set-Content -Path $Path -Encoding utf8
}

function Join-UniqueValues {
    param(
        [string[]]$Values
    )

    return (($Values | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | Sort-Object -Unique) -join ", ")
}

function Get-DisplayLabel {
    param(
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

function Get-PrincipalTypeLabel {
    param(
        $Principal
    )

    if ($null -eq $Principal) {
        return "Unknown"
    }

    $typeValue = [string]$Principal.'@odata.type'
    if ([string]::IsNullOrWhiteSpace($typeValue)) {
        return "Unknown"
    }

    return $typeValue.Replace("#microsoft.graph.", "")
}

function Normalize-RoleName {
    param(
        [string]$RoleName
    )

    if ($RoleName -eq "Company Administrator") {
        return "Global Administrator"
    }

    return $RoleName
}

function Test-PrivilegedRole {
    param(
        [string]$RoleName
    )

    return $PrivilegedRoleNames -contains (Normalize-RoleName -RoleName $RoleName)
}

function Get-AuditActor {
    param(
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

function Get-AuditTargets {
    param(
        $AuditEvent
    )

    $targetNames = @(
        @($AuditEvent.targetResources) |
        ForEach-Object { [string]$_.displayName } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
    )

    return (Join-UniqueValues -Values $targetNames)
}

function Get-GrantControlLabel {
    param(
        $Policy
    )

    $labels = @()
    $labels += @($Policy.grantControls.builtInControls | ForEach-Object { [string]$_ })

    if ($Policy.grantControls.authenticationStrength.displayName) {
        $labels += [string]$Policy.grantControls.authenticationStrength.displayName
    }
    elseif ($Policy.grantControls.authenticationStrength.id) {
        $labels += [string]$Policy.grantControls.authenticationStrength.id
    }

    return (Join-UniqueValues -Values $labels)
}

function Test-StrongAdminAuthRequirement {
    param(
        $Policy
    )

    $builtInControls = @($Policy.grantControls.builtInControls | ForEach-Object { [string]$_ })
    if ($builtInControls -contains "mfa") {
        return $true
    }

    if ($Policy.grantControls.authenticationStrength.id -or $Policy.grantControls.authenticationStrength.displayName) {
        return $true
    }

    return $false
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

$null = New-Item -ItemType Directory -Path $OutputPath -Force
$resolvedOutputPath = (Resolve-Path $OutputPath).Path

Write-Section -Message "Enumerating privileged Entra role assignments"
$roleDefinitions = Invoke-GraphCollection -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$select=id,displayName,templateId,isBuiltIn"
$roleDefinitionById = @{}
$privilegedRoleTemplateIds = @()
$roleDisplayNameByTemplateId = @{}

foreach ($roleDefinition in $roleDefinitions) {
    $roleDefinitionById[[string]$roleDefinition.id] = $roleDefinition

    if ($roleDefinition.templateId) {
        $roleDisplayNameByTemplateId[[string]$roleDefinition.templateId] = [string](Normalize-RoleName -RoleName $roleDefinition.displayName)
    }

    if (Test-PrivilegedRole -RoleName $roleDefinition.displayName) {
        if ($roleDefinition.templateId) {
            $privilegedRoleTemplateIds += [string]$roleDefinition.templateId
        }
    }
}

$privilegedRoleTemplateIds = @($privilegedRoleTemplateIds | Sort-Object -Unique)
$roleAssignments = Invoke-GraphCollection -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments?`$expand=principal"

foreach ($assignment in $roleAssignments) {
    $roleDefinition = $assignment.roleDefinition
    if ($null -eq $roleDefinition -and $roleDefinitionById.ContainsKey([string]$assignment.roleDefinitionId)) {
        $roleDefinition = $roleDefinitionById[[string]$assignment.roleDefinitionId]
    }

    $roleName = Normalize-RoleName -RoleName ([string]$roleDefinition.displayName)
    if (-not (Test-PrivilegedRole -RoleName $roleName)) {
        continue
    }

    $principalLabel = Get-DisplayLabel -Object $assignment.principal
    $principalType = Get-PrincipalTypeLabel -Principal $assignment.principal

    $record = [PSCustomObject]@{
        Role          = $roleName
        Principal     = $principalLabel
        PrincipalId   = [string]$assignment.principal.id
        PrincipalType = $principalType
        DirectoryScopeId = [string]$assignment.directoryScopeId
        AssignmentId  = [string]$assignment.id
    }

    $PrivilegedRoleAssignments.Add($record)
    $StandingPrivilegedAssignments.Add($record)
}

Export-ReportCsv -Path (Join-Path $resolvedOutputPath "PrivilegedRoleAssignments.csv") -Items @($PrivilegedRoleAssignments)
Export-ReportCsv -Path (Join-Path $resolvedOutputPath "StandingPrivilegedAssignments.csv") -Items @($StandingPrivilegedAssignments)

$globalAdmins = @($StandingPrivilegedAssignments | Where-Object { $_.Role -eq "Global Administrator" })
if ($globalAdmins.Count -gt 3) {
    Add-Finding -Severity Critical -Category "Entra Roles" -Title "Too many Global Administrators detected" -Details ($globalAdmins | Select-Object -First 25) -Recommendation "Reduce standing Global Administrators to a tightly controlled minimum and move admin workflows to Entra PIM with approval and MFA."
}

if ($StandingPrivilegedAssignments.Count -gt 0) {
    Add-Finding -Severity Medium -Category "Entra Roles" -Title "Standing privileged Entra role assignments detected" -Details ($StandingPrivilegedAssignments | Select-Object -First 25) -Recommendation "Review permanent privileged role assignments and convert routine admin access to just-in-time activation with approval and strong authentication."
}

$globalAdminPrincipalIds = @($globalAdmins | ForEach-Object { $_.PrincipalId } | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
$intuneAdmins = @($StandingPrivilegedAssignments | Where-Object { $_.Role -eq "Intune Administrator" })
$overlap = @($intuneAdmins | Where-Object { $globalAdminPrincipalIds -contains $_.PrincipalId })
if ($overlap.Count -gt 0) {
    Add-Finding -Severity High -Category "Entra Roles" -Title "Global Administrator and Intune Administrator overlap detected" -Details ($overlap | Select-Object -First 25) -Recommendation "Separate tenant-wide identity administration from Intune administration wherever possible to reduce control-plane blast radius."
}

Write-Section -Message "Reviewing Conditional Access coverage for privileged roles"
try {
    $caPolicies = Invoke-GraphCollection -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"

    foreach ($policy in $caPolicies) {
        $includeRoles = @($policy.conditions.users.includeRoles | ForEach-Object { [string]$_ })
        $excludeRoles = @($policy.conditions.users.excludeRoles | ForEach-Object { [string]$_ })
        $includeUsers = @($policy.conditions.users.includeUsers | ForEach-Object { [string]$_ })
        $targetsPrivilegedRoles = @($includeRoles | Where-Object { $privilegedRoleTemplateIds -contains $_ }).Count -gt 0
        $targetsAllUsers = $includeUsers -contains "All"
        $requiresStrongAuth = Test-StrongAdminAuthRequirement -Policy $policy

        $ConditionalAccessPolicies.Add([PSCustomObject]@{
                DisplayName            = [string]$policy.displayName
                State                  = [string]$policy.state
                IncludeRoles           = Join-UniqueValues -Values (@($includeRoles | ForEach-Object {
                            if ($roleDisplayNameByTemplateId.ContainsKey($_)) { $roleDisplayNameByTemplateId[$_] } else { $_ }
                        }))
                ExcludeRoles           = Join-UniqueValues -Values (@($excludeRoles | ForEach-Object {
                            if ($roleDisplayNameByTemplateId.ContainsKey($_)) { $roleDisplayNameByTemplateId[$_] } else { $_ }
                        }))
                IncludeUsers           = Join-UniqueValues -Values $includeUsers
                GrantControls          = Get-GrantControlLabel -Policy $policy
                TargetsPrivilegedRoles = $targetsPrivilegedRoles
                TargetsAllUsers        = $targetsAllUsers
                RequiresStrongAuth     = $requiresStrongAuth
            })
    }

    Export-ReportCsv -Path (Join-Path $resolvedOutputPath "ConditionalAccessPolicies.csv") -Items @($ConditionalAccessPolicies)

    $explicitAdminCoverage = @(
        $ConditionalAccessPolicies |
        Where-Object { $_.State -eq "enabled" -and $_.TargetsPrivilegedRoles -and $_.RequiresStrongAuth }
    )

    $broadCoverage = @(
        $ConditionalAccessPolicies |
        Where-Object { $_.State -eq "enabled" -and $_.TargetsAllUsers -and $_.RequiresStrongAuth }
    )

    if ($explicitAdminCoverage.Count -eq 0 -and $broadCoverage.Count -eq 0) {
        Add-Finding -Severity High -Category "Conditional Access" -Title "No enabled Conditional Access policy clearly requires MFA or strong authentication for privileged roles" -Details ($ConditionalAccessPolicies | Select-Object DisplayName, State, IncludeRoles, IncludeUsers, GrantControls) -Recommendation "Create or validate a Conditional Access policy that explicitly covers privileged roles and requires strong authentication."
    }
    elseif ($explicitAdminCoverage.Count -eq 0 -and $broadCoverage.Count -gt 0) {
        Add-Finding -Severity Medium -Category "Conditional Access" -Title "Broad MFA coverage exists, but no explicit privileged-role-targeted policy was found" -Details ($broadCoverage | Select-Object DisplayName, State, IncludeUsers, GrantControls) -Recommendation "Confirm that privileged roles are intentionally covered and consider adding an explicit admin-targeted policy for clarity and resilience."
    }
}
catch {
    Export-ReportCsv -Path (Join-Path $resolvedOutputPath "ConditionalAccessPolicies.csv") -Items @()
    Add-Finding -Severity Info -Category "Conditional Access" -Title "Could not enumerate Conditional Access policies" -Details @{ Error = $_.Exception.Message } -Recommendation "Make sure Policy.Read.All consent is granted and review admin MFA coverage manually if policy enumeration is unavailable."
}

Write-Section -Message "Inspecting service principals and app permissions"
$graphServicePrincipalFilter = [System.Uri]::EscapeDataString("appId eq '00000003-0000-0000-c000-000000000000'")
$graphServicePrincipal = Invoke-GraphCollection -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$filter=$graphServicePrincipalFilter&`$select=id,displayName,appRoles"
$graphPermissionMap = @{}

if ($graphServicePrincipal.Count -gt 0) {
    foreach ($appRole in $graphServicePrincipal[0].appRoles) {
        if ($appRole.id -and $appRole.value) {
            $graphPermissionMap[[string]$appRole.id] = [string]$appRole.value
        }
    }
}

$servicePrincipals = Invoke-GraphCollection -Uri "https://graph.microsoft.com/v1.0/servicePrincipals?`$select=id,displayName,appId,servicePrincipalType&`$top=999"
$servicePrincipalById = @{}

foreach ($servicePrincipal in $servicePrincipals) {
    $servicePrincipalById[[string]$servicePrincipal.id] = $servicePrincipal
}

if ($graphServicePrincipal.Count -eq 0) {
    Add-Finding -Severity Medium -Category "App Permissions" -Title "Microsoft Graph service principal lookup failed" -Details @{ Note = "Dangerous app permission checks were skipped because the Microsoft Graph resource service principal could not be resolved." } -Recommendation "Verify Graph connectivity and rerun the assessment."
}
else {
    $graphServicePrincipalId = [string]$graphServicePrincipal[0].id

    foreach ($servicePrincipal in $servicePrincipals) {
        try {
            $assignments = Invoke-GraphCollection -Uri "https://graph.microsoft.com/v1.0/servicePrincipals/$($servicePrincipal.id)/appRoleAssignments"
        }
        catch {
            continue
        }

        foreach ($assignment in $assignments) {
            if ([string]$assignment.resourceId -ne $graphServicePrincipalId) {
                continue
            }

            $permissionName = $null
            $appRoleId = [string]$assignment.appRoleId
            if ($graphPermissionMap.ContainsKey($appRoleId)) {
                $permissionName = $graphPermissionMap[$appRoleId]
            }

            if ($DangerousGraphPermissions -notcontains $permissionName) {
                continue
            }

            $DangerousServicePrincipalPermissions.Add([PSCustomObject]@{
                    DisplayName    = if ($servicePrincipal.displayName) { [string]$servicePrincipal.displayName } else { [string]$servicePrincipal.id }
                    AppId          = [string]$servicePrincipal.appId
                    Type           = [string]$servicePrincipal.servicePrincipalType
                    Resource       = "Microsoft Graph"
                    Permission     = $permissionName
                    PermissionType = "Application"
                })
        }
    }

    $delegatedGrantFilter = [System.Uri]::EscapeDataString("consentType eq 'AllPrincipals'")
    $delegatedGrants = Invoke-GraphCollection -Uri "https://graph.microsoft.com/v1.0/oauth2PermissionGrants?`$filter=$delegatedGrantFilter&`$select=clientId,scope,resourceId"

    foreach ($grant in $delegatedGrants) {
        $scopes = @([string]$grant.scope -split " " | Where-Object { -not [string]::IsNullOrWhiteSpace($_) })
        $matchedScopes = @($scopes | Where-Object { $DangerousGraphPermissions -contains $_ })
        if ($matchedScopes.Count -eq 0) {
            continue
        }

        $clientId = [string]$grant.clientId
        $servicePrincipal = if ($servicePrincipalById.ContainsKey($clientId)) { $servicePrincipalById[$clientId] } else { $null }

        foreach ($scopeName in $matchedScopes) {
            $DangerousServicePrincipalPermissions.Add([PSCustomObject]@{
                    DisplayName    = if ($servicePrincipal.displayName) { [string]$servicePrincipal.displayName } else { $clientId }
                    AppId          = if ($servicePrincipal.appId) { [string]$servicePrincipal.appId } else { "" }
                    Type           = if ($servicePrincipal.servicePrincipalType) { [string]$servicePrincipal.servicePrincipalType } else { "Unknown" }
                    Resource       = "Microsoft Graph"
                    Permission     = $scopeName
                    PermissionType = "Delegated(AllPrincipals)"
                })
        }
    }
}

$DangerousServicePrincipalPermissionsForExport = @(
    $DangerousServicePrincipalPermissions |
    Sort-Object DisplayName, PermissionType, Permission -Unique
)

Export-ReportCsv -Path (Join-Path $resolvedOutputPath "DangerousServicePrincipalPermissions.csv") -Items $DangerousServicePrincipalPermissionsForExport

if ($DangerousServicePrincipalPermissionsForExport.Count -gt 0) {
    Add-Finding -Severity High -Category "App Permissions" -Title "Dangerous service principal or application permissions detected" -Details ($DangerousServicePrincipalPermissionsForExport | Select-Object -First 50) -Recommendation "Review app ownership, remove unnecessary Graph permissions, and treat Intune privileged operations, directory write scopes, and Conditional Access write scopes as high-risk control-plane access."
}

Write-Section -Message "Reviewing Intune RBAC assignments for destructive actions"
try {
    $intuneRoleDefinitions = Invoke-GraphCollection -Uri "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions"
    $intuneRoleAssignments = Invoke-GraphCollection -Uri "https://graph.microsoft.com/beta/deviceManagement/roleAssignments"
    $intuneRoleDefinitionById = @{}

    foreach ($roleDefinition in $intuneRoleDefinitions) {
        $intuneRoleDefinitionById[[string]$roleDefinition.id] = $roleDefinition
    }

    foreach ($assignment in $intuneRoleAssignments) {
        $roleDefinitionId = [string]$assignment.roleDefinitionId
        if (-not $intuneRoleDefinitionById.ContainsKey($roleDefinitionId)) {
            continue
        }

        $roleDefinition = $intuneRoleDefinitionById[$roleDefinitionId]
        $allowedActions = @()

        foreach ($rolePermission in @($roleDefinition.rolePermissions)) {
            foreach ($resourceAction in @($rolePermission.resourceActions)) {
                $allowedActions += @($resourceAction.allowedResourceActions | ForEach-Object { [string]$_ })
            }
        }

        $highRiskActions = @(
            $allowedActions |
            Where-Object { $_ -match "wipe|retire|delete|clean|remote" } |
            Sort-Object -Unique
        )

        if ($highRiskActions.Count -eq 0) {
            continue
        }

        $IntuneHighRiskRoleAssignments.Add([PSCustomObject]@{
                RoleName       = [string]$roleDefinition.displayName
                AssignmentId   = [string]$assignment.id
                MemberGroupIds = Join-UniqueValues -Values (@($assignment.members | ForEach-Object { [string]$_ }))
                ScopeGroupIds  = Join-UniqueValues -Values (@($assignment.scopeMembers | ForEach-Object { [string]$_ }))
                AllowedActions = Join-UniqueValues -Values $highRiskActions
            })
    }

    Export-ReportCsv -Path (Join-Path $resolvedOutputPath "IntuneHighRiskRoleAssignments.csv") -Items @($IntuneHighRiskRoleAssignments)

    if ($IntuneHighRiskRoleAssignments.Count -gt 0) {
        Add-Finding -Severity High -Category "Intune RBAC" -Title "Intune RBAC assignments include destructive remote actions" -Details ($IntuneHighRiskRoleAssignments | Select-Object -First 25) -Recommendation "Keep wipe, retire, delete, and remote actions in tightly scoped custom Intune roles and separate them from broad operations or help desk access."
    }
}
catch {
    Export-ReportCsv -Path (Join-Path $resolvedOutputPath "IntuneHighRiskRoleAssignments.csv") -Items @()
    Add-Finding -Severity Info -Category "Intune RBAC" -Title "Could not enumerate Intune RBAC assignments" -Details @{ Error = $_.Exception.Message } -Recommendation "Review Intune custom roles manually if Graph beta access is unavailable or restricted in the tenant."
}

if (-not $SkipAuditLogCheck) {
    Write-Section -Message "Reviewing recent destructive or privilege-altering audit activity"
    try {
        $cutoff = (Get-Date).ToUniversalTime().AddDays(-1 * $RecentAuditDays).ToString("o")
        $auditFilter = [System.Uri]::EscapeDataString("activityDateTime ge $cutoff")
        $auditEvents = Invoke-GraphCollection -Uri "https://graph.microsoft.com/beta/auditLogs/directoryAudits?`$filter=$auditFilter"
        $activityPattern = "wipe|retire|delete|remove|disable|lock|role assignment|add member to role|add eligible member to role|activate eligible assignment|app role assignment|consent to application|permission grant|conditional access"

        foreach ($auditEvent in $auditEvents) {
            if (-not ([string]$auditEvent.activityDisplayName -match $activityPattern)) {
                continue
            }

            $RecentDestructiveAuditEvents.Add([PSCustomObject]@{
                    ActivityDateTime = [string]$auditEvent.activityDateTime
                    ActivityDisplayName = [string]$auditEvent.activityDisplayName
                    InitiatedBy      = Get-AuditActor -AuditEvent $auditEvent
                    Targets          = Get-AuditTargets -AuditEvent $auditEvent
                    Result           = [string]$auditEvent.result
                    CorrelationId    = [string]$auditEvent.correlationId
                })
        }

        $RecentDestructiveAuditEventsForExport = @(
            $RecentDestructiveAuditEvents |
            Sort-Object ActivityDateTime -Descending
        )

        Export-ReportCsv -Path (Join-Path $resolvedOutputPath "RecentDestructiveAuditEvents.csv") -Items $RecentDestructiveAuditEventsForExport

        if ($RecentDestructiveAuditEventsForExport.Count -gt 0) {
            Add-Finding -Severity Medium -Category "Audit Logs" -Title "Recent destructive or privilege-altering audit activity detected" -Details ($RecentDestructiveAuditEventsForExport | Select-Object -First 25) -Recommendation "Validate each event, baseline expected administrative changes, and forward these audit events to SIEM for alerting and response."
        }
    }
    catch {
        Export-ReportCsv -Path (Join-Path $resolvedOutputPath "RecentDestructiveAuditEvents.csv") -Items @()
        Add-Finding -Severity Info -Category "Audit Logs" -Title "Could not query directory audit activity" -Details @{ Error = $_.Exception.Message } -Recommendation "Verify AuditLog.Read.All consent and make sure audit data is available to the assessment account."
    }
}
else {
    Export-ReportCsv -Path (Join-Path $resolvedOutputPath "RecentDestructiveAuditEvents.csv") -Items @()
}

Add-ManualReviewItem -Severity High -Title "Verify Intune Multi Admin Approval is enabled for high-risk changes" -Recommendation "Use Intune Multi Admin Approval for protected changes where supported, and review whether the highest-impact workflows in your tenant are covered." -Details @{ Note = "Current Graph coverage for every MAA-protected object is incomplete, so manual validation is still required." }

Add-ManualReviewItem -Severity High -Title "Confirm there is a custom approval gate for mass wipe or retire workflows" -Recommendation "Wrap bulk Intune destructive actions in a second-approver workflow and require a change ticket or emergency approval above a defined device threshold." -Details @{ Note = "There is no standard native tenant-wide kill-switch threshold for destructive device actions exposed here." }

Add-ManualReviewItem -Severity Medium -Title "Review break-glass account design and monitoring" -Recommendation "Maintain cloud-only emergency access accounts, exclude them carefully from lockout paths, and alert on every sign-in or credential change." -Details @{ Note = "Break-glass account validation usually requires local review of exclusions, credentials, and monitoring standards." }

$findingsForCsv = @(
    $Findings |
    ForEach-Object {
        [PSCustomObject]@{
            Severity       = $_.Severity
            Category       = $_.Category
            Title          = $_.Title
            Recommendation = $_.Recommendation
            Details        = Format-Details -Details $_.Details
        }
    }
)

Export-ReportCsv -Path (Join-Path $resolvedOutputPath "Findings.csv") -Items $findingsForCsv
Export-ReportJson -Path (Join-Path $resolvedOutputPath "Findings.json") -Data @($Findings)
Export-ReportJson -Path (Join-Path $resolvedOutputPath "ManualReviewItems.json") -Data @($ManualReviewItems)

$summary = [PSCustomObject]@{
    TenantId             = $context.TenantId
    Account              = $context.Account
    GeneratedAtUtc       = (Get-Date).ToUniversalTime().ToString("o")
    RecentAuditDays      = $RecentAuditDays
    ReportPath           = $resolvedOutputPath
    TotalFindings        = $Findings.Count
    CriticalSeverityCount = @($Findings | Where-Object { $_.Severity -eq "Critical" }).Count
    HighSeverityCount    = @($Findings | Where-Object { $_.Severity -eq "High" }).Count
    MediumSeverityCount  = @($Findings | Where-Object { $_.Severity -eq "Medium" }).Count
    LowSeverityCount     = @($Findings | Where-Object { $_.Severity -eq "Low" }).Count
    InfoCount            = @($Findings | Where-Object { $_.Severity -eq "Info" }).Count
}

Export-ReportJson -Path (Join-Path $resolvedOutputPath "Summary.json") -Data $summary

Write-Host "`n==== Summary ====" -ForegroundColor Cyan
$severityOrder = @("Critical", "High", "Medium", "Low", "Info")
$summaryTable = foreach ($severity in $severityOrder) {
    [PSCustomObject]@{
        Severity = $severity
        Count    = @($Findings | Where-Object { $_.Severity -eq $severity }).Count
    }
}

$summaryTable | Format-Table -AutoSize | Out-String | Write-Host

Write-Host "==== Findings ====" -ForegroundColor Cyan
if ($Findings.Count -eq 0) {
    Write-Host "[OK] No major control-plane risks were identified by the current checks." -ForegroundColor Green
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
        Write-Host "  Details : $(Format-Details -Details $finding.Details)" -ForegroundColor Gray
        Write-Host "  Action  : $($finding.Recommendation)`n" -ForegroundColor Gray
    }
}

Write-Host "[+] Reports written to: $resolvedOutputPath" -ForegroundColor Cyan
Write-Host "[+] Assessment complete.`n" -ForegroundColor Cyan
