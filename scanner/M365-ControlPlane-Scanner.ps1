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

$MicrosoftGraphAppId = "00000003-0000-0000-c000-000000000000"
$WindowsAzureServiceManagementAppId = "797f4846-ba00-4fd7-ba43-dac1f8f63013"
$SecurityInfoRegistrationUserAction = "urn:user:registersecurityinfo"
$AllRiskLevels = @("low", "medium", "high")

$Findings = [System.Collections.Generic.List[object]]::new()
$PrivilegedRoleAssignments = [System.Collections.Generic.List[object]]::new()
$StandingPrivilegedAssignments = [System.Collections.Generic.List[object]]::new()
$ConditionalAccessPolicies = [System.Collections.Generic.List[object]]::new()
$DangerousServicePrincipalPermissions = [System.Collections.Generic.List[object]]::new()
$IntuneHighRiskRoleAssignments = [System.Collections.Generic.List[object]]::new()
$RecentDestructiveAuditEvents = [System.Collections.Generic.List[object]]::new()
$ManualReviewItems = [System.Collections.Generic.List[object]]::new()
$IdentityHardeningPolicyChecks = [System.Collections.Generic.List[object]]::new()

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

        [string]$Status = "",

        $Details,

        [string]$Recommendation
    )

    $Findings.Add([PSCustomObject]@{
            Severity       = $Severity
            Category       = $Category
            Title          = $Title
            Status         = $Status
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
    Add-Finding -Severity $Severity -Category "Manual Review" -Title $Title -Status "MANUAL REVIEW REQUIRED" -Details $Details -Recommendation $Recommendation
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

function Test-CollectionContainsAll {
    param(
        [string[]]$Collection,
        [string[]]$RequiredValues
    )

    foreach ($requiredValue in @($RequiredValues)) {
        if (@($Collection) -notcontains $requiredValue) {
            return $false
        }
    }

    return $true
}

function Test-CollectionIntersects {
    param(
        [string[]]$Collection,
        [string[]]$Candidates
    )

    foreach ($value in @($Collection)) {
        if (@($Candidates) -contains $value) {
            return $true
        }
    }

    return $false
}

function Test-PolicyEnabled {
    param(
        $Policy
    )

    return [string]$Policy.state -eq "enabled"
}

function Test-PolicyReportOnly {
    param(
        $Policy
    )

    return [string]$Policy.state -eq "enabledForReportingButNotEnforced"
}

function Get-PolicyIncludeUsers {
    param(
        $Policy
    )

    return @($Policy.conditions.users.includeUsers | ForEach-Object { [string]$_ })
}

function Get-PolicyIncludeGroups {
    param(
        $Policy
    )

    return @($Policy.conditions.users.includeGroups | ForEach-Object { [string]$_ })
}

function Get-PolicyExcludeUsers {
    param(
        $Policy
    )

    return @($Policy.conditions.users.excludeUsers | ForEach-Object { [string]$_ })
}

function Get-PolicyExcludeGroups {
    param(
        $Policy
    )

    return @($Policy.conditions.users.excludeGroups | ForEach-Object { [string]$_ })
}

function Get-PolicyIncludeRoles {
    param(
        $Policy
    )

    return @($Policy.conditions.users.includeRoles | ForEach-Object { [string]$_ })
}

function Get-PolicyExcludeRoles {
    param(
        $Policy
    )

    return @($Policy.conditions.users.excludeRoles | ForEach-Object { [string]$_ })
}

function Get-PolicyIncludeApplications {
    param(
        $Policy
    )

    return @($Policy.conditions.applications.includeApplications | ForEach-Object { [string]$_ })
}

function Get-PolicyIncludeUserActions {
    param(
        $Policy
    )

    return @($Policy.conditions.applications.includeUserActions | ForEach-Object { [string]$_ })
}

function Get-PolicyUserRiskLevels {
    param(
        $Policy
    )

    return @($Policy.conditions.userRiskLevels | ForEach-Object { ([string]$_).ToLowerInvariant() })
}

function Get-PolicySignInRiskLevels {
    param(
        $Policy
    )

    return @($Policy.conditions.signInRiskLevels | ForEach-Object { ([string]$_).ToLowerInvariant() })
}

function Get-PolicyTransferMethods {
    param(
        $Policy
    )

    $transferMethod = [string]$Policy.conditions.authenticationFlows.transferMethods
    if ([string]::IsNullOrWhiteSpace($transferMethod) -or $transferMethod -eq "none") {
        return @()
    }

    return @($transferMethod)
}

function Get-PolicyAuthenticationStrengthLabel {
    param(
        $Policy
    )

    if ($Policy.grantControls.authenticationStrength.displayName) {
        return [string]$Policy.grantControls.authenticationStrength.displayName
    }

    if ($Policy.grantControls.authenticationStrength.id) {
        return [string]$Policy.grantControls.authenticationStrength.id
    }

    return ""
}

function Get-PolicyBuiltInControls {
    param(
        $Policy
    )

    return @($Policy.grantControls.builtInControls | ForEach-Object { [string]$_ })
}

function Test-PolicyHasBlockGrant {
    param(
        $Policy
    )

    return (Get-PolicyBuiltInControls -Policy $Policy) -contains "block"
}

function Test-PolicyTargetsAllUsers {
    param(
        $Policy
    )

    return (Get-PolicyIncludeUsers -Policy $Policy) -contains "All"
}

function Test-PolicyTargetsAllResources {
    param(
        $Policy
    )

    return (Get-PolicyIncludeApplications -Policy $Policy) -contains "All"
}

function Test-PolicyTargetsPrivilegedRoles {
    param(
        $Policy,
        [string[]]$PrivilegedRoleTemplateIds
    )

    return (Test-CollectionIntersects -Collection (Get-PolicyIncludeRoles -Policy $Policy) -Candidates $PrivilegedRoleTemplateIds)
}

function Test-PolicyTargetsUserAction {
    param(
        $Policy,
        [string]$UserAction
    )

    return (Get-PolicyIncludeUserActions -Policy $Policy) -contains $UserAction
}

function Test-PolicyTargetsApplication {
    param(
        $Policy,
        [string[]]$ApplicationTargets
    )

    return (Test-CollectionIntersects -Collection (Get-PolicyIncludeApplications -Policy $Policy) -Candidates $ApplicationTargets)
}

function Test-PolicyHasAnyAuthStrength {
    param(
        $Policy
    )

    return -not [string]::IsNullOrWhiteSpace((Get-PolicyAuthenticationStrengthLabel -Policy $Policy))
}

function Test-PolicyHasPhishResistantAuthStrength {
    param(
        $Policy
    )

    $label = Get-PolicyAuthenticationStrengthLabel -Policy $Policy
    if ([string]::IsNullOrWhiteSpace($label)) {
        return $false
    }

    return $label -match "phish"
}

function Test-PolicyRequiresCompliantDeviceOrPaw {
    param(
        $Policy
    )

    $builtInControls = Get-PolicyBuiltInControls -Policy $Policy
    if ($builtInControls -contains "compliantDevice" -or $builtInControls -contains "domainJoinedDevice") {
        return $true
    }

    if ($Policy.conditions.devices.deviceFilter.rule) {
        return $true
    }

    return $false
}

function Test-PolicyHasScopedApprovalLogic {
    param(
        $Policy
    )

    if ((Get-PolicyIncludeGroups -Policy $Policy).Count -gt 0) {
        return $true
    }

    if ((Get-PolicyExcludeGroups -Policy $Policy).Count -gt 0) {
        return $true
    }

    if ((Get-PolicyExcludeUsers -Policy $Policy).Count -gt 0) {
        return $true
    }

    if ((Get-PolicyExcludeRoles -Policy $Policy).Count -gt 0) {
        return $true
    }

    return $false
}

function Get-PolicyNames {
    param(
        [object[]]$Policies
    )

    return @(
        @($Policies) |
        ForEach-Object { [string]$_.displayName } |
        Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
        Sort-Object -Unique
    )
}

function Add-PolicyAssessment {
    param(
        [string]$Title,

        [ValidateSet("CONFIGURED", "MISSING", "PARTIALLY CONFIGURED", "MANUAL REVIEW REQUIRED")]
        [string]$Status,

        [ValidateSet("Critical", "High", "Medium", "Low", "Info")]
        [string]$Severity,

        [string]$Summary,

        [string]$Recommendation,

        $Evidence,

        [object[]]$MatchedPolicies = @()
    )

    $matchedPolicyNames = Get-PolicyNames -Policies $MatchedPolicies

    $IdentityHardeningPolicyChecks.Add([PSCustomObject]@{
            Title           = $Title
            Status          = $Status
            Severity        = $Severity
            Summary         = $Summary
            Recommendation  = $Recommendation
            MatchedPolicies = Join-UniqueValues -Values $matchedPolicyNames
            Evidence        = $Evidence
        })

    if ($Status -ne "CONFIGURED") {
        Add-Finding -Severity $Severity -Category "Identity Hardening Policies Most Tenants Miss" -Title $Summary -Status $Status -Details $Evidence -Recommendation $Recommendation
    }
}

function Get-ConditionalAccessEvidenceRows {
    param(
        [object[]]$Policies,
        [string[]]$Columns
    )

    $policyNames = Get-PolicyNames -Policies $Policies
    if ($policyNames.Count -eq 0) {
        return @()
    }

    return @(
        $ConditionalAccessPolicies |
        Where-Object { $policyNames -contains $_.DisplayName } |
        Select-Object $Columns
    )
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
$rawConditionalAccessPolicies = @()
try {
    $rawConditionalAccessPolicies = Invoke-GraphCollection -Uri "https://graph.microsoft.com/beta/identity/conditionalAccess/policies"

    foreach ($policy in $rawConditionalAccessPolicies) {
        $includeRoles = Get-PolicyIncludeRoles -Policy $policy
        $excludeRoles = Get-PolicyExcludeRoles -Policy $policy
        $includeUsers = Get-PolicyIncludeUsers -Policy $policy
        $includeApplications = Get-PolicyIncludeApplications -Policy $policy
        $includeUserActions = Get-PolicyIncludeUserActions -Policy $policy
        $userRiskLevels = Get-PolicyUserRiskLevels -Policy $policy
        $signInRiskLevels = Get-PolicySignInRiskLevels -Policy $policy
        $transferMethods = Get-PolicyTransferMethods -Policy $policy
        $targetsPrivilegedRoles = @($includeRoles | Where-Object { $privilegedRoleTemplateIds -contains $_ }).Count -gt 0
        $targetsAllUsers = $includeUsers -contains "All"
        $targetsAllResources = $includeApplications -contains "All"
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
                IncludeGroupsCount     = (Get-PolicyIncludeGroups -Policy $policy).Count
                IncludeApplications    = Join-UniqueValues -Values $includeApplications
                IncludeUserActions     = Join-UniqueValues -Values $includeUserActions
                UserRiskLevels         = Join-UniqueValues -Values $userRiskLevels
                SignInRiskLevels       = Join-UniqueValues -Values $signInRiskLevels
                AuthenticationFlows    = Join-UniqueValues -Values $transferMethods
                GrantControls          = Get-GrantControlLabel -Policy $policy
                AuthenticationStrength = Get-PolicyAuthenticationStrengthLabel -Policy $policy
                TargetsPrivilegedRoles = $targetsPrivilegedRoles
                TargetsAllUsers        = $targetsAllUsers
                TargetsAllResources    = $targetsAllResources
                RequiresStrongAuth     = $requiresStrongAuth
                RequiresCompliantDeviceOrPaw = Test-PolicyRequiresCompliantDeviceOrPaw -Policy $policy
                HasSecureSignInSession = [bool]$policy.sessionControls.secureSignInSession.isEnabled
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

Write-Section -Message "Identity Hardening Policies Most Tenants Miss"

if (@($rawConditionalAccessPolicies).Count -eq 0) {
    $caUnavailableRecommendation = "Conditional Access policy data could not be enumerated automatically. Review the policy set manually in Entra and rerun after confirming Policy.Read.All access."
    $caUnavailableDetails = @{ Note = "Conditional Access data was unavailable for automated evaluation." }

    Add-PolicyAssessment -Title "Block security info registration for risky users" -Status "MANUAL REVIEW REQUIRED" -Severity Medium -Summary "Conditional Access data was unavailable, so security info registration protections for risky users could not be validated automatically" -Recommendation $caUnavailableRecommendation -Evidence $caUnavailableDetails
    Add-PolicyAssessment -Title "Block security info registration for risky sign-ins" -Status "MANUAL REVIEW REQUIRED" -Severity Medium -Summary "Conditional Access data was unavailable, so security info registration protections for risky sign-ins could not be validated automatically" -Recommendation $caUnavailableRecommendation -Evidence $caUnavailableDetails
    Add-PolicyAssessment -Title "Block high-risk users" -Status "MANUAL REVIEW REQUIRED" -Severity High -Summary "Conditional Access data was unavailable, so blocking of high-risk users could not be validated automatically" -Recommendation $caUnavailableRecommendation -Evidence $caUnavailableDetails
    Add-PolicyAssessment -Title "Restrict Microsoft Graph and PowerShell for unapproved users" -Status "MANUAL REVIEW REQUIRED" -Severity High -Summary "Conditional Access data was unavailable, so Microsoft Graph and PowerShell restrictions could not be validated automatically" -Recommendation $caUnavailableRecommendation -Evidence $caUnavailableDetails
    Add-PolicyAssessment -Title "Require phishing-resistant MFA for admin roles, admin portals, and Azure management" -Status "MANUAL REVIEW REQUIRED" -Severity High -Summary "Conditional Access data was unavailable, so phishing-resistant MFA coverage for privileged access could not be validated automatically" -Recommendation $caUnavailableRecommendation -Evidence $caUnavailableDetails
    Add-PolicyAssessment -Title "Block Device Code Flow" -Status "MANUAL REVIEW REQUIRED" -Severity High -Summary "Conditional Access data was unavailable, so Device Code Flow blocking could not be validated automatically" -Recommendation $caUnavailableRecommendation -Evidence $caUnavailableDetails
    Add-PolicyAssessment -Title "Block Authentication Transfer" -Status "MANUAL REVIEW REQUIRED" -Severity High -Summary "Conditional Access data was unavailable, so Authentication Transfer blocking could not be validated automatically" -Recommendation $caUnavailableRecommendation -Evidence $caUnavailableDetails
    Add-PolicyAssessment -Title "Require compliant devices or PAWs for privileged admins" -Status "MANUAL REVIEW REQUIRED" -Severity High -Summary "Conditional Access data was unavailable, so device compliance or PAW requirements for privileged admins could not be validated automatically" -Recommendation $caUnavailableRecommendation -Evidence $caUnavailableDetails
    Add-PolicyAssessment -Title "Token protection coverage" -Status "MANUAL REVIEW REQUIRED" -Severity Medium -Summary "Conditional Access data was unavailable, so token protection coverage could not be validated automatically" -Recommendation $caUnavailableRecommendation -Evidence $caUnavailableDetails
}
else {
    $securityInfoUserRiskPolicies = @(
        $rawConditionalAccessPolicies |
        Where-Object {
            (Test-PolicyTargetsUserAction -Policy $_ -UserAction $SecurityInfoRegistrationUserAction) -and
            (Test-PolicyHasBlockGrant -Policy $_) -and
            (Get-PolicyUserRiskLevels -Policy $_).Count -gt 0
        }
    )
    $securityInfoUserRiskConfigured = @(
        $securityInfoUserRiskPolicies |
        Where-Object {
            (Test-PolicyEnabled -Policy $_) -and
            (Test-CollectionContainsAll -Collection (Get-PolicyUserRiskLevels -Policy $_) -RequiredValues $AllRiskLevels)
        }
    )
    $securityInfoUserRiskPartial = @(
        $securityInfoUserRiskPolicies |
        Where-Object {
            (Test-PolicyReportOnly -Policy $_) -or
            ((Get-PolicyUserRiskLevels -Policy $_).Count -gt 0)
        }
    )

    if ($securityInfoUserRiskConfigured.Count -gt 0) {
        Add-PolicyAssessment -Title "Block security info registration for risky users" -Status "CONFIGURED" -Severity Medium -Summary "Security info registration is blocked for users at low, medium, and high user risk" -Recommendation "Keep this policy enabled and review exclusions regularly." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $securityInfoUserRiskConfigured -Columns @("DisplayName", "State", "IncludeUserActions", "UserRiskLevels", "GrantControls")) -MatchedPolicies $securityInfoUserRiskConfigured
    }
    elseif ($securityInfoUserRiskPartial.Count -gt 0) {
        Add-PolicyAssessment -Title "Block security info registration for risky users" -Status "PARTIALLY CONFIGURED" -Severity Medium -Summary "Security info registration risk-based blocking exists, but it does not clearly cover all user risk levels or is not fully enforced" -Recommendation "Target the security info registration user action and block access for low, medium, and high user risk with an enabled policy." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $securityInfoUserRiskPartial -Columns @("DisplayName", "State", "IncludeUserActions", "UserRiskLevels", "GrantControls")) -MatchedPolicies $securityInfoUserRiskPartial
    }
    else {
        Add-PolicyAssessment -Title "Block security info registration for risky users" -Status "MISSING" -Severity Medium -Summary "No policy found restricting security info registration for risky users" -Recommendation "Create an enabled Conditional Access policy for the security info registration user action that blocks low, medium, and high user risk." -Evidence @{ UserAction = $SecurityInfoRegistrationUserAction }
    }

    $securityInfoSignInRiskPolicies = @(
        $rawConditionalAccessPolicies |
        Where-Object {
            (Test-PolicyTargetsUserAction -Policy $_ -UserAction $SecurityInfoRegistrationUserAction) -and
            (Test-PolicyHasBlockGrant -Policy $_) -and
            (Get-PolicySignInRiskLevels -Policy $_).Count -gt 0
        }
    )
    $securityInfoSignInRiskConfigured = @(
        $securityInfoSignInRiskPolicies |
        Where-Object {
            (Test-PolicyEnabled -Policy $_) -and
            (Test-CollectionContainsAll -Collection (Get-PolicySignInRiskLevels -Policy $_) -RequiredValues $AllRiskLevels)
        }
    )
    $securityInfoSignInRiskPartial = @(
        $securityInfoSignInRiskPolicies |
        Where-Object {
            (Test-PolicyReportOnly -Policy $_) -or
            ((Get-PolicySignInRiskLevels -Policy $_).Count -gt 0)
        }
    )

    if ($securityInfoSignInRiskConfigured.Count -gt 0) {
        Add-PolicyAssessment -Title "Block security info registration for risky sign-ins" -Status "CONFIGURED" -Severity Medium -Summary "Security info registration is blocked for low, medium, and high sign-in risk" -Recommendation "Keep this policy enabled and review exclusions regularly." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $securityInfoSignInRiskConfigured -Columns @("DisplayName", "State", "IncludeUserActions", "SignInRiskLevels", "GrantControls")) -MatchedPolicies $securityInfoSignInRiskConfigured
    }
    elseif ($securityInfoSignInRiskPartial.Count -gt 0) {
        Add-PolicyAssessment -Title "Block security info registration for risky sign-ins" -Status "PARTIALLY CONFIGURED" -Severity Medium -Summary "Security info registration sign-in-risk blocking exists, but it does not clearly cover all sign-in risk levels or is not fully enforced" -Recommendation "Target the security info registration user action and block access for low, medium, and high sign-in risk with an enabled policy." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $securityInfoSignInRiskPartial -Columns @("DisplayName", "State", "IncludeUserActions", "SignInRiskLevels", "GrantControls")) -MatchedPolicies $securityInfoSignInRiskPartial
    }
    else {
        Add-PolicyAssessment -Title "Block security info registration for risky sign-ins" -Status "MISSING" -Severity Medium -Summary "No policy found restricting security info registration for risky sign-ins" -Recommendation "Create an enabled Conditional Access policy for the security info registration user action that blocks low, medium, and high sign-in risk." -Evidence @{ UserAction = $SecurityInfoRegistrationUserAction }
    }

    $highRiskUserPolicies = @(
        $rawConditionalAccessPolicies |
        Where-Object {
            (Test-PolicyHasBlockGrant -Policy $_) -and
            (Test-PolicyTargetsAllUsers -Policy $_) -and
            (Test-PolicyTargetsAllResources -Policy $_) -and
            ((Get-PolicyUserRiskLevels -Policy $_) -contains "high")
        }
    )
    $highRiskUserConfigured = @($highRiskUserPolicies | Where-Object { Test-PolicyEnabled -Policy $_ })
    $highRiskUserPartial = @(
        $rawConditionalAccessPolicies |
        Where-Object {
            ((Get-PolicyUserRiskLevels -Policy $_) -contains "high") -and
            ((Test-PolicyHasBlockGrant -Policy $_) -or (Test-PolicyReportOnly -Policy $_))
        }
    )

    if ($highRiskUserConfigured.Count -gt 0) {
        Add-PolicyAssessment -Title "Block high-risk users" -Status "CONFIGURED" -Severity High -Summary "High-risk users are blocked by an enabled Conditional Access policy" -Recommendation "Keep this policy enforced and make sure exclusions are tightly controlled." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $highRiskUserConfigured -Columns @("DisplayName", "State", "IncludeUsers", "IncludeApplications", "UserRiskLevels", "GrantControls")) -MatchedPolicies $highRiskUserConfigured
    }
    elseif ($highRiskUserPartial.Count -gt 0) {
        Add-PolicyAssessment -Title "Block high-risk users" -Status "PARTIALLY CONFIGURED" -Severity High -Summary "A high-risk user policy exists, but it is not clearly enforced for all users and all apps" -Recommendation "Use an enabled Conditional Access policy that blocks high-risk users across all users and all resources rather than relying on password change remediation alone." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $highRiskUserPartial -Columns @("DisplayName", "State", "IncludeUsers", "IncludeApplications", "UserRiskLevels", "GrantControls")) -MatchedPolicies $highRiskUserPartial
    }
    else {
        Add-PolicyAssessment -Title "Block high-risk users" -Status "MISSING" -Severity High -Summary "No Conditional Access policy found blocking high-risk users" -Recommendation "Create an enabled policy targeting all users and all cloud apps that blocks access when user risk is high." -Evidence @{ RequiredUserRisk = "high" }
    }

    $graphOrPowerShellPolicies = @(
        $rawConditionalAccessPolicies |
        Where-Object {
            (Test-PolicyHasBlockGrant -Policy $_) -and
            (
                (Test-PolicyTargetsAllResources -Policy $_) -or
                (Test-PolicyTargetsApplication -Policy $_ -ApplicationTargets @($MicrosoftGraphAppId, $WindowsAzureServiceManagementAppId))
            )
        }
    )
    $graphCoverage = @(
        $graphOrPowerShellPolicies |
        Where-Object {
            (Test-PolicyEnabled -Policy $_) -and
            (
                (Test-PolicyTargetsAllResources -Policy $_) -or
                (Test-PolicyTargetsApplication -Policy $_ -ApplicationTargets @($MicrosoftGraphAppId))
            )
        }
    )
    $powerShellCoverage = @(
        $graphOrPowerShellPolicies |
        Where-Object {
            (Test-PolicyEnabled -Policy $_) -and
            (
                (Test-PolicyTargetsAllResources -Policy $_) -or
                (Test-PolicyTargetsApplication -Policy $_ -ApplicationTargets @($WindowsAzureServiceManagementAppId))
            )
        }
    )
    $scopedApprovalPolicies = @($graphOrPowerShellPolicies | Where-Object { Test-PolicyHasScopedApprovalLogic -Policy $_ })

    if ($graphCoverage.Count -gt 0 -and $powerShellCoverage.Count -gt 0 -and $scopedApprovalPolicies.Count -gt 0) {
        Add-PolicyAssessment -Title "Restrict Microsoft Graph and PowerShell for unapproved users" -Status "CONFIGURED" -Severity High -Summary "Enabled policies appear to restrict Microsoft Graph and PowerShell access using scoped approval logic" -Recommendation "Keep this model documented and review approved-user scopes, exclusions, and break-glass handling regularly." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $graphOrPowerShellPolicies -Columns @("DisplayName", "State", "IncludeUsers", "IncludeApplications", "GrantControls")) -MatchedPolicies $graphOrPowerShellPolicies
    }
    elseif ($graphOrPowerShellPolicies.Count -gt 0) {
        Add-PolicyAssessment -Title "Restrict Microsoft Graph and PowerShell for unapproved users" -Status "PARTIALLY CONFIGURED" -Severity High -Summary "Policies targeting Microsoft Graph or PowerShell resources were found, but approved-user logic could not be fully confirmed" -Recommendation "Use enabled Conditional Access policies that explicitly target Microsoft Graph and Azure management or PowerShell resources and clearly scope access to approved users only." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $graphOrPowerShellPolicies -Columns @("DisplayName", "State", "IncludeUsers", "IncludeApplications", "GrantControls")) -MatchedPolicies $graphOrPowerShellPolicies
    }
    else {
        Add-PolicyAssessment -Title "Restrict Microsoft Graph and PowerShell for unapproved users" -Status "MISSING" -Severity High -Summary "No Conditional Access policy found restricting Microsoft Graph or PowerShell resources for unapproved users" -Recommendation "Target Microsoft Graph and Windows Azure Service Management API with enabled policies that enforce an approved-user model and block everyone else." -Evidence @{ Targets = @($MicrosoftGraphAppId, $WindowsAzureServiceManagementAppId) }
    }

    $adminPhishResistantPolicies = @(
        $rawConditionalAccessPolicies |
        Where-Object {
            (Test-PolicyEnabled -Policy $_) -and
            (Test-PolicyTargetsPrivilegedRoles -Policy $_ -PrivilegedRoleTemplateIds $privilegedRoleTemplateIds) -and
            (Test-PolicyHasPhishResistantAuthStrength -Policy $_)
        }
    )
    $adminPortalPhishPolicies = @(
        $rawConditionalAccessPolicies |
        Where-Object {
            (Test-PolicyEnabled -Policy $_) -and
            (
                (Test-PolicyTargetsAllResources -Policy $_) -or
                (Test-PolicyTargetsApplication -Policy $_ -ApplicationTargets @("MicrosoftAdminPortals"))
            ) -and
            (Test-PolicyHasPhishResistantAuthStrength -Policy $_)
        }
    )
    $azureManagementPhishPolicies = @(
        $rawConditionalAccessPolicies |
        Where-Object {
            (Test-PolicyEnabled -Policy $_) -and
            (
                (Test-PolicyTargetsAllResources -Policy $_) -or
                (Test-PolicyTargetsApplication -Policy $_ -ApplicationTargets @($WindowsAzureServiceManagementAppId))
            ) -and
            (Test-PolicyHasPhishResistantAuthStrength -Policy $_)
        }
    )
    $anyStrongAuthPolicies = @(
        $rawConditionalAccessPolicies |
        Where-Object {
            (
                (Test-PolicyTargetsPrivilegedRoles -Policy $_ -PrivilegedRoleTemplateIds $privilegedRoleTemplateIds) -or
                (Test-PolicyTargetsApplication -Policy $_ -ApplicationTargets @("MicrosoftAdminPortals", $WindowsAzureServiceManagementAppId)) -or
                (Test-PolicyTargetsAllResources -Policy $_)
            ) -and
            (
                (Test-PolicyHasPhishResistantAuthStrength -Policy $_) -or
                (Test-PolicyHasAnyAuthStrength -Policy $_)
            )
        }
    )

    if ($adminPhishResistantPolicies.Count -gt 0 -and $adminPortalPhishPolicies.Count -gt 0 -and $azureManagementPhishPolicies.Count -gt 0) {
        Add-PolicyAssessment -Title "Require phishing-resistant MFA for admin roles, admin portals, and Azure management" -Status "CONFIGURED" -Severity High -Summary "Enabled policies require phishing-resistant MFA across privileged roles, admin portals, and Azure management resources" -Recommendation "Keep these policies enabled and verify break-glass exclusions remain tightly controlled." -Evidence (Get-ConditionalAccessEvidenceRows -Policies (@($adminPhishResistantPolicies + $adminPortalPhishPolicies + $azureManagementPhishPolicies)) -Columns @("DisplayName", "State", "IncludeRoles", "IncludeApplications", "AuthenticationStrength", "GrantControls")) -MatchedPolicies (@($adminPhishResistantPolicies + $adminPortalPhishPolicies + $azureManagementPhishPolicies))
    }
    elseif ($anyStrongAuthPolicies.Count -gt 0) {
        Add-PolicyAssessment -Title "Require phishing-resistant MFA for admin roles, admin portals, and Azure management" -Status "PARTIALLY CONFIGURED" -Severity High -Summary "Strong authentication policies were found, but phishing-resistant MFA is not clearly enforced everywhere privileged access occurs" -Recommendation "Use enabled authentication strength policies that explicitly require phishing-resistant MFA for privileged roles, Microsoft admin portals, and Windows Azure Service Management API." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $anyStrongAuthPolicies -Columns @("DisplayName", "State", "IncludeRoles", "IncludeApplications", "AuthenticationStrength", "GrantControls")) -MatchedPolicies $anyStrongAuthPolicies
    }
    else {
        Add-PolicyAssessment -Title "Require phishing-resistant MFA for admin roles, admin portals, and Azure management" -Status "MISSING" -Severity High -Summary "No policy found requiring phishing-resistant MFA for privileged roles, admin portals, and Azure management" -Recommendation "Create enabled Conditional Access policies that enforce phishing-resistant authentication strength for privileged roles, Microsoft admin portals, and Windows Azure Service Management API." -Evidence @{ Targets = @("Privileged roles", "MicrosoftAdminPortals", $WindowsAzureServiceManagementAppId) }
    }

    $deviceCodeFlowPolicies = @(
        $rawConditionalAccessPolicies |
        Where-Object {
            (Test-PolicyHasBlockGrant -Policy $_) -and
            ((Get-PolicyTransferMethods -Policy $_) -contains "deviceCodeFlow")
        }
    )
    $deviceCodeFlowConfigured = @(
        $deviceCodeFlowPolicies |
        Where-Object {
            (Test-PolicyEnabled -Policy $_) -and
            (Test-PolicyTargetsAllUsers -Policy $_) -and
            (Test-PolicyTargetsAllResources -Policy $_)
        }
    )

    if ($deviceCodeFlowConfigured.Count -gt 0) {
        Add-PolicyAssessment -Title "Block Device Code Flow" -Status "CONFIGURED" -Severity High -Summary "Device Code Flow is blocked by an enabled Conditional Access policy" -Recommendation "Keep this policy enforced and review exclusions carefully." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $deviceCodeFlowConfigured -Columns @("DisplayName", "State", "IncludeUsers", "IncludeApplications", "AuthenticationFlows", "GrantControls")) -MatchedPolicies $deviceCodeFlowConfigured
    }
    elseif ($deviceCodeFlowPolicies.Count -gt 0) {
        Add-PolicyAssessment -Title "Block Device Code Flow" -Status "PARTIALLY CONFIGURED" -Severity High -Summary "A Device Code Flow blocking policy exists, but it is not clearly enforced for all users and all resources" -Recommendation "Use an enabled Conditional Access policy that blocks Device Code Flow for all users and all cloud apps." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $deviceCodeFlowPolicies -Columns @("DisplayName", "State", "IncludeUsers", "IncludeApplications", "AuthenticationFlows", "GrantControls")) -MatchedPolicies $deviceCodeFlowPolicies
    }
    else {
        Add-PolicyAssessment -Title "Block Device Code Flow" -Status "MISSING" -Severity High -Summary "No Conditional Access policy found blocking Device Code Flow" -Recommendation "Create an enabled policy targeting all users and all cloud apps that blocks the Device Code Flow authentication transfer method." -Evidence @{ TransferMethod = "deviceCodeFlow" }
    }

    $authenticationTransferPolicies = @(
        $rawConditionalAccessPolicies |
        Where-Object {
            (Test-PolicyHasBlockGrant -Policy $_) -and
            ((Get-PolicyTransferMethods -Policy $_) -contains "authenticationTransfer")
        }
    )
    $authenticationTransferConfigured = @(
        $authenticationTransferPolicies |
        Where-Object {
            (Test-PolicyEnabled -Policy $_) -and
            (Test-PolicyTargetsAllUsers -Policy $_) -and
            (Test-PolicyTargetsAllResources -Policy $_)
        }
    )

    if ($authenticationTransferConfigured.Count -gt 0) {
        Add-PolicyAssessment -Title "Block Authentication Transfer" -Status "CONFIGURED" -Severity High -Summary "Authentication Transfer is blocked by an enabled Conditional Access policy" -Recommendation "Keep this policy enforced and review exclusions carefully." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $authenticationTransferConfigured -Columns @("DisplayName", "State", "IncludeUsers", "IncludeApplications", "AuthenticationFlows", "GrantControls")) -MatchedPolicies $authenticationTransferConfigured
    }
    elseif ($authenticationTransferPolicies.Count -gt 0) {
        Add-PolicyAssessment -Title "Block Authentication Transfer" -Status "PARTIALLY CONFIGURED" -Severity High -Summary "An Authentication Transfer blocking policy exists, but it is not clearly enforced for all users and all resources" -Recommendation "Use an enabled Conditional Access policy that blocks Authentication Transfer for all users and all cloud apps." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $authenticationTransferPolicies -Columns @("DisplayName", "State", "IncludeUsers", "IncludeApplications", "AuthenticationFlows", "GrantControls")) -MatchedPolicies $authenticationTransferPolicies
    }
    else {
        Add-PolicyAssessment -Title "Block Authentication Transfer" -Status "MISSING" -Severity High -Summary "No Conditional Access policy found blocking Authentication Transfer" -Recommendation "Create an enabled policy targeting all users and all cloud apps that blocks the Authentication Transfer flow." -Evidence @{ TransferMethod = "authenticationTransfer" }
    }

    $adminDevicePolicies = @(
        $rawConditionalAccessPolicies |
        Where-Object {
            (Test-PolicyTargetsPrivilegedRoles -Policy $_ -PrivilegedRoleTemplateIds $privilegedRoleTemplateIds) -and
            (Test-PolicyRequiresCompliantDeviceOrPaw -Policy $_)
        }
    )
    $adminDeviceConfigured = @($adminDevicePolicies | Where-Object { Test-PolicyEnabled -Policy $_ })
    $broadDevicePolicies = @(
        $rawConditionalAccessPolicies |
        Where-Object {
            (Test-PolicyTargetsAllUsers -Policy $_) -and
            (Test-PolicyRequiresCompliantDeviceOrPaw -Policy $_)
        }
    )

    if ($adminDeviceConfigured.Count -gt 0) {
        Add-PolicyAssessment -Title "Require compliant devices or PAWs for privileged admins" -Status "CONFIGURED" -Severity High -Summary "Privileged admins are covered by an enabled device compliance or PAW-style Conditional Access policy" -Recommendation "Keep this policy enforced and validate privileged workstation standards regularly." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $adminDeviceConfigured -Columns @("DisplayName", "State", "IncludeRoles", "GrantControls", "RequiresCompliantDeviceOrPaw")) -MatchedPolicies $adminDeviceConfigured
    }
    elseif ($adminDevicePolicies.Count -gt 0 -or $broadDevicePolicies.Count -gt 0) {
        Add-PolicyAssessment -Title "Require compliant devices or PAWs for privileged admins" -Status "PARTIALLY CONFIGURED" -Severity High -Summary "Device compliance or PAW-style protection exists, but it does not clearly target privileged roles in an enforced state" -Recommendation "Use an enabled Conditional Access policy that targets privileged roles and requires compliant devices, hybrid joined devices, or a PAW-oriented device filter." -Evidence (Get-ConditionalAccessEvidenceRows -Policies (@($adminDevicePolicies + $broadDevicePolicies)) -Columns @("DisplayName", "State", "IncludeRoles", "IncludeUsers", "GrantControls", "RequiresCompliantDeviceOrPaw")) -MatchedPolicies (@($adminDevicePolicies + $broadDevicePolicies))
    }
    else {
        Add-PolicyAssessment -Title "Require compliant devices or PAWs for privileged admins" -Status "MISSING" -Severity High -Summary "No policy found requiring compliant devices or PAW-style access controls for privileged admins" -Recommendation "Create an enabled policy targeting privileged roles that requires compliant devices, hybrid joined devices, or an approved PAW device filter." -Evidence @{ Targets = "Privileged roles" }
    }

    $tokenProtectionPolicies = @(
        $rawConditionalAccessPolicies |
        Where-Object { [bool]$_.sessionControls.secureSignInSession.isEnabled }
    )
    $tokenProtectionConfigured = @($tokenProtectionPolicies | Where-Object { Test-PolicyEnabled -Policy $_ })
    $tokenProtectionReportOnly = @($tokenProtectionPolicies | Where-Object { Test-PolicyReportOnly -Policy $_ })

    if ($tokenProtectionConfigured.Count -gt 0) {
        Add-PolicyAssessment -Title "Token protection coverage" -Status "MANUAL REVIEW REQUIRED" -Severity Medium -Summary "Token protection policy found, but effective coverage could not be fully validated automatically" -Recommendation "Validate supported resources, Windows coverage, and sign-in telemetry to confirm token protection is effective where you expect it." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $tokenProtectionConfigured -Columns @("DisplayName", "State", "IncludeApplications", "HasSecureSignInSession")) -MatchedPolicies $tokenProtectionConfigured
    }
    elseif ($tokenProtectionReportOnly.Count -gt 0) {
        Add-PolicyAssessment -Title "Token protection coverage" -Status "PARTIALLY CONFIGURED" -Severity Medium -Summary "Token protection appears to be configured in report-only mode, but it is not enforced" -Recommendation "Move token protection coverage to enabled policies after validation and confirm supported resources and sign-in behavior." -Evidence (Get-ConditionalAccessEvidenceRows -Policies $tokenProtectionReportOnly -Columns @("DisplayName", "State", "IncludeApplications", "HasSecureSignInSession")) -MatchedPolicies $tokenProtectionReportOnly
    }
    else {
        Add-PolicyAssessment -Title "Token protection coverage" -Status "MISSING" -Severity Medium -Summary "No Conditional Access policy found enabling token protection" -Recommendation "Follow Microsoft's token protection deployment guidance and validate supported Windows and resource coverage in your tenant." -Evidence @{ SessionControl = "secureSignInSession" }
    }
}

$intuneScriptingAppExposure = @(
    $DangerousServicePrincipalPermissionsForExport |
    Where-Object {
        $_.Permission -match "DeviceManagementConfiguration\.ReadWrite\.All|DeviceManagementManagedDevices\.ReadWrite\.All|DeviceManagementManagedDevices\.PrivilegedOperations\.All"
    }
)
$intuneScriptingRbacExposure = @(
    $IntuneHighRiskRoleAssignments |
    Where-Object { $_.AllowedActions -match "script" }
)

if ($intuneScriptingAppExposure.Count -gt 0 -or $intuneScriptingRbacExposure.Count -gt 0) {
    Add-PolicyAssessment -Title "Intune scripting exposure paths" -Status "MISSING" -Severity High -Summary "Intune scripting exposure paths were detected" -Recommendation "Review app permissions and Intune RBAC assignments for script-capable or privileged Intune operations, and reduce them to approved admin paths only." -Evidence @{
        ApplicationPermissions = @($intuneScriptingAppExposure | Select-Object -First 25)
        IntuneRbacAssignments  = @($intuneScriptingRbacExposure | Select-Object -First 25)
    }
}
else {
    Add-PolicyAssessment -Title "Intune scripting exposure paths" -Status "CONFIGURED" -Severity Low -Summary "No obvious Intune scripting exposure paths were detected in the current app-permission and Intune RBAC checks" -Recommendation "Keep monitoring Intune script-capable roles, app permissions, and automation accounts as the environment changes." -Evidence @{
        ApplicationPermissions = @()
        IntuneRbacAssignments  = @()
    }
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
            Status         = $_.Status
            Recommendation = $_.Recommendation
            Details        = Format-Details -Details $_.Details
        }
    }
)

$identityHardeningPolicyChecksForCsv = @(
    $IdentityHardeningPolicyChecks |
    ForEach-Object {
        [PSCustomObject]@{
            Title           = $_.Title
            Status          = $_.Status
            Severity        = $_.Severity
            Summary         = $_.Summary
            Recommendation  = $_.Recommendation
            MatchedPolicies = $_.MatchedPolicies
            Evidence        = Format-Details -Details $_.Evidence
        }
    }
)

Export-ReportCsv -Path (Join-Path $resolvedOutputPath "Findings.csv") -Items $findingsForCsv
Export-ReportJson -Path (Join-Path $resolvedOutputPath "Findings.json") -Data @($Findings)
Export-ReportJson -Path (Join-Path $resolvedOutputPath "ManualReviewItems.json") -Data @($ManualReviewItems)
Export-ReportCsv -Path (Join-Path $resolvedOutputPath "IdentityHardeningPolicyChecks.csv") -Items $identityHardeningPolicyChecksForCsv
Export-ReportJson -Path (Join-Path $resolvedOutputPath "IdentityHardeningPolicyChecks.json") -Data @($IdentityHardeningPolicyChecks)

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
    ConfiguredPolicyChecksCount = @($IdentityHardeningPolicyChecks | Where-Object { $_.Status -eq "CONFIGURED" }).Count
    MissingPolicyChecksCount = @($IdentityHardeningPolicyChecks | Where-Object { $_.Status -eq "MISSING" }).Count
    PartialPolicyChecksCount = @($IdentityHardeningPolicyChecks | Where-Object { $_.Status -eq "PARTIALLY CONFIGURED" }).Count
    ManualReviewPolicyChecksCount = @($IdentityHardeningPolicyChecks | Where-Object { $_.Status -eq "MANUAL REVIEW REQUIRED" }).Count
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

Write-Host "==== Identity Hardening Policies Most Tenants Miss ====" -ForegroundColor Cyan
if ($IdentityHardeningPolicyChecks.Count -eq 0) {
    Write-Host "[OK] No identity hardening policy assessments were generated." -ForegroundColor Green
}
else {
    foreach ($assessment in $IdentityHardeningPolicyChecks) {
        $color = switch ($assessment.Status) {
            "CONFIGURED" { "Green" }
            "MISSING" { "Red" }
            "PARTIALLY CONFIGURED" { "Yellow" }
            default { "Cyan" }
        }

        Write-Host "[$($assessment.Status)] [$($assessment.Severity)] $($assessment.Title)" -ForegroundColor $color
        Write-Host "  Summary : $($assessment.Summary)" -ForegroundColor Gray
        if (-not [string]::IsNullOrWhiteSpace($assessment.MatchedPolicies)) {
            Write-Host "  Policies: $($assessment.MatchedPolicies)" -ForegroundColor Gray
        }
        Write-Host "  Action  : $($assessment.Recommendation)`n" -ForegroundColor Gray
    }
}

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

        if ([string]::IsNullOrWhiteSpace($finding.Status)) {
            Write-Host "[$($finding.Severity)] $($finding.Title)" -ForegroundColor $color
        }
        else {
            Write-Host "[$($finding.Status)] [$($finding.Severity)] $($finding.Title)" -ForegroundColor $color
        }
        Write-Host "  Category: $($finding.Category)" -ForegroundColor Gray
        Write-Host "  Details : $(Format-Details -Details $finding.Details)" -ForegroundColor Gray
        Write-Host "  Action  : $($finding.Recommendation)`n" -ForegroundColor Gray
    }
}

Write-Host "[+] Reports written to: $resolvedOutputPath" -ForegroundColor Cyan
Write-Host "[+] Assessment complete.`n" -ForegroundColor Cyan
