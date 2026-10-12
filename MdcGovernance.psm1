#Requires -Modules Az.Accounts

# Manage Microsoft Defender for Cloud (MDC) governance rules via the Azure REST API.
#
# Example usage:
#   Import-Module .\MdcGovernance.psm1
#   Get-MdcGovernanceRule -All
#   Get-MdcGovernanceRule -SubscriptionId $sub -RuleId $ruleId
#   New-MdcGovernanceRule -DisplayName 'Critical/High findings' -RulePriority 180 -OwnerEmail 'user@contoso.com' `
#       -RemediationTimeframe (New-TimeSpan -Days 7) -GracePeriod `
#       -Condition @{ Property = 'properties.risk.level'; Operator = 'In'; Value = 'Critical', 'High' }
#   Get-MdcGovernanceRule -SubscriptionId $src -RuleId $ruleId | New-MdcGovernanceRule -SubscriptionId $dest
#   Set-MdcGovernanceRule -RuleId $ruleId -Disabled
#   Get-MdcGovernanceRule -All | Where-Object { $_.properties.isDisabled } | Remove-MdcGovernanceRule
#
# API documentation
# https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/governance-rules?view=rest-defenderforcloud-composite-preview

$script:ArmEndpoint = 'https://management.azure.com'
$script:ApiVersion = '2022-01-01-preview'

#region Private helpers

function Get-MdcAuthHeader {
    param ([string]$TenantId)

    $context = Get-AzContext -ErrorAction SilentlyContinue
    if (-not $context) {
        throw "No Azure context found. Run Connect-AzAccount$(if ($TenantId) { " -TenantId $TenantId" }) and try again."
    }

    $tokenParams = @{ ResourceUrl = "$script:ArmEndpoint/"; ErrorAction = 'Stop'; WarningAction = 'SilentlyContinue' }
    if ($TenantId) { $tokenParams.TenantId = $TenantId }

    try {
        $armToken = Get-AzAccessToken @tokenParams -AsSecureString
    }
    catch {
        $message = $_.Exception.Message
        $loginHint = "Connect-AzAccount -TenantId $(if ($TenantId) { $TenantId } else { $context.Tenant.Id })"

        if ($message -match 'interaction (is )?required|InteractionRequired|AADSTS50076|AADSTS50079|AADSTS50158|AADSTS53003') {
            throw "Interactive authentication (e.g. MFA or Conditional Access) is required. Re-authenticate with: $loginHint (add -UseDeviceAuthentication if a browser is unavailable). Details: $message"
        }
        if ($message -match 'AADSTS700082|AADSTS70043|expired|refresh token') {
            throw "Your Azure session has expired. Re-authenticate with: $loginHint. Details: $message"
        }
        throw "Failed to acquire an ARM access token: $message"
    }

    # Token type differs across Az.Accounts versions (SecureString vs string).
    $plainTextToken = if ($armToken.Token -is [securestring]) {
        [System.Net.NetworkCredential]::new('', $armToken.Token).Password
    }
    else {
        $armToken.Token
    }

    @{ Authorization = "Bearer $plainTextToken" }
}

function Resolve-MdcScope {
    param ([string]$SubscriptionId, [string]$ManagementGroupId, [string]$Scope)

    if (@($SubscriptionId, $ManagementGroupId, $Scope).Where({ $_ }).Count -gt 1) {
        throw 'Specify only one of -SubscriptionId, -ManagementGroupId or -Scope.'
    }
    if ($SubscriptionId) { return "subscriptions/$SubscriptionId" }
    if ($ManagementGroupId) { return "providers/Microsoft.Management/managementGroups/$ManagementGroupId" }
    if ($Scope) { return $Scope.Trim('/') }

    $contextSubscriptionId = (Get-AzContext).Subscription.Id
    if (-not $contextSubscriptionId) {
        throw 'No scope specified and the current Azure context has no subscription. Use -SubscriptionId, -ManagementGroupId or -Scope.'
    }
    Write-Verbose "No scope specified; using current context subscription $contextSubscriptionId."
    "subscriptions/$contextSubscriptionId"
}

function Get-MdcRuleUri {
    param ([string]$ScopePath, [string]$RuleId)

    $uri = "$script:ArmEndpoint/$ScopePath/providers/Microsoft.Security/governanceRules"
    if ($RuleId) { $uri += "/$RuleId" }
    "$uri`?api-version=$script:ApiVersion"
}

function Split-MdcRuleResourceId {
    param ([string]$ResourceId)

    if ($ResourceId -match '^/?(?<scope>.+?)/providers/Microsoft\.Security/governanceRules/(?<ruleId>[^/]+)$') {
        return [pscustomobject]@{ ScopePath = $Matches.scope; RuleId = $Matches.ruleId }
    }
    throw "'$ResourceId' is not a governance rule resource ID."
}

function Invoke-MdcRequest {
    param (
        [Parameter(Mandatory)][ValidateSet('GET', 'PUT', 'DELETE')][string]$Method,
        [Parameter(Mandatory)][string]$Uri,
        [Parameter(Mandatory)][hashtable]$Headers,
        [object]$Body,
        # Return $null instead of throwing on HTTP 404.
        [switch]$AllowNotFound
    )

    $requestParams = @{ Uri = $Uri; Method = $Method; Headers = $Headers; UseBasicParsing = $true; ErrorAction = 'Stop' }
    if ($null -ne $Body) {
        $requestParams.Body = ConvertTo-Json -InputObject $Body -Depth 20
        $requestParams.ContentType = 'application/json; charset=utf-8'
    }

    Write-Verbose "$Method $Uri"
    try {
        $response = Invoke-WebRequest @requestParams
    }
    catch {
        $statusCode = [int]$_.Exception.Response.StatusCode
        if ($AllowNotFound -and $statusCode -eq 404) { return $null }

        $detail = if ($_.ErrorDetails.Message) { $_.ErrorDetails.Message } else { $_.Exception.Message }
        $armError = try { (ConvertFrom-Json -InputObject $detail -ErrorAction Stop).error } catch { $null }
        if ($armError) { $detail = "$($armError.code): $($armError.message)" }

        $reason = switch ($statusCode) {
            { $_ -in 400, 409 -and $detail -match 'priority' } { 'Another governance rule on this scope already uses this priority. Choose a different -RulePriority.'; break }
            400 { 'Bad request - check the rule properties against the API schema.' }
            401 { 'Unauthorized - the access token is invalid or expired. Run Connect-AzAccount and retry.' }
            403 { 'Forbidden - reading rules requires Security Reader; creating, updating or deleting typically requires Security Admin.' }
            404 { 'Not found - the rule or scope does not exist, or Microsoft.Security is not registered.' }
            409 { 'Conflict - the rule was modified concurrently or conflicts with an existing rule.' }
            429 { 'Throttled by ARM - wait and retry.' }
            default { 'Request failed.' }
        }

        throw "$Method $(([uri]$Uri).AbsolutePath) failed (HTTP $statusCode): $reason`n$detail"
    }

    [pscustomobject]@{
        StatusCode = [int]$response.StatusCode
        Headers    = $response.Headers
        Content    = if ($response.Content) { ConvertFrom-Json -InputObject $response.Content } else { $null }
    }
}

function ConvertTo-MdcCondition {
    param ([hashtable[]]$Condition)

    foreach ($item in $Condition) {
        if (-not $item.Property -or $null -eq $item.Value) {
            throw "Each -Condition needs Property and Value keys, e.g. @{ Property = 'properties.risk.level'; Operator = 'In'; Value = 'Critical', 'High' }"
        }

        # The API expects value as a JSON-encoded array string; pass through if already encoded.
        $value = if ($item.Value -is [string] -and $item.Value.TrimStart().StartsWith('[')) {
            $item.Value
        }
        else {
            ConvertTo-Json -InputObject @($item.Value) -Compress
        }

        [ordered]@{
            property = $item.Property
            operator = if ($item.Operator) { $item.Operator } else { 'In' }
            value    = $value
        }
    }
}

function ConvertTo-MdcRuleProperties {
    param ([object]$InputObject)

    $properties = [ordered]@{}
    if ($null -eq $InputObject) { return $properties }

    $source = if ($null -ne $InputObject.properties) { $InputObject.properties } else { $InputObject }
    if ($source -is [System.Collections.IDictionary]) {
        foreach ($key in $source.Keys) { $properties[$key] = $source[$key] }
    }
    else {
        foreach ($property in $source.PSObject.Properties) { $properties[$property.Name] = $property.Value }
    }

    # Read-only fields returned by GET that the PUT API does not accept.
    foreach ($key in 'metadata', 'tenantId') { $properties.Remove($key) }

    $properties
}

function Update-MdcRuleProperties {
    param (
        [System.Collections.IDictionary]$Properties,
        [System.Collections.IDictionary]$BoundParameters
    )

    $bound = $BoundParameters
    if ($bound.ContainsKey('OwnerEmail') -and $bound.ContainsKey('OwnerTag')) {
        throw 'Specify either -OwnerEmail or -OwnerTag, not both.'
    }

    $valueMap = @{ DisplayName = 'displayName'; Description = 'description'; RulePriority = 'rulePriority'; RuleType = 'ruleType'; ExcludedScopes = 'excludedScopes' }
    foreach ($name in $valueMap.Keys) {
        if ($bound.ContainsKey($name)) { $Properties[$valueMap[$name]] = $bound[$name] }
    }

    $switchMap = @{ GracePeriod = 'isGracePeriod'; Disabled = 'isDisabled'; IncludeMemberScopes = 'includeMemberScopes' }
    foreach ($name in $switchMap.Keys) {
        if ($bound.ContainsKey($name)) { $Properties[$switchMap[$name]] = [bool]$bound[$name] }
    }

    if ($bound.ContainsKey('RemediationTimeframe')) {
        $timeframe = $bound['RemediationTimeframe']
        $Properties['remediationTimeframe'] = '{0}.{1:hh\:mm\:ss}' -f $timeframe.Days, $timeframe
    }

    if ($bound.ContainsKey('OwnerEmail')) { $Properties['ownerSource'] = [ordered]@{ type = 'Manually'; value = $bound['OwnerEmail'] } }
    if ($bound.ContainsKey('OwnerTag')) { $Properties['ownerSource'] = [ordered]@{ type = 'ByTag'; value = $bound['OwnerTag'] } }

    if ($bound.ContainsKey('DisableOwnerEmail') -or $bound.ContainsKey('DisableManagerEmail')) {
        $current = $Properties['governanceEmailNotification']
        $Properties['governanceEmailNotification'] = [ordered]@{
            disableManagerEmailNotification = if ($bound.ContainsKey('DisableManagerEmail')) { [bool]$bound['DisableManagerEmail'] } else { [bool]$current.disableManagerEmailNotification }
            disableOwnerEmailNotification   = if ($bound.ContainsKey('DisableOwnerEmail')) { [bool]$bound['DisableOwnerEmail'] } else { [bool]$current.disableOwnerEmailNotification }
        }
    }

    if ($bound.ContainsKey('Condition')) {
        $Properties['conditionSets'] = @(@{ conditions = @(ConvertTo-MdcCondition -Condition $bound['Condition']) })
    }

    if (-not $Properties['ruleType']) { $Properties['ruleType'] = 'Integrated' }
    if (-not $Properties['sourceResourceType']) { $Properties['sourceResourceType'] = 'Assessments' }
}

#endregion

#region Public functions

function Get-MdcGovernanceRule {
    [CmdletBinding(DefaultParameterSetName = 'ByRuleId')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'ByRuleId')]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$RuleId,

        [Parameter(Mandatory, ParameterSetName = 'All')]
        [switch]$All,

        # Defaults to the current context subscription when no scope is given.
        [Parameter(ValueFromPipeline, ValueFromPipelineByPropertyName)]
        [Alias('Id')]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$SubscriptionId,

        [string]$ManagementGroupId,

        # Any ARM scope, e.g. a security connector resource ID.
        [ValidatePattern('^/?(subscriptions|providers)/')]
        [string]$Scope,

        [string]$TenantId
    )

    begin {
        $authHeader = Get-MdcAuthHeader -TenantId $TenantId
    }

    process {
        try {
            $scopePath = Resolve-MdcScope -SubscriptionId $SubscriptionId -ManagementGroupId $ManagementGroupId -Scope $Scope

            if ($PSCmdlet.ParameterSetName -eq 'ByRuleId') {
                (Invoke-MdcRequest -Method GET -Uri (Get-MdcRuleUri -ScopePath $scopePath -RuleId $RuleId) -Headers $authHeader).Content
            }
            else {
                $uri = Get-MdcRuleUri -ScopePath $scopePath
                do {
                    $response = (Invoke-MdcRequest -Method GET -Uri $uri -Headers $authHeader).Content
                    $response.value
                    $uri = $response.nextLink
                } while ($uri)
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }

    end {
        $authHeader = $null
    }
}

function New-MdcGovernanceRule {
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'OwnerEmail')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'OwnerEmail')]
        [Parameter(Mandatory, ParameterSetName = 'OwnerTag')]
        [Parameter(ParameterSetName = 'InputObject')]
        [string]$DisplayName,

        # Lower number = higher priority; must be unique per scope.
        [Parameter(Mandatory, ParameterSetName = 'OwnerEmail')]
        [Parameter(Mandatory, ParameterSetName = 'OwnerTag')]
        [Parameter(ParameterSetName = 'InputObject')]
        [ValidateRange(0, 1000)]
        [int]$RulePriority,

        # Hashtables with Property, Value and optional Operator (default 'In'); all must match (AND).
        [Parameter(Mandatory, ParameterSetName = 'OwnerEmail')]
        [Parameter(Mandatory, ParameterSetName = 'OwnerTag')]
        [Parameter(ParameterSetName = 'InputObject')]
        [hashtable[]]$Condition,

        [Parameter(Mandatory, ParameterSetName = 'OwnerEmail')]
        [Parameter(ParameterSetName = 'InputObject')]
        [string]$OwnerEmail,

        # Name of the resource tag holding the owner's email.
        [Parameter(Mandatory, ParameterSetName = 'OwnerTag')]
        [Parameter(ParameterSetName = 'InputObject')]
        [string]$OwnerTag,

        # Full rule (e.g. from Get-MdcGovernanceRule), a properties hashtable, or JSON; other parameters override its values.
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'InputObject')]
        [Alias('Body')]
        [object]$InputObject,

        [string]$Description,
        [timespan]$RemediationTimeframe,
        [switch]$GracePeriod,
        [switch]$Disabled,
        [switch]$DisableOwnerEmail,
        [switch]$DisableManagerEmail,
        [ValidateSet('Integrated', 'ServiceNow')]
        [string]$RuleType,
        [string[]]$ExcludedScopes,
        [switch]$IncludeMemberScopes,

        # Defaults to a new GUID.
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$RuleId,

        # Defaults to the current context subscription when no scope is given.
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$SubscriptionId,

        [string]$ManagementGroupId,

        [ValidatePattern('^/?(subscriptions|providers)/')]
        [string]$Scope,

        [string]$TenantId
    )

    begin {
        $authHeader = Get-MdcAuthHeader -TenantId $TenantId
    }

    process {
        try {
            if ($InputObject -is [string]) { $InputObject = ConvertFrom-Json -InputObject $InputObject }

            $scopePath = Resolve-MdcScope -SubscriptionId $SubscriptionId -ManagementGroupId $ManagementGroupId -Scope $Scope
            $newRuleId = if ($RuleId) { $RuleId } else { [guid]::NewGuid().Guid }

            $properties = ConvertTo-MdcRuleProperties -InputObject $InputObject
            Update-MdcRuleProperties -Properties $properties -BoundParameters $PSBoundParameters

            $missing = 'displayName', 'rulePriority', 'ownerSource', 'conditionSets' | Where-Object { $null -eq $properties[$_] }
            if ($missing) { throw "Missing required rule properties: $($missing -join ', ')." }

            $uri = Get-MdcRuleUri -ScopePath $scopePath -RuleId $newRuleId
            if (Invoke-MdcRequest -Method GET -Uri $uri -Headers $authHeader -AllowNotFound) {
                throw "Governance rule $newRuleId already exists at /$scopePath. Use Set-MdcGovernanceRule to update it."
            }

            if ($PSCmdlet.ShouldProcess("/$scopePath", "Create governance rule '$($properties['displayName'])' ($newRuleId)")) {
                (Invoke-MdcRequest -Method PUT -Uri $uri -Headers $authHeader -Body @{ properties = $properties }).Content
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }

    end {
        $authHeader = $null
    }
}

function Set-MdcGovernanceRule {
    [CmdletBinding(SupportsShouldProcess, DefaultParameterSetName = 'ByRuleId')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'ByRuleId')]
        [Parameter(ParameterSetName = 'InputObject')]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$RuleId,

        # Full replacement rule (e.g. a modified Get-MdcGovernanceRule result); target is taken from its id unless -RuleId is given.
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'InputObject')]
        [Alias('Body')]
        [object]$InputObject,

        [string]$DisplayName,
        [ValidateRange(0, 1000)]
        [int]$RulePriority,
        [hashtable[]]$Condition,
        [string]$OwnerEmail,
        [string]$OwnerTag,
        [string]$Description,
        [timespan]$RemediationTimeframe,
        [switch]$GracePeriod,
        [switch]$Disabled,
        [switch]$DisableOwnerEmail,
        [switch]$DisableManagerEmail,
        [ValidateSet('Integrated', 'ServiceNow')]
        [string]$RuleType,
        [string[]]$ExcludedScopes,
        [switch]$IncludeMemberScopes,

        # Defaults to the current context subscription when no scope is given.
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$SubscriptionId,

        [string]$ManagementGroupId,

        [ValidatePattern('^/?(subscriptions|providers)/')]
        [string]$Scope,

        [string]$TenantId
    )

    begin {
        $authHeader = Get-MdcAuthHeader -TenantId $TenantId
    }

    process {
        try {
            if ($InputObject -is [string]) { $InputObject = ConvertFrom-Json -InputObject $InputObject }

            if ($RuleId) {
                $targetRuleId = $RuleId
                $scopePath = Resolve-MdcScope -SubscriptionId $SubscriptionId -ManagementGroupId $ManagementGroupId -Scope $Scope
            }
            elseif ($InputObject.id) {
                $target = Split-MdcRuleResourceId -ResourceId $InputObject.id
                $targetRuleId = $target.RuleId
                $scopePath = $target.ScopePath
            }
            else {
                throw 'Cannot determine which rule to update: -InputObject has no id. Specify -RuleId.'
            }

            $uri = Get-MdcRuleUri -ScopePath $scopePath -RuleId $targetRuleId
            $properties = if ($PSCmdlet.ParameterSetName -eq 'InputObject') {
                ConvertTo-MdcRuleProperties -InputObject $InputObject
            }
            else {
                ConvertTo-MdcRuleProperties -InputObject (Invoke-MdcRequest -Method GET -Uri $uri -Headers $authHeader).Content
            }
            Update-MdcRuleProperties -Properties $properties -BoundParameters $PSBoundParameters

            if ($PSCmdlet.ShouldProcess("/$scopePath", "Update governance rule '$($properties['displayName'])' ($targetRuleId)")) {
                (Invoke-MdcRequest -Method PUT -Uri $uri -Headers $authHeader -Body @{ properties = $properties }).Content
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }

    end {
        $authHeader = $null
    }
}

function Remove-MdcGovernanceRule {
    [CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High', DefaultParameterSetName = 'ByRuleId')]
    param (
        [Parameter(Mandatory, ParameterSetName = 'ByRuleId')]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$RuleId,

        # Rule object from Get-MdcGovernanceRule.
        [Parameter(Mandatory, ValueFromPipeline, ParameterSetName = 'InputObject')]
        [object]$InputObject,

        # Defaults to the current context subscription when no scope is given.
        [Parameter(ParameterSetName = 'ByRuleId')]
        [ValidatePattern('^[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}$')]
        [string]$SubscriptionId,

        [Parameter(ParameterSetName = 'ByRuleId')]
        [string]$ManagementGroupId,

        [Parameter(ParameterSetName = 'ByRuleId')]
        [ValidatePattern('^/?(subscriptions|providers)/')]
        [string]$Scope,

        [string]$TenantId
    )

    begin {
        $authHeader = Get-MdcAuthHeader -TenantId $TenantId
    }

    process {
        try {
            if ($PSCmdlet.ParameterSetName -eq 'InputObject') {
                $target = Split-MdcRuleResourceId -ResourceId $InputObject.id
                $targetRuleId = $target.RuleId
                $scopePath = $target.ScopePath
                $label = "'$($InputObject.properties.displayName)' ($targetRuleId)"
            }
            else {
                $targetRuleId = $RuleId
                $scopePath = Resolve-MdcScope -SubscriptionId $SubscriptionId -ManagementGroupId $ManagementGroupId -Scope $Scope
                $label = $targetRuleId
            }

            if (-not $PSCmdlet.ShouldProcess("/$scopePath", "Delete governance rule $label")) { return }

            $response = Invoke-MdcRequest -Method DELETE -Uri (Get-MdcRuleUri -ScopePath $scopePath -RuleId $targetRuleId) -Headers $authHeader

            if ($response.StatusCode -eq 204) {
                Write-Warning "Governance rule $targetRuleId does not exist at /$scopePath."
                return
            }

            # 202 = deletion is asynchronous; poll the Location header until it completes.
            $deadline = (Get-Date).AddMinutes(5)
            while ($response.StatusCode -eq 202 -and (Get-Date) -lt $deadline) {
                $location = [string]($response.Headers['Location'] | Select-Object -First 1)
                if (-not $location) { break }

                $retryAfter = 0
                if (-not [int]::TryParse([string]($response.Headers['Retry-After'] | Select-Object -First 1), [ref]$retryAfter) -or $retryAfter -le 0) {
                    $retryAfter = 5
                }
                Start-Sleep -Seconds $retryAfter
                $response = Invoke-MdcRequest -Method GET -Uri $location -Headers $authHeader
            }

            if ($response.StatusCode -eq 202) {
                Write-Warning "Deletion of governance rule $targetRuleId was accepted but has not completed yet."
            }
            else {
                Write-Verbose "Deleted governance rule $targetRuleId from /$scopePath."
            }
        }
        catch {
            $PSCmdlet.WriteError($_)
        }
    }

    end {
        $authHeader = $null
    }
}

#endregion

Export-ModuleMember -Function Get-MdcGovernanceRule, New-MdcGovernanceRule, Set-MdcGovernanceRule, Remove-MdcGovernanceRule
