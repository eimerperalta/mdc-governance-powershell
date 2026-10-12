# MDC Governance Rules

A PowerShell module for managing **Microsoft Defender for Cloud (MDC) governance rules** through the Azure REST API. Create, view, update, and remove rules without building REST requests yourself.

Rules let you assign remediation owners, set remediation timeframes, and target findings using conditions such as risk level.

## Get Started

You'll need PowerShell, the `Az.Accounts` module, and an Azure account with access to your target scope. Reading rules requires Security Reader permissions; creating, updating, and deleting typically requires Security Admin permissions (or equivalent).

From the cloned repository folder, install the dependency, sign in, and import the module:

```powershell
Install-Module Az.Accounts -Scope CurrentUser
Connect-AzAccount
Set-AzContext -Subscription '<subscription-id>'
Import-Module .\MdcGovernance.psm1
```

List the rules in your current subscription:

```powershell
Get-MdcGovernanceRule -All
```

## Commands

| Command | What it does |
| --- | --- |
| `Get-MdcGovernanceRule` | Lists all rules with `-All`, or retrieves one with `-RuleId`. |
| `New-MdcGovernanceRule` | Creates a rule with a new GUID, or an explicit `-RuleId`. Refuses to overwrite an existing rule. |
| `Set-MdcGovernanceRule` | Updates selected settings, or replaces properties using `-InputObject`. |
| `Remove-MdcGovernanceRule` | Deletes a rule, with confirmation by default. |

## Create a Rule

This example assigns critical and high-risk findings to an owner with a seven-day remediation timeframe and a grace period:

```powershell
$rule = New-MdcGovernanceRule `
  -DisplayName 'Critical and high-risk findings' `
  -RulePriority 180 `
  -OwnerEmail 'owner@contoso.com' `
  -RemediationTimeframe (New-TimeSpan -Days 7) `
  -GracePeriod `
  -Condition @{ Property = 'properties.risk.level'; Operator = 'In'; Value = 'Critical', 'High' }
```

Lower priority numbers take precedence, and each priority must be unique within its scope. To look up the owner's email from a resource tag, use `-OwnerTag 'OwnerEmail'` instead of `-OwnerEmail`. Multiple conditions are combined with AND; the default operator is `In`.

## Update, Copy, or Delete

Use the rule returned above to retrieve it or preview changes:

```powershell
Get-MdcGovernanceRule -RuleId $rule.name
Set-MdcGovernanceRule -RuleId $rule.name -Disabled -WhatIf
Remove-MdcGovernanceRule -RuleId $rule.name -WhatIf
```

Remove `-WhatIf` when you're ready to apply the change. To re-enable a rule, use `-Disabled:$false`.

You can also copy a rule to another subscription. The copy gets a new GUID; its priority must be available in the destination scope:

```powershell
Get-MdcGovernanceRule -SubscriptionId '<source-subscription-id>' -RuleId '<rule-id>' |
  New-MdcGovernanceRule -SubscriptionId '<destination-subscription-id>'
```

## Scopes and Notes

- Commands default to your current Azure subscription. Choose one of `-SubscriptionId`, `-ManagementGroupId`, or `-Scope` to target another scope. `-Scope` accepts an ARM scope path, such as a security connector resource ID.
- Use `-TenantId` for token acquisition in a specific tenant. If authentication expires or requires MFA, sign in again with `Connect-AzAccount -TenantId '<tenant-id>'`.
- Add `-Verbose` for request details. `-WhatIf` prevents writes, but authentication and prerequisite reads can still occur.
- The module uses the **2022-01-01-preview** API. See the [Azure REST API reference](https://learn.microsoft.com/en-us/rest/api/defenderforcloud-composite/governance-rules?view=rest-defenderforcloud-composite-preview) for supported rule properties and scope details.
