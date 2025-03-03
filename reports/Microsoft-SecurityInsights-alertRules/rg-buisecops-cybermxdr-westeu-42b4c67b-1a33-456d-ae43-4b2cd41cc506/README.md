# Multiple admin membership removals from newly created admin.

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/42b4c67b-1a33
  -456d-ae43-4b2cd41cc506
 
 name: '42b4c67b-1a33-456d-ae43-4b2cd41cc506' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'P7D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   incidentConfiguration: 
     createIncident: true 
     groupingConfiguration: 
       enabled: null 
       reopenClosedIncident: null 
       lookbackDuration: 'PT5M' 
       matchingMethod: 'AllEntities' 
       groupByEntities: null 
       groupByAlertDetails: null 
       groupByCustomDetails: null 
   entityMappings: 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'Name' 
         columnName: 'Name' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'UPNSuffix' 
   severity: 'Medium' 
   query: >
    let lookback = 7d;
    let timeframe = 1h;
    let GlobalAdminsRemoved = AuditLogs
    | where TimeGenerated > ago(timeframe)
    | where Category =~ "RoleManagement"
    | where AADOperationType in ("Unassign", "RemoveEligibleRole")
    | where ActivityDisplayName has_any ("Remove member from role", "Remove eligible
    member from role")
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type =~ "User"
    | extend Target = tostring(TargetResource.userPrincipalName),
    props = TargetResource.modifiedProperties
    )
    | mv-apply Property = props on
    (
    where Property.displayName =~ "Role.DisplayName"
    | extend RoleName = trim('"',tostring(Property.oldValue))
    )
    | where RoleName =~ "Global Administrator" // Add other Privileged role if applicable
    
    | extend InitiatingApp = tostring(InitiatedBy.app.displayName)
    | extend Initiator = iif(isnotempty(InitiatingApp), InitiatingApp, tostring(Init
    iatedBy.user.userPrincipalName))
    | where Initiator != "MS-PIM"  // Filtering PIM events
    | summarize RemovedGlobalAdminTime = max(TimeGenerated), TargetAdmins =
    make_set(Target,100) by OperationName,  RoleName, Initiator, Result;
    let GlobalAdminsAdded = AuditLogs
    | where TimeGenerated > ago(lookback)
    | where Category =~ "RoleManagement"
    | where AADOperationType in ("Assign", "AssignEligibleRole")
    | where ActivityDisplayName has_any ("Add eligible member to role", "Add member
    to role") and Result == "success"
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type =~ "User"
    | extend Target = tostring(TargetResource.userPrincipalName),
    props = TargetResource.modifiedProperties
    )
    | mv-apply Property = props on
    (
    where Property.displayName =~ "Role.DisplayName"
    | extend RoleName = trim('"',tostring(Property.newValue))
    )
    | where RoleName =~ "Global Administrator" // Add other Privileged role if applicable
    
    | extend InitiatingApp = tostring(InitiatedBy.app.displayName)
    | extend Initiator = iif(isnotempty(InitiatingApp), InitiatingApp, tostring(Init
    iatedBy.user.userPrincipalName))
    | where Initiator != "MS-PIM"  // Filtering PIM events
    | summarize AddedGlobalAdminTime = max(TimeGenerated) by OperationName,  RoleName,
    Target, Initiator, Result
    | extend AccountCustomEntity = Target;
    GlobalAdminsAdded
    | join kind= inner GlobalAdminsRemoved on $left.Target == $right.Initiator
    | where AddedGlobalAdminTime < RemovedGlobalAdminTime
    | extend NoofAdminsRemoved = array_length(TargetAdmins)
    | where NoofAdminsRemoved > 1
    | project AddedGlobalAdminTime, Initiator, Target, AccountCustomEntity,
    RemovedGlobalAdminTime, TargetAdmins, NoofAdminsRemoved
    | extend Name = tostring(split(AccountCustomEntity,'@',0)[0]), UPNSuffix = tostr
    ing(split(AccountCustomEntity,'@',1)[0])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: 
    - 'T1531' 
   displayName: 'Multiple admin membership removals from newly created admin.' 
   enabled: true 
   description: >
    This query detects when newly created Global admin removes multiple existing global
    admins which can be an attempt by adversaries to lock down organization and retain
    sole access.
    Investigate reasoning and intention of multiple membership removal by new Global
    admins and take necessary actions accordingly.
 
   alertRuleTemplateName: 'cda5928c-2c1e-4575-9dfa-07568bc27a4f' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
