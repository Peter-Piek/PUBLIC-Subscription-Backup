# Conditional Access Policy Modified by New User

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/5d4e30e4-0748
  -4ef5-9762-c990ef2e9e1a
 
 name: '5d4e30e4-0748-4ef5-9762-c990ef2e9e1a' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P14D' 
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
         identifier: 'FullName' 
         columnName: 'InitiatingUserPrincipalName' 
       - 
         identifier: 'Name' 
         columnName: 'InitiatingAccountName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'InitiatingAccountUPNSuffix' 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'AadUserId' 
         columnName: 'InitiatingAadUserId' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'InitiatingIPAddress' 
    - 
      entityType: 'CloudApplication' 
      fieldMappings: 
       - 
         identifier: 'AppId' 
         columnName: 'InitiatingAppId' 
       - 
         identifier: 'Name' 
         columnName: 'InitiatingAppName' 
   severity: 'Medium' 
   query: >
    let known_users = (AuditLogs
    | where TimeGenerated between(ago(14d)..ago(1d))
    | where OperationName has "conditional access policy"
    | where Result =~ "success"
    | extend InitiatingUserPrincipalName = tostring(InitiatedBy.user.userPrincipal
    Name)
    | summarize by InitiatingUserPrincipalName);
    AuditLogs
    | where TimeGenerated > ago(1d)
    | where OperationName has "conditional access policy"
    | where Result =~ "success"
    | extend InitiatingAppName = tostring(InitiatedBy.app.displayName)
    | extend InitiatingAppId = tostring(InitiatedBy.app.appId)
    | extend InitiatingAppServicePrincipalId = tostring(InitiatedBy.app.servicePri
    ncipalId)
    | extend InitiatingUserPrincipalName = tostring(InitiatedBy.user.userPrincipal
    Name)
    | extend InitiatingAadUserId = tostring(InitiatedBy.user.id)
    | extend InitiatingIPAddress = tostring(InitiatedBy.user.ipAddress)
    | extend CAPolicyName = tostring(TargetResources[0].displayName)
    | where InitiatingUserPrincipalName !in (known_users)
    | extend NewPolicyValues = TargetResources[0].modifiedProperties[0].newValue
    | extend OldPolicyValues = TargetResources[0].modifiedProperties[0].oldValue
    | extend InitiatingAccountName = tostring(split(InitiatingUserPrincipalName,
    "@")[0]), InitiatingAccountUPNSuffix = tostring(split(InitiatingUserPrincipalNa
    me, "@")[1])
    | project-reorder TimeGenerated, OperationName, CAPolicyName, InitiatingAppId,
    InitiatingAppName, InitiatingAppServicePrincipalId, InitiatingUserPrincipalName,
    InitiatingAadUserId, InitiatingIPAddress, NewPolicyValues, OldPolicyValues
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'DefenseEvasion' 
   techniques: 
    - 'T1078' 
   displayName: 'Conditional Access Policy Modified by New User' 
   enabled: true 
   description: >
    Detects a Conditional Access Policy being modified by a user who has not modified
    a policy in the last 14 days.
    A threat actor may try to modify policies to weaken the security controls in p
    lace.
    Investigate any change to ensure they are approved.
    Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-o
    perations-infrastructure#conditional-access
 
   alertRuleTemplateName: '25a7f951-54b7-4cf5-9862-ebc04306c590' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
