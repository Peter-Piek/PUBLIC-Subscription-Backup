# PIM Elevation Request Rejected

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/4a141c1c-0e60
  -4516-a056-4303146cc93d
 
 name: '4a141c1c-0e60-4516-a056-4303146cc93d' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT2H' 
   queryPeriod: 'PT2H' 
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
         columnName: 'InitiatingName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'InitiatingUPNSuffix' 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'Name' 
         columnName: 'UserName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'UserUPNSuffix' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'InitiatingIpAddress' 
   severity: 'High' 
   query: >
    AuditLogs
    | where ActivityDisplayName =~'Add member to role request denied (PIM activation
    )'
    | mv-apply ResourceItem = TargetResources on
    (
    where ResourceItem.type =~ "Role"
    | extend Role = trim(@'"',tostring(ResourceItem.displayName))
    )
    | mv-apply ResourceItem = TargetResources on
    (
    where ResourceItem.type =~ "User"
    | extend User = trim(@'"',tostring(ResourceItem.userPrincipalName))
    )
    | project-reorder TimeGenerated, User, Role, OperationName, Result, ResultDescri
    ption
    | where isnotempty(InitiatedBy.user)
    | extend InitiatingUser = tostring(InitiatedBy.user.userPrincipalName),
    InitiatingIpAddress = tostring(InitiatedBy.user.ipAddress)
    | extend InitiatingName = tostring(split(InitiatingUser,'@',0)[0]), InitiatingUPNSuffix
    = tostring(split(InitiatingUser,'@',1)[0])
    | extend UserName = tostring(split(User,'@',0)[0]), UserUPNSuffix = tostring(spl
    it(User,'@',1)[0])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Persistence' 
   techniques: 
    - 'T1078' 
   displayName: 'PIM Elevation Request Rejected' 
   enabled: true 
   description: >
    Identifies when a user is rejected for a privileged role elevation via PIM. Monitor
    rejections for indicators of attacker compromise of the requesting account.
    Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-op
    erations-privileged-identity-management
 
   alertRuleTemplateName: '7d7e20f8-3384-4b71-811c-f5e950e8306c' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
