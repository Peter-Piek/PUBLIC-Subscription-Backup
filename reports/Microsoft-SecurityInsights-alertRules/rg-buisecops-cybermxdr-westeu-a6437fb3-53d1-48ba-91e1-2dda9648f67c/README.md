# Account Created and Deleted in Short Timeframe

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/a6437fb3-53d1
  -48ba-91e1-2dda9648f67c
 
 name: 'a6437fb3-53d1-48ba-91e1-2dda9648f67c' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'P1D' 
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
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'DeletedByIPAddress' 
   severity: 'High' 
   query: >
    let queryfrequency = 1h;
    let queryperiod = 1d;
    AuditLogs
    | where TimeGenerated > ago(queryfrequency)
    | where OperationName =~ "Delete user"
    //extend UserPrincipalName = tostring(TargetResources[0].userPrincipalName)
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type == "User"
    | extend UserPrincipalName = extract(@'([a-f0-9]{32})?(.*)', 2, tostring(T
    argetResource.userPrincipalName))
    )
    | extend DeletedByUser = tostring(InitiatedBy.user.userPrincipalName), DeletedByIPAddress
    = tostring(InitiatedBy.user.ipAddress)
    | extend DeletedByApp = tostring(InitiatedBy.app.displayName)
    | project Deletion_TimeGenerated = TimeGenerated, UserPrincipalName, DeletedByUser,
    DeletedByIPAddress, DeletedByApp, Deletion_AdditionalDetails = AdditionalDetails,
    Deletion_InitiatedBy = InitiatedBy, Deletion_TargetResources = TargetResources
    | join kind=inner (
    AuditLogs
    | where TimeGenerated > ago(queryperiod)
    | where OperationName =~ "Add user"
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type == "User"
    | extend UserPrincipalName = trim(@'"',tostring(TargetResource.userPri
    ncipalName))
    )
    | project-rename Creation_TimeGenerated = TimeGenerated
    ) on UserPrincipalName
    | extend TimeDelta = Deletion_TimeGenerated - Creation_TimeGenerated
    | where  TimeDelta between (time(0s) .. queryperiod)
    | extend CreatedByUser = tostring(InitiatedBy.user.userPrincipalName), CreatedByIPAddress
    = tostring(InitiatedBy.user.ipAddress)
    | extend CreatedByApp = tostring(InitiatedBy.app.displayName)
    | project Creation_TimeGenerated, Deletion_TimeGenerated, TimeDelta, UserPrincipalName,
    DeletedByUser, DeletedByIPAddress, DeletedByApp, CreatedByUser, CreatedByIPAddress,
    CreatedByApp, Creation_AdditionalDetails = AdditionalDetails, Creation_InitiatedBy
    = InitiatedBy, Creation_TargetResources = TargetResources, Deletion_AdditionalDetails,
    Deletion_InitiatedBy, Deletion_TargetResources
    | extend timestamp = Deletion_TimeGenerated, Name = tostring(split(UserPrincipal
    Name,'@',0)[0]), UPNSuffix = tostring(split(UserPrincipalName,'@',1)[0])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'InitialAccess' 
   techniques: 
    - 'T1078' 
   displayName: 'Account Created and Deleted in Short Timeframe' 
   enabled: true 
   description: >
    Search for user principal name (UPN) events. Look for accounts created and then
    deleted in under 24 hours. Attackers may create an account for their use, and
    then remove the account when no longer needed.
    Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-op
    erations-user-accounts#short-lived-account
 
   alertRuleTemplateName: 'bb616d82-108f-47d3-9dec-9652ea0d3bf6' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
