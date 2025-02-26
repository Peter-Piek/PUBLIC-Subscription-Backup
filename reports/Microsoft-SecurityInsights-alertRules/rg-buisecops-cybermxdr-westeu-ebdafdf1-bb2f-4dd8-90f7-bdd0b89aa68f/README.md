# Account created or deleted by non-approved user

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/ebdafdf1-bb2f
  -4dd8-90f7-bdd0b89aa68f
 
 name: 'ebdafdf1-bb2f-4dd8-90f7-bdd0b89aa68f' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    // Add non-approved user principal names to the list below to search for their
    account creation/deletion activity
    // ex: dynamic(["UPN1", "upn123"])
    let nonapproved_users = dynamic([]);
    AuditLogs
    | where OperationName =~ "Add user" or OperationName =~ "Delete user"
    | where Result =~ "success"
    | extend InitiatingUser = tostring(InitiatedBy.user.userPrincipalName)
    | where InitiatingUser has_any (nonapproved_users)
    | project-reorder TimeGenerated, ResourceId, OperationName, InitiatingUser, Targ
    etResources
    | extend InitiatedUserIpAddress = tostring(InitiatedBy.user.ipAddress)
    | extend Name = tostring(split(InitiatingUser,'@',0)[0]), UPNSuffix = tostring(s
    plit(InitiatingUser,'@',1)[0])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
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
         columnName: 'InitiatedUserIpAddress' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'InitialAccess' 
   techniques: 
    - 'T1078' 
   subTechniques: null 
   displayName: 'Account created or deleted by non-approved user' 
   enabled: true 
   description: >
    Identifies accounts that were created or deleted by a defined list of non-approved
    user principal names. Add to this list before running the query for accurate re
    sults.
    Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-op
    erations-user-accounts
 
   alertRuleTemplateName: '6d63efa6-7c25-4bd4-a486-aa6bf50fde8a' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
