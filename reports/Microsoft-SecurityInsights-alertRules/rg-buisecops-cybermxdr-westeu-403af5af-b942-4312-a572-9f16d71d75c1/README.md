# Account created from non-approved sources

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/403af5af-b942
  -4312-a572-9f16d71d75c1
 
 name: '403af5af-b942-4312-a572-9f16d71d75c1' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
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
         columnName: 'InitiatingAppName' 
       - 
         identifier: 'AadUserId' 
         columnName: 'InitiatingAppServicePrincipalId' 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'FullName' 
         columnName: 'InitiatingUserPrincipalName' 
       - 
         identifier: 'Name' 
         columnName: 'AddedByName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'AddedByUPNSuffix' 
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
         columnName: 'InitiatingIpAddress' 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'FullName' 
         columnName: 'UserAdded' 
       - 
         identifier: 'Name' 
         columnName: 'UserAddedName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'UserAddedDomain' 
   severity: 'Medium' 
   query: >
    let core_domains = (SigninLogs
    | where TimeGenerated > ago(7d)
    | where ResultType == 0
    | extend domain = tolower(split(UserPrincipalName, "@")[1])
    | summarize by tostring(domain));
    let alternative_domains = (SigninLogs
    | where TimeGenerated > ago(7d)
    | where isnotempty(AlternateSignInName)
    | where ResultType == 0
    | extend domain = tolower(split(AlternateSignInName, "@")[1])
    | summarize by tostring(domain));
    AuditLogs
    | where TimeGenerated > ago(1d)
    | where OperationName =~ "Add User"
    | extend InitiatingAppName = tostring(InitiatedBy.app.displayName)
    | extend InitiatingAppServicePrincipalId = tostring(InitiatedBy.app.servicePri
    ncipalId)
    | extend InitiatingUserPrincipalName = tostring(InitiatedBy.user.userPrincipal
    Name)
    | extend InitiatingAadUserId = tostring(InitiatedBy.user.id)
    | extend InitiatingIpAddress = tostring(iff(isnotempty(InitiatedBy.user.ipAddr
    ess), InitiatedBy.user.ipAddress, InitiatedBy.app.ipAddress))
    | extend UserAdded = tostring(TargetResources[0].userPrincipalName)
    | extend UserAddedDomain = case(
    UserAdded has "#EXT#", tostring(split(tostring(split(UserAdded, "#EXT#")[0]),
    "_")[1]),
    UserAdded !has "#EXT#", tostring(split(UserAdded, "@")[1]),
    UserAdded)
    | where UserAddedDomain !in (core_domains) and UserAddedDomain !in (alternativ
    e_domains)
    | extend AddedByName = case(
    InitiatingUserPrincipalName has "#EXT#", tostring(split(tostring(split(Initiat
    ingUserPrincipalName, "#EXT#")[0]), "_")[0]),
    InitiatingUserPrincipalName !has "#EXT#", tostring(split(InitiatingUserPrincip
    alName, "@")[0]),
    InitiatingUserPrincipalName)
    | extend AddedByUPNSuffix = case(
    InitiatingUserPrincipalName has "#EXT#", tostring(split(tostring(split(Initiat
    ingUserPrincipalName, "#EXT#")[0]), "_")[1]),
    InitiatingUserPrincipalName !has "#EXT#", tostring(split(InitiatingUserPrincip
    alName, "@")[1]),
    InitiatingUserPrincipalName)
    | extend UserAddedName = case(
    UserAdded has "#EXT#", tostring(split(tostring(split(UserAdded, "#EXT#")[0]),
    "_")[0]),
    UserAdded !has "#EXT#", tostring(split(UserAdded, "@")[0]),
    UserAdded)
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Persistence' 
   techniques: 
    - 'T1136' 
   displayName: 'Account created from non-approved sources' 
   enabled: true 
   description: >
    This query looks for an account being created from a domain that is not regularly
    seen in a tenant.
    Attackers may attempt to add accounts from these sources as a means of establishing
    persistant access to an environment.
    Created accounts should be investigated to confirm expected creation.
    Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-o
    perations-user-accounts#short-lived-accounts
 
   alertRuleTemplateName: '99d589fa-7337-40d7-91a0-c96d0c4fa437' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
