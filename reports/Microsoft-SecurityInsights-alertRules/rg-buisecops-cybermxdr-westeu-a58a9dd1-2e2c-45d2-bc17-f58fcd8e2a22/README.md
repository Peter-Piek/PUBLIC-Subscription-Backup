# Suspicious Login from deleted guest account

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/a58a9dd1-2e2c
  -45d2-bc17-f58fcd8e2a22
 
 name: 'a58a9dd1-2e2c-45d2-bc17-f58fcd8e2a22' 
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
         identifier: 'FullName' 
         columnName: 'UserPrincipalName' 
       - 
         identifier: 'Name' 
         columnName: 'AccountName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'AccountUPNSuffix' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'IPAddress' 
   severity: 'Medium' 
   query: >
    let query_frequency = 1h;
    let query_period = 1d;
    AuditLogs
    | where TimeGenerated > ago(query_frequency)
    | where Category =~ "UserManagement" and OperationName =~ "Delete user"
    | mv-expand TargetResource = TargetResources
    | where TargetResource["type"] == "User" and TargetResource["userPrincipalName"]
    has "#EXT#"
    | extend ParsedDeletedUserPrincipalName = extract(@"^[0-9a-f]{32}([^\#]+)\#EXT\#
    ", 1, tostring(TargetResource["userPrincipalName"]))
    | extend
    Initiator = iif(isnotempty(InitiatedBy["app"]), tostring(InitiatedBy["app"][
    "displayName"]), tostring(InitiatedBy["user"]["userPrincipalName"])),
    InitiatorId = iif(isnotempty(InitiatedBy["app"]), tostring(InitiatedBy["app"
    ]["servicePrincipalId"]), tostring(InitiatedBy["user"]["id"])),
    Delete_IPAddress = tostring(InitiatedBy[tostring(bag_keys(InitiatedBy)[0])][
    "ipAddress"])
    | project Delete_TimeGenerated = TimeGenerated, Category, Identity, Initiator,
    Delete_IPAddress, OperationName, Result, ParsedDeletedUserPrincipalName, InitiatedBy,
    AdditionalDetails, TargetResources, InitiatorId, CorrelationId
    | join kind=inner (
    SigninLogs
    | where TimeGenerated > ago(query_period)
    | where ResultType == 0
    | summarize take_any(*) by UserPrincipalName
    | extend ParsedUserPrincipalName = translate("@", "_", UserPrincipalName)
    | project SigninLogs_TimeGenerated = TimeGenerated, UserPrincipalName,
    UserDisplayName, ResultType, ResultDescription, IPAddress, LocationDetails,
    AppDisplayName, ResourceDisplayName, ClientAppUsed, UserAgent, DeviceDetail,
    UserId, UserType, OriginalRequestId, ParsedUserPrincipalName
    ) on $left.ParsedDeletedUserPrincipalName == $right.ParsedUserPrincipalName
    | where SigninLogs_TimeGenerated > Delete_TimeGenerated
    | project-away ParsedDeletedUserPrincipalName, ParsedUserPrincipalName
    | extend
    AccountName = tostring(split(UserPrincipalName, "@")[0]),
    AccountUPNSuffix = tostring(split(UserPrincipalName, "@")[1])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'PrivilegeEscalation' 
   techniques: 
    - 'T1078' 
   displayName: 'Suspicious Login from deleted guest account' 
   enabled: true 
   description: >
    This query will detect logins from guest account which was recently deleted.
    For any successful logins from deleted identities should be investigated further
    if any existing user accounts have been altered or linked to such identity prior
    deletion
 
   alertRuleTemplateName: 'defe4855-0d33-4362-9557-009237623976' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
