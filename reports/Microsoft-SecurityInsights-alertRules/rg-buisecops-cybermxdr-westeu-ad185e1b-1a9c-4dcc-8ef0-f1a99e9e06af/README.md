# Multi-Factor Authentication Disabled for a User

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/ad185e1b-1a9c
  -4dcc-8ef0-f1a99e9e06af
 
 name: 'ad185e1b-1a9c-4dcc-8ef0-f1a99e9e06af' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'PT1H' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    (union isfuzzy=true
    (AuditLogs
    | where OperationName =~ "Disable Strong Authentication"
    | extend _parsedIntiatedByUser = parse_json(tostring(InitiatedBy.user))
    | extend _parsedIntiatedByApp = parse_json(tostring(InitiatedBy.app))
    | extend IPAddress = tostring(_parsedIntiatedByUser.ipAddress)
    | extend InitiatedByUser = iff(isnotempty(tostring(_parsedIntiatedByUser.userPri
    ncipalName)),
    tostring(_parsedIntiatedByUser.userPrincipalName), tostring(_parsedIntiatedByAp
    p.displayName))
    | extend Targetprop = todynamic(TargetResources)
    | extend TargetUser = tostring(Targetprop[0].userPrincipalName)
    | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by
    User = TargetUser, InitiatedByUser , Operation = OperationName , CorrelationId,
    IPAddress, Category, Source = SourceSystem , AADTenantId, Type
    ),
    (AWSCloudTrail
    | where EventName in~ ("DeactivateMFADevice", "DeleteVirtualMFADevice")
    | extend _parsedRequestParameters = parse_json(RequestParameters)
    | extend InstanceProfileName = tostring(_parsedRequestParameters.InstanceProfile
    Name)
    | extend TargetUser = tostring(_parsedRequestParameters.userName)
    | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated) by
    User = TargetUser, Source = EventSource , Operation = EventName , TenantorInstance_Detail
    = InstanceProfileName, IPAddress = SourceIpAddress
    )
    )
    | extend timestamp = StartTimeUtc, UserName = tostring(split(User, '@', 0)[0]),
    UPNSuffix = tostring(split(User, '@', 1)[0])
 
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
         columnName: 'UserName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'UPNSuffix' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'IPAddress' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'CredentialAccess' 
    - 'Persistence' 
   techniques: 
    - 'T1098' 
    - 'T1556' 
   subTechniques: null 
   displayName: 'Multi-Factor Authentication Disabled for a User' 
   enabled: true 
   description: >
    Multi-Factor Authentication (MFA) helps prevent credential compromise. This alert
    identifies when an attempt has been made to deactivate MFA for a user.
 
   alertRuleTemplateName: '65c78944-930b-4cae-bd79-c3664ae30ba7' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
