# Detect PIM Alert Disabling activity

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/2e575204-a313
  -46e0-aca7-599aafd3c506
 
 name: '2e575204-a313-46e0-aca7-599aafd3c506' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    AuditLogs
    | where LoggedByService =~ "PIM"
    | where Category =~ "RoleManagement"
    | where ActivityDisplayName has "Disable PIM Alert"
    | extend IpAddress = case(
    isnotempty(tostring(parse_json(tostring(InitiatedBy.user)).ipAddress)) and tos
    tring(parse_json(tostring(InitiatedBy.user)).ipAddress) != 'null', tostring(pars
    e_json(tostring(InitiatedBy.user)).ipAddress),
    isnotempty(tostring(parse_json(tostring(InitiatedBy.app)).ipAddress)) and tost
    ring(parse_json(tostring(InitiatedBy.app)).ipAddress) != 'null', tostring(parse_
    json(tostring(InitiatedBy.app)).ipAddress),
    'Not Available')
    | extend InitiatedBy = iff(isnotempty(tostring(parse_json(tostring(InitiatedBy.u
    ser)).userPrincipalName)),
    tostring(parse_json(tostring(InitiatedBy.user)).userPrincipalName), tostring(p
    arse_json(tostring(InitiatedBy.app)).displayName)), UserRoles = tostring(parse_j
    son(tostring(InitiatedBy.user)).ipAddress)
    | project InitiatedBy, ActivityDateTime, ActivityDisplayName, IpAddress,
    AADOperationType, AADTenantId, ResourceId, CorrelationId, Identity
    | extend AccountName = tostring(split(InitiatedBy, "@")[0]), AccountUPNSuffix =
    tostring(split(InitiatedBy, "@")[1])
 
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
         identifier: 'FullName' 
         columnName: 'InitiatedBy' 
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
         columnName: 'IpAddress' 
    - 
      entityType: 'AzureResource' 
      fieldMappings: 
       - 
         identifier: 'ResourceId' 
         columnName: 'ResourceId' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Persistence' 
    - 'PrivilegeEscalation' 
   techniques: 
    - 'T1098' 
    - 'T1078' 
   subTechniques: null 
   displayName: 'Detect PIM Alert Disabling activity' 
   enabled: true 
   description: >
    Privileged Identity Management (PIM) generates alerts when there is suspicious or
    unsafe activity in Microsoft Entra ID (Azure AD) organization.
    This query will help detect attackers attempts to disable in product PIM alerts
    which are associated with Azure MFA requirements and could indicate activation
    of privileged access
 
   alertRuleTemplateName: '1f3b4dfd-21ff-4ed3-8e27-afc219e05c50' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
