# Exchange AuditLog Disabled

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/82f183a6-f31c
  -4c3a-bbd4-c9bd38bd47e1
 
 name: '82f183a6-f31c-4c3a-bbd4-c9bd38bd47e1' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
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
         columnName: 'AccountName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'AccountUPNSuffix' 
       - 
         identifier: 'NTDomain' 
         columnName: 'AccountNTDomain' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'ClientIP' 
   severity: 'Medium' 
   query: >
    OfficeActivity
    | where OfficeWorkload =~ "Exchange"
    | where UserType in~ ("Admin","DcAdmin")
    // Only admin or global-admin can disable audit logging
    | where Operation =~ "Set-AdminAuditLogConfig"
    | extend AdminAuditLogEnabledValue = tostring(parse_json(tostring(parse_json(tos
    tring(array_slice(parse_json(Parameters),3,3)))[0])).Value)
    | where AdminAuditLogEnabledValue =~ "False"
    | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated),
    OperationCount = count() by Operation, UserType, UserId, ClientIP, ResultStatus,
    Parameters, AdminAuditLogEnabledValue
    | extend AccountName = iff(UserId contains '@', tostring(split(UserId, '@')[0]),
    UserId)
    | extend AccountUPNSuffix = iff(UserId contains '@', tostring(split(UserId, '@')[1]),
    '')
    | extend AccountName = iff(UserId contains '\\', tostring(split(UserId, '\\')[1]),
    AccountName)
    | extend AccountNTDomain = iff(UserId contains '\\', tostring(split(UserId,
    '\\')[0]), '')
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'DefenseEvasion' 
   techniques: 
    - 'T1562' 
   displayName: 'Exchange AuditLog Disabled' 
   enabled: true 
   description: >
    Identifies when the exchange audit logging has been disabled which may be an
    adversary attempt
    to evade detection or avoid other defenses.
 
   alertRuleTemplateName: '194dd92e-d6e7-4249-85a5-273350a7f5ce' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
