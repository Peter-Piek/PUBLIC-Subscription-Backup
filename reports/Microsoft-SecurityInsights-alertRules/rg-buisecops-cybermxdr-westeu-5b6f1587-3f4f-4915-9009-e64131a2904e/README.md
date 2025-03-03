# Starting or Stopping HealthService to Avoid Detection

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/5b6f1587-3f4f
  -4915-9009-e64131a2904e
 
 name: '5b6f1587-3f4f-4915-9009-e64131a2904e' 
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
         identifier: 'FullName' 
         columnName: 'AccountCustomEntity' 
    - 
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'FullName' 
         columnName: 'HostCustomEntity' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'IPCustomEntity' 
   severity: 'Medium' 
   query: >
    SecurityEvent
    | where EventID == 4656
    | extend EventData = parse_xml(EventData).EventData.Data
    | mv-expand bagexpansion=array EventData
    | evaluate bag_unpack(EventData)
    | extend Key = tostring(column_ifexists('@Name', "")), Value = column_ifexists('#text',
    "")
    | evaluate pivot(Key, any(Value), TimeGenerated, TargetAccount, Computer,
    EventSourceName, Channel, Task, Level, EventID, Activity, TargetLogonId,
    SourceComputerId, EventOriginId, Type, _ResourceId, TenantId, SourceSystem,
    ManagementGroupName, IpAddress, Account)
    | extend ObjectServer = column_ifexists('ObjectServer', ""), ObjectType =
    column_ifexists('ObjectType', ""), ObjectName = column_ifexists('ObjectName', "
    ")
    | where isnotempty(ObjectServer) and isnotempty(ObjectType) and isnotempty(Objec
    tName)
    | where ObjectServer =~ "SC Manager" and ObjectType =~ "SERVICE OBJECT" and
    ObjectName =~ "HealthService"
    // Comment out the join below if the SACL only audits users that are part of the
    Network logon users, i.e. with user/group target pointing to "NU."
    | join kind=leftouter (
    SecurityEvent
    | where EventID == 4624
    ) on TargetLogonId
    | project TimeGenerated, Computer, Account, TargetAccount, IpAddress,TargetLogonId,
    ObjectServer, ObjectType, ObjectName
    | extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity
    = Account, IPCustomEntity = IpAddress
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'DefenseEvasion' 
   techniques: 
    - 'T1562' 
   displayName: 'Starting or Stopping HealthService to Avoid Detection' 
   enabled: true 
   description: >
    This query detects events where an actor is stopping or starting HealthService to
    disable telemetry collection/detection from the agent.
    The query requires a SACL to audit for access request to the service.
 
   alertRuleTemplateName: '2bc7b4ae-eeaa-4538-ba15-ef298ec1ffae' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
