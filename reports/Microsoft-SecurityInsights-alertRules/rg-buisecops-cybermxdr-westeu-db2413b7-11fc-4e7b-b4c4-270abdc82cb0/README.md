# Exchange OAB Virtual Directory Attribute Containing Potential Webshell

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/db2413b7-11fc
  -4e7b-b4c4-270abdc82cb0
 
 name: 'db2413b7-11fc-4e7b-b4c4-270abdc82cb0' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'PT1H' 
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
   severity: 'High' 
   query: >
    SecurityEvent
    // Look for specific Directory Service Changes and parse data
    | where EventID == 5136
    | extend EventData = parse_xml(EventData).EventData.Data
    | mv-expand bagexpansion = array EventData
    | evaluate bag_unpack(EventData)
    | extend Key = tostring(column_ifexists('@Name', "")), Value = column_ifexists('#text',
    "")
    | evaluate pivot(Key, any(Value),TimeGenerated, EventID, Computer, Account,
    AccountType, EventSourceName, Activity, SubjectAccount)
    // Where changes relate to Exchange OAB
    | extend ObjectClass = column_ifexists("ObjectClass", "")
    | where ObjectClass =~ "msExchOABVirtualDirectory"
    // Look for InternalHostName or ExternalHostName properties being changed
    | extend AttributeLDAPDisplayName = column_ifexists("AttributeLDAPDisplayName",
    "")
    | where AttributeLDAPDisplayName in~ ("msExchExternalHostName", "msExchInternalH
    ostName")
    // Look for suspected webshell activity
    | extend AttributeValue = column_ifexists("AttributeValue", "")
    | where AttributeValue has "script"
    | project-rename LastSeen = TimeGenerated
    | extend ObjectDN = column_ifexists("ObjectDN", "")
    | project-reorder LastSeen, Computer, Account, ObjectDN, AttributeLDAPDisplayName,
    AttributeValue
    | extend timestamp = LastSeen, AccountCustomEntity = Account, HostCustomEntity =
    Computer
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'InitialAccess' 
   techniques: 
    - 'T1190' 
   displayName: 'Exchange OAB Virtual Directory Attribute Containing Potential Webshell' 
   enabled: true 
   description: >
    This query uses Windows Event ID 5136 in order to detect potential webshell
    deployment by exploitation of CVE-2021-27065.
    This query looks for changes to the InternalHostName or ExternalHostName properties
    of Exchange OAB Virtual Directory objects in AD Directory Services
    where the new objects contain potential webshell objects.
 
   alertRuleTemplateName: 'faf1a6ff-53b5-4f92-8c55-4b20e9957594' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
