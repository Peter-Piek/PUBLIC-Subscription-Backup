# TI map File Hash to Security Event

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/5a229c14-e36d
  -4028-9b67-c078a5b32f89
 
 name: '5a229c14-e36d-4028-9b67-c078a5b32f89' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'P14D' 
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
         identifier: 'NTDomain' 
         columnName: 'NTDomain' 
    - 
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'HostName' 
         columnName: 'HostName' 
       - 
         identifier: 'DnsDomain' 
         columnName: 'DnsDomain' 
    - 
      entityType: 'URL' 
      fieldMappings: 
       - 
         identifier: 'Url' 
         columnName: 'Url' 
    - 
      entityType: 'FileHash' 
      fieldMappings: 
       - 
         identifier: 'Value' 
         columnName: 'FileHashValue' 
       - 
         identifier: 'Algorithm' 
         columnName: 'FileHashType' 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h;
    let ioc_lookBack = 14d;
    ThreatIntelligenceIndicator
    | where isnotempty(FileHashValue)
    | where TimeGenerated >= ago(ioc_lookBack)
    | extend FileHashValue = toupper(FileHashValue)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    // using innerunique to keep perf fast and result set low, we only need one match
    to indicate potential malicious activity that needs to be investigated
    | join kind=innerunique ( union isfuzzy=true
    (SecurityEvent | where TimeGenerated >= ago(dt_lookBack)
    | where EventID in ("8003","8002","8005")
    | where isnotempty(FileHash)
    | extend SecurityEvent_TimeGenerated = TimeGenerated, Event = EventID,
    FileHash = toupper(FileHash)
    ),
    (WindowsEvent | where TimeGenerated >= ago(dt_lookBack)
    | where EventID in ("8003","8002","8005")
    | where isnotempty(EventData.FileHash)
    | extend SecurityEvent_TimeGenerated = TimeGenerated, Event = EventID,
    FileHash = toupper(EventData.FileHash)
    )
    )
    on $left.FileHashValue == $right.FileHash
    | where SecurityEvent_TimeGenerated < ExpirationDateTime
    | summarize SecurityEvent_TimeGenerated = arg_max(SecurityEvent_TimeGenerated, *)
    by IndicatorId, FileHash
    | project SecurityEvent_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, Url, ExpirationDateTime, ConfidenceScore,
    Process, FileHash, Computer, Account, Event, FileHashValue, FileHashType
    | extend NTDomain = tostring(split(Account, '\\', 0)[0]), Name = tostring(split(Account,
    '\\', 1)[0])
    | extend HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(s
    trcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))
    | extend timestamp = SecurityEvent_TimeGenerated
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map File Hash to Security Event' 
   enabled: true 
   description: 'Identifies a match in Security Event data from any File Hash IOC from TI' 
   alertRuleTemplateName: 'a7427ed7-04b4-4e3b-b323-08b981b9b4bf' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
