# TI map Email entity to SecurityEvent

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/3a7b3e85-f371
  -4ae2-b07b-238076c13374
 
 name: '3a7b3e85-f371-4ae2-b07b-238076c13374' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'P14D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h;
    let ioc_lookBack = 14d;
    let emailregex = @'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$';
    ThreatIntelligenceIndicator
    //Filtering the table for Email related IOCs
    | where isnotempty(EmailSenderAddress)
    | where TimeGenerated >= ago(ioc_lookBack)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    // using innerunique to keep perf fast and result set low, we only need one match
    to indicate potential malicious activity that needs to be investigated
    | join kind=innerunique (
    (union isfuzzy=true
    (SecurityEvent
    | where TimeGenerated >= ago(dt_lookBack) and isnotempty(TargetUserName)
    //Normalizing the column to lower case for exact match with EmailSenderAddress c
    olumn
    | extend TargetUserName = tolower(TargetUserName)
    // renaming timestamp column so it is clear the log this came from SecurityEvent
    table
    | extend SecurityEvent_TimeGenerated = TimeGenerated
    ),
    (WindowsEvent
    | where TimeGenerated >= ago(dt_lookBack)
    | extend TargetUserName = tostring(EventData.TargetUserName)
    | where isnotempty(TargetUserName)
    //Normalizing the column to lower case for exact match with EmailSenderAddress c
    olumn
    | extend TargetUserName = tolower(TargetUserName)
    // renaming timestamp column so it is clear the log this came from SecurityEvent
    table
    | extend SecurityEvent_TimeGenerated = TimeGenerated
    ))
    )
    on $left.EmailSenderAddress == $right.TargetUserName
    | where SecurityEvent_TimeGenerated < ExpirationDateTime
    | summarize SecurityEvent_TimeGenerated = arg_max(SecurityEvent_TimeGenerated, *)
    by IndicatorId, TargetUserName
    | project SecurityEvent_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, Url, ExpirationDateTime, ConfidenceScore,
    EmailSenderName, EmailRecipient, EmailSourceDomain, EmailSourceIpAddress, EmailSubject,
    FileHashValue, FileHashType, Computer, EventID, TargetUserName, Activity, IpAddress,
    AccountType,
    LogonTypeName, LogonProcessName, Status, SubStatus
    | extend HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring(s
    trcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))
    | extend timestamp = SecurityEvent_TimeGenerated
 
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
         columnName: 'TargetUserName' 
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
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'IpAddress' 
    - 
      entityType: 'URL' 
      fieldMappings: 
       - 
         identifier: 'Url' 
         columnName: 'Url' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Impact' 
   techniques: null 
   subTechniques: null 
   displayName: 'TI map Email entity to SecurityEvent' 
   enabled: true 
   description: 'Identifies a match in SecurityEvent table from any Email IOC from TI' 
   alertRuleTemplateName: '2fc5d810-c9cc-491a-b564-841427ae0e50' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
