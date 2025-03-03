# TI map File Hash to CommonSecurityLog Event

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/74c62f26-f154
  -4387-8888-06adc7f8c9e9
 
 name: '74c62f26-f154-4387-8888-06adc7f8c9e9' 
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
         identifier: 'UPNSuffix' 
         columnName: 'UPNSuffix' 
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
         columnName: 'SourceIP' 
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
    let fileHashIndicators = ThreatIntelligenceIndicator
    | where isnotempty(FileHashValue)
    | where TimeGenerated >= ago(ioc_lookBack)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now();
    // Handle matches against both lower case and uppercase versions of the hash:
    (fileHashIndicators | extend  FileHashValue = tolower(FileHashValue)
    | union (fileHashIndicators | extend FileHashValue = toupper(FileHashValue)))
    // using innerunique to keep perf fast and result set low, we only need one match
    to indicate potential malicious activity that needs to be investigated
    |  join kind=innerunique (
    CommonSecurityLog | where TimeGenerated >= ago(dt_lookBack)
    | where isnotempty(FileHash)
    | extend CommonSecurityLog_TimeGenerated = TimeGenerated
    )
    on $left.FileHashValue == $right.FileHash
    | where CommonSecurityLog_TimeGenerated < ExpirationDateTime
    | summarize CommonSecurityLog_TimeGenerated = arg_max(CommonSecurityLog_TimeGene
    rated, *) by IndicatorId, FileHashValue
    | project CommonSecurityLog_TimeGenerated, Description, ActivityGroupNames,
    IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
    SourceIP, SourcePort, DestinationIP, DestinationPort, SourceUserID, SourceUserName,
    DeviceName, DeviceAction,
    RequestURL, DestinationUserName, DestinationUserID, ApplicationProtocol, Activity,
    FileHashValue, FileHashType
    | extend HostName = tostring(split(DeviceName, '.', 0)[0]), DnsDomain = tostring
    (strcat_array(array_slice(split(DeviceName, '.'), 1, -1), '.'))
    | extend Name = tostring(split(SourceUserName, '@', 0)[0]), UPNSuffix = tostring
    (split(SourceUserName, '@', 1)[0])
    | extend timestamp = CommonSecurityLog_TimeGenerated
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map File Hash to CommonSecurityLog Event' 
   enabled: true 
   description: 'Identifies a match in CommonSecurityLog Event data from any FileHash IOC from TI' 
   alertRuleTemplateName: '5d33fc63-b83b-4913-b95e-94d13f0d379f' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
