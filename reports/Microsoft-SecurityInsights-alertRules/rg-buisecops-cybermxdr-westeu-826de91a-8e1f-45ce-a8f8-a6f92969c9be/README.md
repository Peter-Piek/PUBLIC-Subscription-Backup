# TI map Email entity to PaloAlto CommonSecurityLog

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/826de91a-8e1f
  -45ce-a8f8-a6f92969c9be
 
 name: '826de91a-8e1f-45ce-a8f8-a6f92969c9be' 
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
         columnName: 'DestinationUserID' 
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
    CommonSecurityLog | where TimeGenerated >= ago(dt_lookBack) and isnotempty(D
    estinationUserID)
    // Filtering PAN Logs for specific event type to match relevant email entiti
    es
    | where DeviceVendor == "Palo Alto Networks" and  DeviceEventClassID ==
    "wildfire" and ApplicationProtocol in ("smtp","pop3")
    | extend DestinationUserID = tolower(DestinationUserID)
    | where DestinationUserID matches regex emailregex
    | extend CommonSecurityLog_TimeGenerated = TimeGenerated
    )
    on $left.EmailSenderAddress == $right.DestinationUserID
    | where CommonSecurityLog_TimeGenerated < ExpirationDateTime
    | summarize CommonSecurityLog_TimeGenerated = arg_max(CommonSecurityLog_TimeGene
    rated, *) by IndicatorId, DestinationUserID
    | project CommonSecurityLog_TimeGenerated, Description, ActivityGroupNames,
    IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore, EmailSenderName,
    EmailRecipient,
    EmailSourceDomain, EmailSourceIpAddress, EmailSubject, FileHashValue, FileHashType,
    DestinationUserID, DeviceEventClassID, LogSeverity, DeviceAction, SourceIP, Sou
    rcePort,
    DestinationIP, DestinationPort, Protocol, ApplicationProtocol
    | extend timestamp = CommonSecurityLog_TimeGenerated
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map Email entity to PaloAlto CommonSecurityLog' 
   enabled: true 
   description: 'Identifies a match in CommonSecurityLog table from any Email IOC from TI' 
   alertRuleTemplateName: 'ffcd575b-3d54-482a-a6d8-d0de13b6ac63' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
