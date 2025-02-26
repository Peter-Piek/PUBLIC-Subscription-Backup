# TI map Email entity to OfficeActivity

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/37b0e65e-dddf
  -42fc-8303-270443c71818
 
 name: '37b0e65e-dddf-42fc-8303-270443c71818' 
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
    let OfficeEvents = materialize(
    OfficeActivity
    | where isnotempty(UserId)
    | where TimeGenerated >= ago(dt_lookBack)
    | where UserId matches regex emailregex
    | project-rename  OfficeActivity_TimeGenerated = TimeGenerated);
    let OfficeActivityUPNs = OfficeEvents | distinct UserId = tolower(UserId) | summarize
    make_list(UserId);
    ThreatIntelligenceIndicator
    | where isnotempty(EmailSenderAddress)
    | where TimeGenerated >= ago(ioc_lookBack)
    | where tolower(EmailSenderAddress) in (OfficeActivityUPNs)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    | where Description !contains_cs "State: inactive;" and Description !contains_cs
    "State: falsepos;"
    // using innerunique to keep perf fast and result set low, we only need one match
    to indicate potential malicious activity that needs to be investigated
    | join kind=innerunique (OfficeEvents) on $left.EmailSenderAddress == $right.Use
    rId
    | where OfficeActivity_TimeGenerated < ExpirationDateTime
    | summarize OfficeActivity_TimeGenerated = arg_max(OfficeActivity_TimeGenerated,
    *) by IndicatorId, UserId
    | project OfficeActivity_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, Url, ExpirationDateTime, ConfidenceScore, EmailSenderName, EmailRecipient,
    EmailSourceDomain, EmailSourceIpAddress, EmailSubject, FileHashValue, FileHashType,
    UserId, ClientIP, Operation, UserType, RecordType, OfficeWorkload, Parameters
    | extend Name = tostring(split(UserId, '@', 0)[0]), UPNSuffix = tostring(split(UserId,
    '@', 1)[0])
    | extend timestamp = OfficeActivity_TimeGenerated
 
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
         columnName: 'Name' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'UPNSuffix' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'ClientIP' 
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
   displayName: 'TI map Email entity to OfficeActivity' 
   enabled: true 
   description: 'Identifies a match in OfficeActivity table from any Email IOC from TI' 
   alertRuleTemplateName: '4a3f5ed7-8da5-4ce2-af6f-c9ada45060f2' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
