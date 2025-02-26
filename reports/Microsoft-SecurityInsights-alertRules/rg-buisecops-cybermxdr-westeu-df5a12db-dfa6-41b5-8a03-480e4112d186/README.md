# TI map Email entity to AzureActivity

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/df5a12db-dfa6
  -41b5-8a03-480e4112d186
 
 name: 'df5a12db-dfa6-41b5-8a03-480e4112d186' 
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
    AzureActivity | where TimeGenerated >= ago(dt_lookBack) and isnotempty(Calle
    r)
    | extend Caller = tolower(Caller)
    | where Caller matches regex emailregex
    | extend AzureActivity_TimeGenerated = TimeGenerated
    )
    on $left.EmailSenderAddress == $right.Caller
    | where AzureActivity_TimeGenerated < ExpirationDateTime
    | summarize AzureActivity_TimeGenerated = arg_max(AzureActivity_TimeGenerated, *)
    by IndicatorId, Caller
    | project AzureActivity_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, ExpirationDateTime, ConfidenceScore, Url, EmailSenderName, EmailRec
    ipient,
    EmailSourceDomain, EmailSourceIpAddress, EmailSubject, FileHashValue, FileHashType,
    Caller, Level, CallerIpAddress, CategoryValue, OperationNameValue, ActivityStat
    usValue,
    ResourceGroup, SubscriptionId
    | extend Name = tostring(split(Caller, '@', 0)[0]), UPNSuffix = tostring(split(Caller,
    '@', 1)[0])
    | extend timestamp = AzureActivity_TimeGenerated
 
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
         columnName: 'CallerIpAddress' 
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
   displayName: 'TI map Email entity to AzureActivity' 
   enabled: true 
   description: 'Identifies a match in AzureActivity table from any Email IOC from TI' 
   alertRuleTemplateName: 'cca3b4d9-ac39-4109-8b93-65bb284003e6' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
