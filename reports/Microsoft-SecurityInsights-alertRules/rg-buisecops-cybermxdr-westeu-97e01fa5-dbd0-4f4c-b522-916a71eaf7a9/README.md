# TI Map URL Entity to Syslog Data

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/97e01fa5-dbd0
  -4f4c-b522-916a71eaf7a9
 
 name: '97e01fa5-dbd0-4f4c-b522-916a71eaf7a9' 
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
    ThreatIntelligenceIndicator
    // Picking up only IOC's that contain the entities we want
    | where isnotempty(Url)
    | where TimeGenerated >= ago(ioc_lookBack)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    // using innerunique to keep perf fast and result set low, we only need one match
    to indicate potential malicious activity that needs to be investigated
    | join kind=innerunique (
    Syslog
    | where TimeGenerated >= ago(dt_lookBack)
    // Extract URL from the Syslog message but only take messages that include URL
    s
    | extend Url = extract("(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?
    :%[0-9a-fA-F][0-9a-fA-F]))+)", 1,SyslogMessage)
    | where isnotempty(Url)
    | extend Syslog_TimeGenerated = TimeGenerated
    ) on Url
    | where Syslog_TimeGenerated < ExpirationDateTime
    | summarize Syslog_TimeGenerated  = arg_max(Syslog_TimeGenerated , *) by IndicatorId,
    Url
    | project timestamp = Syslog_TimeGenerated, Description, ActivityGroupNames,
    IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore, SyslogMessage,
    Computer, ProcessName, Url, HostIP
 
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
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'HostName' 
         columnName: 'Computer' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'HostIP' 
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
   displayName: 'TI Map URL Entity to Syslog Data' 
   enabled: true 
   description: >
    This query identifies any URL indicators of compromise (IOCs) from threat intelligence
    (TI) by searching for matches in Syslog data.
 
   alertRuleTemplateName: 'b31037ea-6f68-4fbd-bab2-d0d0f44c2fcf' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
