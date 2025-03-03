# TI Map URL Entity to PaloAlto Data

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/179db691-0dda
  -48b9-8905-7bbf4d41dacc
 
 name: '179db691-0dda-48b9-8905-7bbf4d41dacc' 
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
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'HostName' 
         columnName: 'DeviceName' 
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
         columnName: 'PA_Url' 
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
    CommonSecurityLog
    | extend IngestionTime = ingestion_time()
    | where IngestionTime > ago(dt_lookBack)
    // Select on Palo Alto logs
    | where DeviceVendor =~ "Palo Alto Networks"
    | where DeviceEventClassID =~ 'url'
    //Uncomment the line below to only alert on allowed connections
    //| where DeviceAction !~ "block-url"
    //Select logs where URL data is populated
    | extend PA_Url = column_ifexists("RequestURL", "None")
    | extend PA_Url = iif(isempty(PA_Url), extract("([^\"]+)", 1, tolower(Addition
    alExtensions)), trim('"', PA_Url))
    | extend PA_Url = iif(PA_Url !startswith "http://" and ApplicationProtocol !~
    "ssl", strcat('http://', PA_Url), iif(PA_Url !startswith "https://" and
    ApplicationProtocol =~ "ssl", strcat('https://', PA_Url), PA_Url))
    | where isnotempty(PA_Url)
    | extend CommonSecurityLog_TimeGenerated = TimeGenerated
    ) on $left.Url == $right.PA_Url
    | where CommonSecurityLog_TimeGenerated < ExpirationDateTime
    | summarize CommonSecurityLog_TimeGenerated = arg_max(CommonSecurityLog_TimeGene
    rated, *) by IndicatorId, PA_Url
    | project timestamp = CommonSecurityLog_TimeGenerated, Description, ActivityGroupNames,
    IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore, DeviceAction,
    SourceIP, PA_Url, DeviceName
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI Map URL Entity to PaloAlto Data' 
   enabled: true 
   description: >
    This query identifies any URL indicators of compromise (IOCs) from threat intelligence
    (TI) by searching for matches in PaloAlto Data.
 
   alertRuleTemplateName: '106813db-679e-4382-a51b-1bfc463befc3' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
