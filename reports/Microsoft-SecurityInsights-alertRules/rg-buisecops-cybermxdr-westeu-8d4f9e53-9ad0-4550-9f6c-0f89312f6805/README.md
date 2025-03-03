# TI map Domain entity to PaloAlto CommonSecurityLog

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/8d4f9e53-9ad0
  -4550-9f6c-0f89312f6805
 
 name: '8d4f9e53-9ad0-4550-9f6c-0f89312f6805' 
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
    let dt_lookBack = 1h; // Look back 1 hour
    let ioc_lookBack = 14d; // Look back 14 days
    // Create a list of top-level domains (TLDs) from the threat feed data for later
    validation
    let SecurityLog = materialize(
    CommonSecurityLog
    // Filter common security logs based on the specified time range
    | extend IngestionTime = ingestion_time()
    | where IngestionTime > ago(dt_lookBack)
    | where DeviceEventClassID =~ 'url'
    // Uncomment the line below to only alert on allowed connections
    //| where DeviceAction !~ "block-url"
    // Extract the domain from RequestURL, if not present, extract it from Addit
    ionalExtensions
    | extend PA_Url = column_ifexists("RequestURL", "None")
    | extend PA_Url = iif(isempty(PA_Url) and AdditionalExtensions !startswith
    "PanOS", extract("([^\\\"]+)", 1, tolower(AdditionalExtensions)), trim('"', PA_
    Url))
    | extend PA_Url = iif(PA_Url !startswith "http://" and ApplicationProtocol !~
    "ssl", strcat('http://', PA_Url), iif(PA_Url !startswith "https://" and
    ApplicationProtocol =~ "ssl", strcat('https://', PA_Url), PA_Url))
    | extend Domain = trim('"', tostring(parse_url(PA_Url).Host))
    | where isnotempty(Domain)
    | extend Domain = tolower(Domain)
    | extend CommonSecurityLog_TimeGenerated = TimeGenerated
    );
    let LogDomains = SecurityLog | distinct Domain | summarize make_list(Domain);
    // Retrieve threat intelligence indicators within the specified time range
    let Domain_Indicators = materialize(
    ThreatIntelligenceIndicator
    | where isnotempty(DomainName)
    | where TimeGenerated >= ago(ioc_lookBack)
    | extend TI_DomainEntity = tolower(DomainName)
    | where TI_DomainEntity in (LogDomains)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now());
    // Join threat intelligence indicators with common security logs
    Domain_Indicators | join kind=innerunique (SecurityLog) on $left.TI_DomainEntity
    == $right.Domain
    | where CommonSecurityLog_TimeGenerated < ExpirationDateTime
    | summarize CommonSecurityLog_TimeGenerated = arg_max(CommonSecurityLog_TimeGene
    rated, *) by IndicatorId
    | project CommonSecurityLog_TimeGenerated, Description, ActivityGroupNames, PA_Url,
    Domain, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore, DeviceAction,
    DestinationIP, DestinationPort, DeviceName, SourceIP, SourcePort, ApplicationProtocol,
    RequestMethod, Type, TI_DomainEntity
    | extend timestamp = CommonSecurityLog_TimeGenerated
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map Domain entity to PaloAlto CommonSecurityLog' 
   enabled: true 
   description: >
    Identifies a match in PaloAlto CommonSecurityLog table from any Domain IOC from
    TI
 
   alertRuleTemplateName: 'dd0a6029-ecef-4507-89c4-fc355ac52111' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
