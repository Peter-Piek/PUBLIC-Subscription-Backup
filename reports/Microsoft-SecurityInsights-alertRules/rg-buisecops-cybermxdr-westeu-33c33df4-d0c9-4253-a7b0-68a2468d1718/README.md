# TI map Domain entity to PaloAlto

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/33c33df4-d0c9
  -4253-a7b0-68a2468d1718
 
 name: '33c33df4-d0c9-4253-a7b0-68a2468d1718' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'P14D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h;  // Duration to look back for recent logs (1 hour)
    let ioc_lookBack = 14d;  // Duration to look back for recent threat intelligence
    indicators (14 days)
    // Create a list of top-level domains (TLDs) in our threat feed for later validation
    of extracted domains
    let list_tlds =
    ThreatIntelligenceIndicator
    | where isnotempty(DomainName)
    | where TimeGenerated >= ago(ioc_lookBack)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    | extend DomainName = tolower(DomainName)
    | extend parts = split(DomainName, '.')
    | extend tld = parts[(array_length(parts)-1)]
    | summarize count() by tostring(tld)
    | summarize make_list(tld);
    let Domain_Indicators =
    ThreatIntelligenceIndicator
    // Filter to pick up only IOC's that contain the entities we want (in this
    case, DomainName)
    | where isnotempty(DomainName)
    | where TimeGenerated >= ago(ioc_lookBack)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    | extend TI_DomainEntity = DomainName;
    Domain_Indicators
    // Join with CommonSecurityLog to find potential malicious activity
    | join kind=innerunique (
    CommonSecurityLog
    | extend IngestionTime = ingestion_time()
    | where IngestionTime > ago(dt_lookBack)
    | where DeviceVendor =~ 'Palo Alto Networks'
    | where DeviceEventClassID =~ 'url'
    // Uncomment the line below to only alert on allowed connections
    // | where DeviceAction !~ "block-url"
    // Extract domain from RequestURL, if not present, extract it from Addit
    ionalExtensions
    | extend PA_Url = coalesce(RequestURL, "None")
    | extend PA_Url = iif(isempty(PA_Url) and AdditionalExtensions !startswith
    "PanOS", extract("([^\"]+)", 1, tolower(AdditionalExtensions)), trim('"', PA_Ur
    l))
    | extend PA_Url = iif(PA_Url !in~ ('None', 'http://None', 'https://None')
    and PA_Url !startswith "http://" and PA_Url !startswith "https://" and
    ApplicationProtocol !~ "ssl", strcat('http://', PA_Url), PA_Url)
    | extend PA_Url = iif(PA_Url !in~ ('None', 'http://None', 'https://None')
    and PA_Url !startswith "https://" and ApplicationProtocol =~ "ssl", strcat('https://',
    PA_Url), PA_Url)
    | extend Domain = trim(@"""", tostring(parse_url(PA_Url).Host))
    | where isnotempty(Domain)
    | extend Domain = tolower(Domain)
    | extend parts = split(Domain, '.')
    // Split out the top-level domain (TLD) for the purpose of checking if we
    have any TI indicators with this TLD to match on
    | extend tld = parts[(array_length(parts)-1)]
    // Validate parsed domain by checking TLD against TLDs from the threat
    feed and drop domains where there is no chance of a match
    | where tld in~ (list_tlds)
    | extend CommonSecurityLog_TimeGenerated = TimeGenerated
    ) on $left.TI_DomainEntity == $right.Domain
    | where CommonSecurityLog_TimeGenerated < ExpirationDateTime
    // Group the results by IndicatorId and Domain and keep only the latest Comm
    onSecurityLog_TimeGenerated
    | summarize CommonSecurityLog_TimeGenerated = arg_max(CommonSecurityLog_Time
    Generated, *) by IndicatorId, Domain
    // Select the desired fields for the final result set
    | project CommonSecurityLog_TimeGenerated, Description, ActivityGroupNames,
    PA_Url, Domain, IndicatorId, ThreatType, ExpirationDateTime, ConfidenceScore,
    DeviceAction, DestinationIP, DestinationPort, DeviceName, SourceIP, SourcePort,
    ApplicationProtocol, RequestMethod, Type, TI_DomainEntity
    // Add a new field 'timestamp' for convenience, using the CommonSecurityLog_
    TimeGenerated as its value
    | extend timestamp = CommonSecurityLog_TimeGenerated
 
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
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Impact' 
   techniques: null 
   subTechniques: null 
   displayName: 'TI map Domain entity to PaloAlto' 
   enabled: true 
   description: >
    Identifies a match in Palo Alto data in CommonSecurityLog table from any Domain
    IOC from TI
 
   alertRuleTemplateName: 'ec21493c-2684-4acd-9bc2-696dbad72426' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
