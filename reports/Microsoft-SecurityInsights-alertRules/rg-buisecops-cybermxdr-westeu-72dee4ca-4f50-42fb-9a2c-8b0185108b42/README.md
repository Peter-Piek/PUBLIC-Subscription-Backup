# TI Map URL Entity to SecurityAlert Data

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/72dee4ca-4f50
  -42fb-9a2c-8b0185108b42
 
 name: '72dee4ca-4f50-42fb-9a2c-8b0185108b42' 
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
         columnName: 'Compromised_Host' 
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
    let URLRegex = "((https?|ftp|ldap|wss?|file):\\/\\/(([\\:\\%\\w\\_\\-]+(\\.|@))*
    ((xn--)?[a-zA-Z0-9\\-]+\\.)+(xn--[a-z0-9]+|[A-Za-z]+)|\\d{1,3}\\.\\d{1,3}\\.\\d{
    1,3}\\.\\d{0,3})[.,:\\w@?^=%&\\/~+#-]*[\\w@?^=%&\\/~+#-])";
    let SecurityEvents = materialize(SecurityAlert
    | where TimeGenerated >= ago(dt_lookBack)
    | extend MSTI = case(AlertName has "TI map" and VendorName == "Microsoft" and
    ProductName == 'Azure Sentinel', true, false)
    | where MSTI == false
    // Extract URL from JSON data
    | mv-expand parse_json(Entities)
    | where isnotempty(Entities.Url) or isnotempty(Entities.Urls)
    | extend Url = coalesce(Entities.Url, Entities.Urls)
    | mv-expand Url
    | extend Url = tolower(Url)
    // Extract hostname from JSON data for entity mapping
    | extend Compromised_Host = tostring(parse_json(ExtendedProperties).["Compromi
    sed Host"])
    | extend Alert_TimeGenerated = TimeGenerated);
    let EventUrls = materialize(SecurityEvents | distinct Url | summarize make_list(
    Url));
    ThreatIntelligenceIndicator
    | where isnotempty(Url)
    | where TimeGenerated >= ago(ioc_lookBack)
    | extend Url = tolower(Url)
    | where tolower(Url) in (EventUrls)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    | where Description !contains_cs "State: inactive;" and Description !contains_cs
    "State: falsepos;"
    // using innerunique to keep perf fast and result set low, we only need one match
    to indicate potential malicious activity that needs to be investigated
    | join kind=innerunique (SecurityEvents) on Url
    | where Alert_TimeGenerated < ExpirationDateTime
    | summarize Alert_TimeGenerated = arg_max(Alert_TimeGenerated, *) by IndicatorId,
    AlertName
    | project timestamp = Alert_TimeGenerated, ActivityGroupNames, IndicatorId,
    ThreatType, ExpirationDateTime, ConfidenceScore, AlertName, AlertSeverity,
    Description, Url, Compromised_Host
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI Map URL Entity to SecurityAlert Data' 
   enabled: true 
   description: >
    This query identifies any URL indicators of compromise (IOCs) from threat intelligence
    (TI) by searching for matches in SecurityAlert data.
 
   alertRuleTemplateName: 'f30a47c1-65fb-42b1-a7f4-00941c12550b' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
