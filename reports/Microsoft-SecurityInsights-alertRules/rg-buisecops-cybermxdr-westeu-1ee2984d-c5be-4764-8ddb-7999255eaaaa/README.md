# TI Map IP Entity to AzureActivity

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/1ee2984d-c5be
  -4764-8ddb-7999255eaaaa
 
 name: '1ee2984d-c5be-4764-8ddb-7999255eaaaa' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'P14D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h; // Look back 1 hour for AzureActivity logs
    let ioc_lookBack = 14d; // Look back 14 days for threat intelligence indicators
    // Fetch threat intelligence indicators related to IP addresses
    let IP_Indicators = ThreatIntelligenceIndicator
    // Filter out indicators without relevant IP address fields
    | where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempt
    y(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
    | where TimeGenerated >= ago(ioc_lookBack)
    // Select the IP entity based on availability of different IP fields
    | extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinatio
    nIP)
    | extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP),
    NetworkSourceIP, TI_ipEntity)
    | extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAd
    dress), EmailSourceIpAddress, TI_ipEntity)
    // Exclude local addresses using the ipv4_is_private operator and filtering out
    specific address prefixes
    | where ipv4_is_private(TI_ipEntity) == false and  TI_ipEntity !startswith "fe80"
    and TI_ipEntity !startswith "::" and TI_ipEntity !startswith "127."
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now();
    // Perform a join between IP indicators and AzureActivity logs to identify potential
    malicious activity
    IP_Indicators
    // using innerunique to keep perf fast and result set low, we only need one match
    to indicate potential malicious activity that needs to be investigated
    | join kind=innerunique (
    AzureActivity | where TimeGenerated >= ago(dt_lookBack)
    // renaming time column so it is clear the log this came from
    | extend AzureActivity_TimeGenerated = TimeGenerated
    )
    on $left.TI_ipEntity == $right.CallerIpAddress
    | where AzureActivity_TimeGenerated < ExpirationDateTime
    | summarize AzureActivity_TimeGenerated = arg_max(AzureActivity_TimeGenerated, *)
    by IndicatorId, CallerIpAddress
    | project AzureActivity_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, Url, ExpirationDateTime, ConfidenceScore, TI_ipEntity, CallerIpAddress,
    
    Caller, OperationNameValue, ActivityStatusValue, CategoryValue, ResourceId,
    NetworkIP, NetworkDestinationIP, NetworkSourceIP, EmailSourceIpAddress, Type
    | extend timestamp = AzureActivity_TimeGenerated
    | extend Name = iif(Caller has '@', tostring(split(Caller,'@',0)[0]), "")
    | extend UPNSuffix = iif(Caller has '@', tostring(split(Caller,'@',1)[0]), "")
    | extend AadUserId = iif(Caller !has '@', tostring(Caller), "")
 
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
         identifier: 'AadUserId' 
         columnName: 'AadUserId' 
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
    - 
      entityType: 'AzureResource' 
      fieldMappings: 
       - 
         identifier: 'ResourceId' 
         columnName: 'ResourceId' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Impact' 
   techniques: null 
   subTechniques: null 
   displayName: 'TI Map IP Entity to AzureActivity' 
   enabled: true 
   description: >
    This query maps any IP indicators of compromise (IOCs) from threat intelligence
    (TI), by searching for matches in AzureActivity.
 
   alertRuleTemplateName: '2441bce9-02e4-407b-8cc7-7d597f38b8b0' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
