# TI map IP entity to AppServiceHTTPLogs

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/09370d28-6702
  -4efa-9ad5-6b9974c20294
 
 name: '09370d28-6702-4efa-9ad5-6b9974c20294' 
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
         columnName: 'HostName' 
       - 
         identifier: 'DnsDomain' 
         columnName: 'DnsDomain' 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'Name' 
         columnName: 'CsUsername' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'CIp' 
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
         columnName: '_ResourceId' 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h; // Look back 1 hour for AppServiceHTTPLogs
    let ioc_lookBack = 14d; // Look back 14 days for threat intelligence indicators
    // Fetch threat intelligence indicators related to IP addresses
    let IP_Indicators = ThreatIntelligenceIndicator
    // Filter out indicators without relevant IP address fields
    | where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempt
    y(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
    | where TimeGenerated >= ago(ioc_lookBack)
    // Filtering out rows where the Confidence Score is less than 50 as they would
    not have an Alert Priority label.
    | where ConfidenceScore > 50
    // Select the IP entity based on availability of different IP fields
    | extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinatio
    nIP)
    | extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP),
    NetworkSourceIP, TI_ipEntity)
    | extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAd
    dress), EmailSourceIpAddress, TI_ipEntity)
    // Determine AlertPriority based on ConfidenceScore
    | extend AlertPriority = case(ConfidenceScore > 82, "High",
    ConfidenceScore > 74, "Medium",
    "Low")
    // Exclude local addresses using the ipv4_is_private operator and filtering out
    specific address prefixes
    | where ipv4_is_private(TI_ipEntity) == false and  TI_ipEntity !startswith "fe80"
    and TI_ipEntity !startswith "::" and TI_ipEntity !startswith "127."
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now();
    // Perform a join between IP indicators and AppServiceHTTPLogs to identify potential
    malicious activity
    IP_Indicators
    // Use innerunique to keep performance fast and result set low, as we only need
    one match to indicate potential malicious activity that needs investigation
    | join kind=innerunique (
    AppServiceHTTPLogs | where TimeGenerated >= ago(dt_lookBack)
    | where isnotempty(CIp)
    | extend WebApp = split(_ResourceId, '/')[8]
    | extend AppService_TimeGenerated = TimeGenerated // Rename time column for
    clarity
    )
    on $left.TI_ipEntity == $right.CIp
    // Filter out logs that occurred after the expiration of the corresponding ind
    icator
    | where AppService_TimeGenerated < ExpirationDateTime
    // Group the results by IndicatorId and CIp, and keep the log entry with the
    latest timestamp
    | summarize AppService_TimeGenerated = arg_max(AppService_TimeGenerated, *) by
    IndicatorId, CIp
    // Select the desired output fields
    | project AppService_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, Url, ExpirationDateTime, ConfidenceScore, TI_ipEntity, CsUsername,
    WebApp = split(_ResourceId, '/')[8], CIp, CsHost, NetworkIP, NetworkDestinationIP,
    NetworkSourceIP, EmailSourceIpAddress, _ResourceId, Type
    // Extract hostname and DNS domain from the CsHost field
    | extend HostName = tostring(split(CsHost, '.', 0)[0]), DnsDomain = tostring(s
    trcat_array(array_slice(split(CsHost, '.'), 1, -1), '.'))
    // Rename the timestamp field
    | extend timestamp = AppService_TimeGenerated
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map IP entity to AppServiceHTTPLogs' 
   enabled: true 
   description: 'Identifies a match in AppServiceHTTPLogs from any IP IOC from TI' 
   alertRuleTemplateName: 'f9949656-473f-4503-bf43-a9d9890f7d08' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
