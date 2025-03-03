# TI map IP entity to AWSCloudTrail

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/82543892-5b30
  -459e-8c81-f16dfaf2b915
 
 name: '82543892-5b30-459e-8c81-f16dfaf2b915' 
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
         identifier: 'ObjectGuid' 
         columnName: 'UserIdentityUserName' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'SourceIpAddress' 
    - 
      entityType: 'URL' 
      fieldMappings: 
       - 
         identifier: 'Url' 
         columnName: 'Url' 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h; // Look back 1 hour for AWSCloudTrail logs
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
    // Perform a join between IP indicators and AWSCloudTrail logs to identify potential
    malicious activity
    IP_Indicators
    // Use innerunique to keep performance fast and result set low, as we only need
    one match to indicate potential malicious activity that needs investigation
    | join kind=innerunique (
    AWSCloudTrail
    | where TimeGenerated >= ago(dt_lookBack)
    | extend AWSCloudTrail_TimeGenerated = TimeGenerated // Rename time column
    for clarity
    )
    on $left.TI_ipEntity == $right.SourceIpAddress
    // Filter out logs that occurred after the expiration of the corresponding ind
    icator
    | where AWSCloudTrail_TimeGenerated < ExpirationDateTime
    // Group the results by IndicatorId and SourceIpAddress, and keep the log entry
    with the latest timestamp
    | summarize AWSCloudTrail_TimeGenerated = arg_max(AWSCloudTrail_TimeGenerated,
    *) by IndicatorId, SourceIpAddress
    // Select the desired output fields
    | project AWSCloudTrail_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, Url, ExpirationDateTime, ConfidenceScore,
    TI_ipEntity, EventName, EventTypeName, UserIdentityAccountId, UserIdentityPrincipalid,
    UserIdentityUserName, SourceIpAddress,
    NetworkIP, NetworkDestinationIP, NetworkSourceIP, EmailSourceIpAddress, Type
    // Rename the timestamp field
    | extend timestamp = AWSCloudTrail_TimeGenerated
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map IP entity to AWSCloudTrail' 
   enabled: true 
   description: 'Identifies a match in AWSCloudTrail from any IP IOC from TI' 
   alertRuleTemplateName: 'f110287e-1358-490d-8147-ed804b328514' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
