# TI Map IP Entity to W3CIISLog

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/f8009e11-7b77
  -4402-8585-8789fcbecdd0
 
 name: 'f8009e11-7b77-4402-8585-8789fcbecdd0' 
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
         identifier: 'Name' 
         columnName: 'csUserName' 
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
         columnName: 'cIP' 
    - 
      entityType: 'URL' 
      fieldMappings: 
       - 
         identifier: 'Url' 
         columnName: 'Url' 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h; // Look back 1 hour for W3CIISLog events
    let ioc_lookBack = 14d; // Look back 14 days for threat intelligence indicators
    // Fetch threat intelligence indicators related to IP addresses
    let IP_Indicators = ThreatIntelligenceIndicator
    | where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempt
    y(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
    | where TimeGenerated >= ago(ioc_lookBack)
    | extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinatio
    nIP)
    | extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP),
    NetworkSourceIP, TI_ipEntity)
    | extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAd
    dress), EmailSourceIpAddress, TI_ipEntity)
    | where ipv4_is_private(TI_ipEntity) == false and TI_ipEntity !startswith "fe80"
    and TI_ipEntity !startswith "::" and TI_ipEntity !startswith "127."
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now();
    // Perform a join between IP indicators and W3CIISLog events
    IP_Indicators
    // Use innerunique to keep performance fast and result set low, as we only need
    one match to indicate potential malicious activity that needs investigation
    | join kind=innerunique (
    W3CIISLog
    | where TimeGenerated >= ago(dt_lookBack)
    | where isnotempty(cIP)
    | where ipv4_is_private(cIP) == false and cIP !startswith "fe80" and cIP
    !startswith "::" and cIP !startswith "127."
    | extend W3CIISLog_TimeGenerated = TimeGenerated
    )
    on $left.TI_ipEntity == $right.cIP
    // Filter out W3CIISLog events that occurred after the expiration of the
    corresponding indicator
    | where W3CIISLog_TimeGenerated < ExpirationDateTime
    // Group the results by IndicatorId and keep the W3CIISLog event with the latest
    timestamp
    | summarize W3CIISLog_TimeGenerated = arg_max(W3CIISLog_TimeGenerated, *) by
    IndicatorId, cIP
    // Select the desired output fields
    | project timestamp = W3CIISLog_TimeGenerated, Description, ActivityGroupNames,
    IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
    TI_ipEntity, Computer, sSiteName, cIP, sIP, sPort, csMethod, csUserName,
    scStatus, scSubStatus, scWin32Status,
    NetworkIP, NetworkDestinationIP, NetworkSourceIP, EmailSourceIpAddress, Type
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI Map IP Entity to W3CIISLog' 
   enabled: true 
   description: >
    This query maps any IP indicators of compromise (IOCs) from threat intelligence
    (TI), by searching for matches in W3CIISLog.
 
   alertRuleTemplateName: '5e45930c-09b1-4430-b2d1-cc75ada0dc0f' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
