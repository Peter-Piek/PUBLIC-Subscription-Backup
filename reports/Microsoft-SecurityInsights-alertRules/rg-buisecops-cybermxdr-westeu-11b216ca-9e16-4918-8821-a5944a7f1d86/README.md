# TI Map IP Entity to VMConnection

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/11b216ca-9e16
  -4918-8821-a5944a7f1d86
 
 name: '11b216ca-9e16-4918-8821-a5944a7f1d86' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'P14D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h; // Look back 1 hour for VMConnection events
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
    | where ipv4_is_private(TI_ipEntity) == false and  TI_ipEntity !startswith "fe80"
    and TI_ipEntity !startswith "::" and TI_ipEntity !startswith "127."
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now();
    // Perform a join between IP indicators and VMConnection events
    IP_Indicators
    // Use innerunique to keep performance fast and result set low, as we only need
    one match to indicate potential malicious activity that needs investigation
    | join kind=innerunique (
    VMConnection
    | where TimeGenerated >= ago(dt_lookBack)
    | extend VMConnection_TimeGenerated = TimeGenerated
    )
    on $left.TI_ipEntity == $right.RemoteIp
    // Filter out VMConnection events that occurred after the expiration of the
    corresponding indicator
    | where VMConnection_TimeGenerated < ExpirationDateTime
    // Group the results by IndicatorId and keep the VMConnection event with the
    latest timestamp
    | summarize VMConnection_TimeGenerated = arg_max(VMConnection_TimeGenerated, *)
    by IndicatorId, RemoteIp
    // Select the desired output fields
    | project VMConnection_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, Url, ExpirationDateTime, ConfidenceScore,
    TI_ipEntity, Computer, Direction, ProcessName, SourceIp, DestinationIp, RemoteIp,
    Protocol, DestinationPort, NetworkIP, NetworkDestinationIP, NetworkSourceIP,
    EmailSourceIpAddress, Type
    | extend timestamp = VMConnection_TimeGenerated, HostName = tostring(split(Computer,
    '.', 0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'),
    1, -1), '.'))
 
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
         columnName: 'HostName' 
       - 
         identifier: 'DnsDomain' 
         columnName: 'DnsDomain' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'RemoteIp' 
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
   displayName: 'TI Map IP Entity to VMConnection' 
   enabled: true 
   description: >
    This query maps any IP indicators of compromise (IOCs) from threat intelligence
    (TI), by searching for matches in VMConnection.
 
   alertRuleTemplateName: '9713e3c0-1410-468d-b79e-383448434b2d' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
