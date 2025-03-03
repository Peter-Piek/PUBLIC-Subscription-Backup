# TI Map IP Entity to DnsEvents

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/41ae77f3-6371
  -414b-ae2d-e46d14766742
 
 name: '41ae77f3-6371-414b-ae2d-e46d14766742' 
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
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'ClientIP' 
    - 
      entityType: 'URL' 
      fieldMappings: 
       - 
         identifier: 'Url' 
         columnName: 'Url' 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h; // Look back 1 hour for DNS events
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
    // Perform a join between IP indicators and DNS events
    IP_Indicators
    // Use innerunique to keep performance fast and result set low, as we only need
    one match to indicate potential malicious activity that needs investigation
    | join kind=innerunique (
    DnsEvents
    | where TimeGenerated >= ago(dt_lookBack)
    | where SubType =~ "LookupQuery" and isnotempty(IPAddresses)
    | mv-expand SingleIP = split(IPAddresses, ", ") to typeof(string)
    | extend DNS_TimeGenerated = TimeGenerated
    )
    on $left.TI_ipEntity == $right.SingleIP
    // Filter out DNS events that occurred after the expiration of the corresponding
    indicator
    | where DNS_TimeGenerated < ExpirationDateTime
    // Group the results by IndicatorId and SingleIP, and keep the DNS event with
    the latest timestamp
    | summarize DNS_TimeGenerated = arg_max(DNS_TimeGenerated, *) by IndicatorId,
    SingleIP
    // Select the desired output fields
    | project DNS_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, Url, DomainName, ExpirationDateTime, ConfidenceScore,
    TI_ipEntity, Computer, EventId, SubType, ClientIP, Name, IPAddresses, NetworkIP,
    NetworkDestinationIP, NetworkSourceIP, EmailSourceIpAddress, Type
    | extend timestamp = DNS_TimeGenerated, HostName = tostring(split(Computer, '.',
    0)[0]), DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1,
    -1), '.'))
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI Map IP Entity to DnsEvents' 
   enabled: true 
   description: >
    This query maps any IP indicators of compromise (IOCs) from threat intelligence
    (TI), by searching for matches in DnsEvents.
 
   alertRuleTemplateName: '69b7723c-2889-469f-8b55-a2d355ed9c87' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
