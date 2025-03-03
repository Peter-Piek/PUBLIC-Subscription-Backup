# TI map IP entity to OfficeActivity

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/871f24d8-fb86
  -4194-be3c-be79527021cf
 
 name: '871f24d8-fb86-4194-be3c-be79527021cf' 
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
         columnName: 'Name' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'UPNSuffix' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'TI_ipEntity' 
    - 
      entityType: 'URL' 
      fieldMappings: 
       - 
         identifier: 'Url' 
         columnName: 'Url' 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h; // Look back 1 hour for OfficeActivity events
    let ioc_lookBack = 14d; // Look back 14 days for threat intelligence indicators
    let OfficeActivity_ = materialize(OfficeActivity
    | where isnotempty(ClientIP)
    | where TimeGenerated >= ago(dt_lookBack)
    | extend ClientIPValues = extract_all(@'\[?(::ffff:)?(?P<IPAddress>(\d+\.\d+\.
    \d+\.\d+)|[^\]%]+)(%\d+)?\]?([-:](?P<Port>\d+))?', dynamic(["IPAddress", "Port"]),
    ClientIP)[0]
    | extend IPAddress = iff(array_length(ClientIPValues) > 0, tostring(ClientIPValues[0]),
    '')
    | project-rename OfficeActivity_TimeGenerated = TimeGenerated);
    let ActivityIPs = OfficeActivity_ | summarize IPs = make_list(IPAddress);
    // Fetch threat intelligence indicators related to IP addresses
    let IP_Indicators = materialize(ThreatIntelligenceIndicator
    | where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempt
    y(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
    | where TimeGenerated >= ago(ioc_lookBack)
    | extend TI_ipEntity = coalesce(NetworkDestinationIP, NetworkSourceIP, EmailSo
    urceIpAddress)
    | where TI_ipEntity in (ActivityIPs)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where  Active == true and ExpirationDateTime > now()
    | where Description !contains_cs "State: inactive;" and Description !contains_cs
    "State: falsepos;");
    IP_Indicators
    // Use innerunique to keep performance fast and result set low, as we only need
    one match to indicate potential malicious activity that needs investigation
    | join kind=innerunique (OfficeActivity_)
    on $left.TI_ipEntity == $right.IPAddress
    // Filter out OfficeActivity events that occurred after the expiration of the
    corresponding indicator
    | where OfficeActivity_TimeGenerated < ExpirationDateTime
    // Group the results by IndicatorId and keep the OfficeActivity event with the
    latest timestamp
    | summarize OfficeActivity_TimeGenerated = arg_max(OfficeActivity_TimeGenerated,
    *) by IndicatorId
    // Select the desired output fields
    | project OfficeActivity_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, Url, ExpirationDateTime, ConfidenceScore, TI_ipEntity, ClientIP,
    UserId, Operation, ResultStatus, RecordType, OfficeObjectId, NetworkIP,
    NetworkDestinationIP, NetworkSourceIP, EmailSourceIpAddress, Type
    | extend timestamp = OfficeActivity_TimeGenerated, Name = tostring(split(UserId,
    '@', 0)[0]), UPNSuffix = tostring(split(UserId, '@', 1)[0])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map IP entity to OfficeActivity' 
   enabled: true 
   description: >
    This query maps any IP indicators of compromise (IOCs) from threat intelligence
    (TI), by searching for matches in OfficeActivity.
 
   alertRuleTemplateName: 'f15370f4-c6fa-42c5-9be4-1d308f40284e' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
