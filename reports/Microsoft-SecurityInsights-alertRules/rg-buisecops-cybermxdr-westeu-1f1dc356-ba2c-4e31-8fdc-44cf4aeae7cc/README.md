# TI Map IP Entity to CommonSecurityLog

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/1f1dc356-ba2c
  -4e31-8fdc-44cf4aeae7cc
 
 name: '1f1dc356-ba2c-4e31-8fdc-44cf4aeae7cc' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'P14D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let IPRegex = '[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}';
    let dt_lookBack = 1h; // Look back 1 hour for CommonSecurityLog events
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
    // Perform a join between IP indicators and CommonSecurityLog events
    IP_Indicators
    // Use innerunique to keep performance fast and result set low, as we only need
    one match to indicate potential malicious activity that needs investigation
    | join kind=innerunique (
    CommonSecurityLog
    | where TimeGenerated >= ago(dt_lookBack)
    | extend MessageIP = extract(IPRegex, 0, Message)
    | extend CS_ipEntity = iff(isnotempty(SourceIP), SourceIP, DestinationIP)
    | extend CS_ipEntity = iff(isempty(CS_ipEntity) and isnotempty(MessageIP),
    MessageIP, CS_ipEntity)
    | extend CommonSecurityLog_TimeGenerated = TimeGenerated
    )
    on $left.TI_ipEntity == $right.CS_ipEntity
    // Filter out logs that occurred after the expiration of the corresponding ind
    icator
    | where CommonSecurityLog_TimeGenerated < ExpirationDateTime
    // Group the results by IndicatorId and CS_ipEntity, and keep the log entry with
    the latest timestamp
    | summarize CommonSecurityLog_TimeGenerated = arg_max(CommonSecurityLog_TimeGe
    nerated, *) by IndicatorId, CS_ipEntity
    // Select the desired output fields
    | project timestamp = CommonSecurityLog_TimeGenerated, SourceIP, DestinationIP,
    MessageIP, Message, DeviceVendor, DeviceProduct, IndicatorId, ThreatType,
    ExpirationDateTime, ConfidenceScore, TI_ipEntity, CS_ipEntity, LogSeverity,
    DeviceAction, Type
 
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
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'CS_ipEntity' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Impact' 
   techniques: null 
   subTechniques: null 
   displayName: 'TI Map IP Entity to CommonSecurityLog' 
   enabled: true 
   description: >
    This query maps any IP indicators of compromise (IOCs) from threat intelligence
    (TI), by searching for matches in CommonSecurityLog.
 
   alertRuleTemplateName: '66c81ae2-1f89-4433-be00-2fbbd9ba5ebe' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
