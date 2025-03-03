# TI map IP entity to DNS Events (ASIM DNS schema)

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/dda77484-fa3d
  -4c11-b080-38eb2abfe2ef
 
 name: 'dda77484-fa3d-4c11-b080-38eb2abfe2ef' 
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
         identifier: 'FullName' 
         columnName: 'Dvc' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'IoC' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'SrcIpAddr' 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h;
    let ioc_lookBack = 14d;
    let IP_TI =
    ThreatIntelligenceIndicator
    | where TimeGenerated >= ago(ioc_lookBack)
    | extend IoC = coalesce(NetworkIP, NetworkDestinationIP, NetworkSourceIP,EmailSo
    urceIpAddress,"NO_IP")
    | where IoC != "NO_IP"
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now();
    IP_TI
    | join kind=innerunique // using innerunique to keep perf fast and result set low,
    we only need one match to indicate potential malicious activity that needs to be
    investigated
    (
    _Im_Dns(starttime=ago(dt_lookBack))
    | where isnotempty(DnsResponseName)
    | summarize imDns_mintime=min(TimeGenerated), imDns_maxtime=max(TimeGenerated) by
    SrcIpAddr, DnsQuery, DnsResponseName, Dvc, EventProduct, EventVendor
    | extend addresses = extract_all (@'(\d+\.\d+\.\d+\.\d+)', DnsResponseName)
    | mv-expand IoC = addresses to typeof(string)
    )
    on IoC
    | where imDns_mintime < ExpirationDateTime
    | project imDns_mintime, imDns_maxtime, Description, ActivityGroupNames, IndicatorId,
    ThreatType, LatestIndicatorTime, ExpirationDateTime, ConfidenceScore, SrcIpAddr,
    IoC, Dvc, EventVendor, EventProduct, DnsQuery, DnsResponseName
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map IP entity to DNS Events (ASIM DNS schema)' 
   enabled: true 
   description: >
    This rule identifies DNS requests for which response IP address is a known IoC.
    This analytic rule uses [ASIM](https://aka.ms/AboutASIM) and supports any built-in
    or custom source that supports the ASIM DNS schema.
 
   alertRuleTemplateName: '67775878-7f8b-4380-ac54-115e1e828901' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
