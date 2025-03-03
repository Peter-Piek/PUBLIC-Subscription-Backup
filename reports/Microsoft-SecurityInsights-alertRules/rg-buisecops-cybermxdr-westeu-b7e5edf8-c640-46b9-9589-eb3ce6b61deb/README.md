# TI map IP entity to Network Session Events (ASIM Network Session schema)

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/b7e5edf8-c640
  -46b9-9589-eb3ce6b61deb
 
 name: 'b7e5edf8-c640-46b9-9589-eb3ce6b61deb' 
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
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'IoCIP' 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h;
    let ioc_lookBack = 14d;
    let IP_TI = materialize (
    ThreatIntelligenceIndicator
    | where TimeGenerated >= ago(ioc_lookBack)
    | extend TI_ipEntity = coalesce(NetworkIP, NetworkDestinationIP, NetworkSource
    IP,EmailSourceIpAddress,"NO_IP")
    | where TI_ipEntity != "NO_IP"
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    );
    IP_TI
    // using innerunique to keep perf fast and result set low, we only need one match
    to indicate potential malicious activity that needs to be investigated
    | join kind=innerunique
    (
    _Im_NetworkSession (starttime=ago(dt_lookBack))
    | where isnotempty(SrcIpAddr)
    | summarize imNWS_mintime=min(TimeGenerated), imNWS_maxtime=max(TimeGenerated)
    by SrcIpAddr, DstIpAddr, Dvc, EventProduct, EventVendor
    | lookup (IP_TI | project TI_ipEntity, Active) on $left.SrcIpAddr == $right.TI
    _ipEntity
    | project-rename SrcMatch = Active
    | lookup (IP_TI | project TI_ipEntity, Active) on $left.DstIpAddr == $right.TI
    _ipEntity
    | project-rename DstMatch = Active
    | where SrcMatch or DstMatch
    | extend
    IoCIP = iff(SrcMatch, SrcIpAddr, DstIpAddr),
    IoCDirection = iff(SrcMatch, "Source", "Destination")
    )on $left.TI_ipEntity == $right.IoCIP
    | where imNWS_mintime < ExpirationDateTime
    | project imNWS_mintime, imNWS_maxtime, Description, ActivityGroupNames, IndicatorId,
    ThreatType, ExpirationDateTime, ConfidenceScore, SrcIpAddr, DstIpAddr, IoCDirection,
    IoCIP, Dvc, EventVendor, EventProduct
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map IP entity to Network Session Events (ASIM Network Session schema)' 
   enabled: true 
   description: >
    This rule identifies a match Network Sessions for which the source or destination
    IP address is a known IoC. This analytic rule uses [ASIM](https://aka.ms/AboutA
    SIM) and supports any built-in or custom source that supports the ASIM NetworkSession
    schema
 
   alertRuleTemplateName: 'e2399891-383c-4caf-ae67-68a008b9f89e' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
