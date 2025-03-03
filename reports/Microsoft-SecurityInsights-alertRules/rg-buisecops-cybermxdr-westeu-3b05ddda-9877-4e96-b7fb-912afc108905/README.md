# TI map IP entity to Web Session Events (ASIM Web Session schema)

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/3b05ddda-9877
  -4e96-b7fb-912afc108905
 
 name: '3b05ddda-9877-4e96-b7fb-912afc108905' 
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
         columnName: 'DstIpAddr' 
   severity: 'Medium' 
   query: >
    let HAS_ANY_MAX = 10000;
    let dt_lookBack = 1h;
    let ioc_lookBack = 14d;
    let IP_TI = ThreatIntelligenceIndicator
    | where TimeGenerated >= ago(ioc_lookBack)
    // As there is potentially more than 1 indicator type for matching IP, taking
    NetworkIP first, then others if that is empty.
    // Taking the first non-empty value based on potential IOC match availability
    | extend TI_ipEntity = coalesce(NetworkIP, NetworkDestinationIP, NetworkSourceIP,
    EmailSourceIpAddress, "NO_IP")
    // Picking up only IOC's that contain the entities we want
    | where TI_ipEntity != "NO_IP"
    // Exclude local addresses, using the ipv4_is_private operator
    | where ipv4_is_private(TI_ipEntity) == false and TI_ipEntity !startswith "fe80"
    and TI_ipEntity !startswith "::" and TI_ipEntity !startswith "127."
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now();
    let IP_TI_list = toscalar(IP_TI
    | summarize NIoCs = dcount(TI_ipEntity), IoCs = make_set(TI_ipEntity)
    | project IoCs = iff(NIoCs > HAS_ANY_MAX, dynamic([]), IoCs));
    IP_TI
    // using innerunique to keep perf fast and result set low, we only need one match
    to indicate potential malicious activity that needs to be investigated
    | join kind = innerunique (
    _Im_WebSession (starttime = ago(dt_lookBack), srcipaddr_has_any_prefix = IP_
    TI_list)
    | where isnotempty(SrcIpAddr)
    // renaming time column so it is clear the log this came from
    | extend imNWS_TimeGenerated = TimeGenerated
    )
    on $left.TI_ipEntity == $right.SrcIpAddr
    | where imNWS_TimeGenerated < ExpirationDateTime
    | summarize imNWS_TimeGenerated = arg_max(imNWS_TimeGenerated, *) by IndicatorId,
    DstIpAddr
    | project imNWS_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, ExpirationDateTime, ConfidenceScore,
    TI_ipEntity, Dvc, SrcIpAddr, DstIpAddr, Url, Type
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map IP entity to Web Session Events (ASIM Web Session schema)' 
   enabled: true 
   description: >
    This rule identifies Web Sessions for which the source IP address is a known IoC.
    This rule uses the [Advanced Security Information Model (ASIM)](https://aka.ms/
    AboutASIM) and supports any web session source that complies with ASIM.
 
   alertRuleTemplateName: 'e2559891-383c-4caf-ae67-55a008b9f89e' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
