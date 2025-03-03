# TI map Domain entity to Web Session Events (ASIM Web Session schema)

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/2bf997b3-3089
  -46f1-971f-43cb3559bb03
 
 name: '2bf997b3-3089-46f1-971f-43cb3559bb03' 
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
         columnName: 'SrcIpAddr' 
    - 
      entityType: 'URL' 
      fieldMappings: 
       - 
         identifier: 'Url' 
         columnName: 'Url' 
   severity: 'Medium' 
   query: >
    let HAS_ANY_MAX = 10000;
    let dt_lookBack = 1h;
    let ioc_lookBack = 14d;
    //Create a list of TLDs in our threat feed for later validation
    let DOMAIN_TI=ThreatIntelligenceIndicator
    // Picking up only IOC's that contain the entities we want
    | where isnotempty(DomainName)
    | where TimeGenerated >= ago(ioc_lookBack)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now();
    let DOMAIN_TI_list= todynamic(toscalar(DOMAIN_TI | summarize NIoCs = dcount(DomainName),
    Domains = make_set(DomainName)
    | project Domains=iff(NIoCs > HAS_ANY_MAX, dynamic([]), Domains) ));
    DOMAIN_TI
    // using innerunique to keep perf fast and result set low, we only need one match
    to indicate potential malicious activity that needs to be investigated
    | join kind=innerunique (
    _Im_WebSession(starttime=ago(dt_lookBack), url_has_any= DOMAIN_TI_list )
    //Extract domain patterns from syslog message
    | extend domain = tostring(parse_url(Url)["Host"])
    | where isnotempty(domain)
    | extend tld = tostring(split(domain, '.')[-1])
    | extend Event_TimeGenerated = TimeGenerated
    ) on $left.DomainName==$right.domain
    | where Event_TimeGenerated < ExpirationDateTime
    | summarize Event_TimeGenerated  = arg_max(Event_TimeGenerated , *) by IndicatorId,
    domain
    | project Event_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, ExpirationDateTime, ConfidenceScore, domain, SrcIpAddr, Url
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map Domain entity to Web Session Events (ASIM Web Session schema)' 
   enabled: true 
   description: >
    This rule identifies Web Sessions for which the target URL hostname is a known
    IoC. This rule uses the [Advanced Security Information Model (ASIM)](https:/aka
    .ms/AboutASIM) and supports any web session source that complies with ASIM.
 
   alertRuleTemplateName: 'b1832f60-6c3d-4722-a0a5-3d564ee61a63' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
