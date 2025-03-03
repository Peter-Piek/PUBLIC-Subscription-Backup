# TI map Domain entity to Dns Events (ASIM DNS Schema)

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/8d06f1ad-29ba
  -4c91-9add-089fc25f1479
 
 name: '8d06f1ad-29ba-4c91-9add-089fc25f1479' 
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
         columnName: 'HostCustomEntity' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'IPCustomEntity' 
    - 
      entityType: 'URL' 
      fieldMappings: 
       - 
         identifier: 'Url' 
         columnName: 'URLCustomEntity' 
   severity: 'Medium' 
   query: >
    let HAS_ANY_MAX = 10000;
    let dt_lookBack = 1h;
    let ioc_lookBack = 14d;
    let DomainTIs= ThreatIntelligenceIndicator
    // Picking up only IOC's that contain the entities we want
    | where isnotempty(DomainName)
    | where TimeGenerated >= ago(ioc_lookBack)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now();
    let Domains = DomainTIs | where isnotempty(DomainName) |summarize NDomains=dcount(DomainName),
    DomainsList=make_set(DomainName)
    | project DomainList = iff(NDomains > HAS_ANY_MAX, dynamic([]), DomainsList) ;
    DomainTIs
    | join (
    _Im_Dns(starttime=ago(dt_lookBack), domain_has_any=toscalar(Domains))
    | extend DNS_TimeGenerated = TimeGenerated
    ) on $left.DomainName==$right.DnsQuery
    | where DNS_TimeGenerated < ExpirationDateTime
    | project LatestIndicatorTime, Description, ActivityGroupNames, IndicatorId,
    ThreatType, ExpirationDateTime, ConfidenceScore, Url, DNS_TimeGenerated, Dvc,
    SrcIpAddr, DnsQuery, DnsQueryType
    | extend timestamp = DNS_TimeGenerated, HostCustomEntity = Dvc, IPCustomEntity =
    SrcIpAddr, URLCustomEntity = Url
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map Domain entity to Dns Events (ASIM DNS Schema)' 
   enabled: true 
   description: >
    Identifies a match in DNS events from any Domain IOC from TI
    This analytic rule uses [ASIM](https://aka.ms/AboutASIM) and supports any built-in
    or custom source that supports the ASIM DNS schema
 
   alertRuleTemplateName: '999e9f5d-db4a-4b07-a206-29c4e667b7e8' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
