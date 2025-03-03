# DNS events related to ToR proxies  (ASIM DNS Schema)

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/94120a31-a5c5
  -4bd0-8f53-2c384a871b96
 
 name: '94120a31-a5c5-4bd0-8f53-2c384a871b96' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
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
         identifier: 'HostName' 
         columnName: 'HostName' 
       - 
         identifier: 'DnsDomain' 
         columnName: 'HostNameDomain' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'SrcIpAddr' 
   severity: 'Low' 
   query: >
    let torProxies=dynamic(["tor2web.org", "tor2web.com", "torlink.co", "onion.to",
    "onion.ink", "onion.cab", "onion.nu", "onion.link",
    "onion.it", "onion.city", "onion.direct", "onion.top", "onion.casa", "onion.plus",
    "onion.rip", "onion.dog", "tor2web.fi",
    "tor2web.blutmagie.de", "onion.sh", "onion.lu", "onion.pet", "t2w.pw", "tor2web.ae.org",
    "tor2web.io", "tor2web.xyz", "onion.lt",
    "s1.tor-gateways.de", "s2.tor-gateways.de", "s3.tor-gateways.de", "s4.tor-gateways.de",
    "s5.tor-gateways.de", "hiddenservice.net"]);
    _Im_Dns(domain_has_any=torProxies)
    | extend HostName = tostring(split(Dvc, ".")[0]), DomainIndex = toint(indexof(Dvc,
    '.'))
    | extend HostNameDomain = iff(DomainIndex != -1, substring(Dvc, DomainIndex + 1),
    Dvc)
    | project-away DomainIndex
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Exfiltration' 
   techniques: 
    - 'T1048' 
   displayName: 'DNS events related to ToR proxies  (ASIM DNS Schema)' 
   enabled: true 
   description: >
    Identifies IP addresses performing DNS lookups associated with common ToR proxie
    s.
    This analytic rule uses [ASIM](https://aka.ms/AboutASIM) and supports any built-in
    or custom source that supports the ASIM DNS schema
 
   alertRuleTemplateName: '3fe3c520-04f1-44b8-8398-782ed21435f8' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
