# DNS events related to ToR proxies

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/19a63f74-3960
  -4c3c-8626-757b946187e8
 
 name: '19a63f74-3960-4c3c-8626-757b946187e8' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Low' 
   query: >
    DnsEvents
    | where Name contains "."
    | where Name has_any ("tor2web.org", "tor2web.com", "torlink.co", "onion.to",
    "onion.ink", "onion.cab", "onion.nu", "onion.link",
    "onion.it", "onion.city", "onion.direct", "onion.top", "onion.casa", "onion.plus",
    "onion.rip", "onion.dog", "tor2web.fi",
    "tor2web.blutmagie.de", "onion.sh", "onion.lu", "onion.pet", "t2w.pw", "tor2web.ae.org",
    "tor2web.io", "tor2web.xyz", "onion.lt",
    "s1.tor-gateways.de", "s2.tor-gateways.de", "s3.tor-gateways.de", "s4.tor-gateways.de",
    "s5.tor-gateways.de", "hiddenservice.net")
    | extend HostName = iff(Computer has '.', substring(Computer,0,indexof(Computer,
    '.')),Computer)
    | extend DnsDomain = iff(Computer has '.', substring(Computer,indexof(Computer,'
    .')+1),"")
 
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
         columnName: 'ClientIP' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Exfiltration' 
   techniques: 
    - 'T1048' 
   subTechniques: null 
   displayName: 'DNS events related to ToR proxies' 
   enabled: true 
   description: >
    Identifies IP addresses performing DNS lookups associated with common ToR proxie
    s.
 
   alertRuleTemplateName: 'a83ef0f4-dace-4767-bce3-ebd32599d2a0' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
