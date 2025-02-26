# Rare client observed with high reverse DNS lookup count

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/57dcd67a-9e4d
  -42b4-b6cc-bae3376cd7dc
 
 name: '57dcd67a-9e4d-42b4-b6cc-bae3376cd7dc' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P8D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let starttime = 8d;
    let endtime = 1d;
    let threshold = 10;
    DnsEvents
    | where TimeGenerated > ago(endtime)
    | where Name has "in-addr.arpa"
    | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated),
    dcount(Name), ReverseDNSLookup_List = make_set(Name,100) by ClientIP
    | where dcount_Name > threshold
    | project StartTimeUtc, EndTimeUtc, ClientIP , dcount_Name, ReverseDNSLookup_Lis
    t
    // Filter out previously seen IPs
    // Returns all the records from the left side that don't have matches from the r
    ight
    | join kind=leftanti (DnsEvents
    | where TimeGenerated between(ago(starttime)..ago(endtime))
    | where Name has "in-addr.arpa"
    | summarize dcount(Name) by ClientIP, bin(TimeGenerated, 1d)
    | where dcount_Name > threshold
    | project ClientIP , dcount_Name
    ) on ClientIP
 
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
         columnName: 'ClientIP' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Discovery' 
   techniques: 
    - 'T1046' 
   subTechniques: null 
   displayName: 'Rare client observed with high reverse DNS lookup count' 
   enabled: true 
   description: >
    Identifies clients with a high reverse DNS counts that could be carrying out
    reconnaissance or discovery activity.
    Alerts are generated if the IP performing such reverse DNS lookups was not seen
    doing so in the preceding 7-day period.
 
   alertRuleTemplateName: '15ae38a2-2e29-48f7-883f-863fb25a5a06' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
