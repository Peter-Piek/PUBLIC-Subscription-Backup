# Daily Data Limit At 80% [Custom]

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/c69cc178-a349
  -493b-95eb-7f0fbbfc7887
 
 name: 'c69cc178-a349-493b-95eb-7f0fbbfc7887' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'PT1H' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'High' 
   query: >
    Usage
    | where IsBillable
    | summarize DataGB = sum(Quantity /1000.)
    | where DataGB > 8.
 
   suppressionDuration: 'PT12H' 
   suppressionEnabled: true 
   incidentConfiguration: 
     createIncident: true 
     groupingConfiguration: 
       enabled: null 
       reopenClosedIncident: null 
       lookbackDuration: 'PT5H' 
       matchingMethod: 'AllEntities' 
       groupByEntities: null 
       groupByAlertDetails: null 
       groupByCustomDetails: null 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: null 
   techniques: null 
   subTechniques: null 
   displayName: 'Daily Data Limit At 80% [Custom]' 
   enabled: true 
   description: >
    To alert if the billable data volume ingested in the last 24 hours was greater
    than 80% of daily data limit.
 
   alertRuleTemplateName: null 
   lastModifiedUtc: 2024-10-30T13:02:29
```
