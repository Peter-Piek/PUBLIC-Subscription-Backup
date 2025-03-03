# Mass Cloud resource deletions Time Series Anomaly

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/bdc3ee75-201c
  -4e1f-a622-6cde74d2d924
 
 name: 'bdc3ee75-201c-4e1f-a622-6cde74d2d924' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
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
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'Name' 
         columnName: 'Name' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'UPNSuffix' 
       - 
         identifier: 'AadUserId' 
         columnName: 'AadUserId' 
   severity: 'Medium' 
   query: >
    let starttime = 14d;
    let endtime = 1d;
    let timeframe = 1d;
    let TotalEventsThreshold = 25;
    let TimeSeriesData = AzureActivity
    | where TimeGenerated between (startofday(ago(starttime))..startofday(now()))
    | where OperationNameValue endswith "delete"
    | project TimeGenerated, Caller
    | make-series Total = count() on TimeGenerated from startofday(ago(starttime)) to
    startofday(now()) step timeframe by Caller;
    TimeSeriesData
    | extend (anomalies, score, baseline) = series_decompose_anomalies(Total, 3, -1,
    'linefit')
    | mv-expand Total to typeof(double), TimeGenerated to typeof(datetime), anomalies
    to typeof(double), score to typeof(double), baseline to typeof(long)
    | where TimeGenerated >= startofday(ago(endtime))
    | where anomalies > 0
    | project Caller, TimeGenerated, Total, baseline, anomalies, score
    | where Total > TotalEventsThreshold and baseline > 0
    | join (AzureActivity
    | where TimeGenerated > startofday(ago(endtime))
    | where OperationNameValue endswith "delete"
    | summarize count(), make_set(OperationNameValue,100), make_set(_ResourceId,100)
    by bin(TimeGenerated, timeframe), Caller ) on TimeGenerated, Caller
    | extend Name = iif(Caller has '@',tostring(split(Caller,'@',0)[0]),"")
    | extend UPNSuffix = iif(Caller has '@',tostring(split(Caller,'@',1)[0]),"")
    | extend AadUserId = iif(Caller !has '@',Caller,"")
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: 
    - 'T1485' 
   displayName: 'Mass Cloud resource deletions Time Series Anomaly' 
   enabled: true 
   description: >
    This query generates the baseline pattern of cloud resource deletions by an
    individual and generates an anomaly when any unusual spike is detected. These
    anomalies from unusual or privileged users could be an indication of a cloud
    infrastructure takedown by an adversary.
 
   alertRuleTemplateName: 'ed43bdb7-eaab-4ea4-be52-6951fcfa7e3b' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
