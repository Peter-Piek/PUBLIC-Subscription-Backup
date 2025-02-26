# Average HTTP Request time by Client IP Address

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'Average HTTP Request time by Client IP Address' 
   version: 2 
   query: >
    search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue
    = avg(TimeTaken) by cIP
    // Oql: Type=W3CIISLog | Measure Avg(TimeTaken) by cIP // Args: {OQ: True;
    WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI:
    True; SortF: True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/law-sentinel
  -prd/savedSearches/LogManagement(law-sentinel-prd)_LogManagement|AverageHTTPRequ
  estTimeByClientIPAddress
 
 name: >
  LogManagement(law-sentinel-prd)_LogManagement|AverageHTTPRequestTimeByClientIPAd
  dress
 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
