# How many connections to Operations Manager's SDK service by day

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'How many connections to Operations Manager''s SDK service by day' 
   version: 2 
   query: >
    Event | where EventID == 26328 and EventLog == "Operations Manager" | summarize
    AggregatedValue = count() by bin(TimeGenerated, 1d) | sort by TimeGenerated des
    c
    // Oql: Type=Event EventID=26328 EventLog="Operations Manager" | Measure count()
    interval 1DAY // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-00000000
    0000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/law-sentinel
  -prd/savedSearches/LogManagement(law-sentinel-prd)_LogManagement|NoOfConnections
  ToOMSDKService
 
 name: 'LogManagement(law-sentinel-prd)_LogManagement|NoOfConnectionsToOMSDKService' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
