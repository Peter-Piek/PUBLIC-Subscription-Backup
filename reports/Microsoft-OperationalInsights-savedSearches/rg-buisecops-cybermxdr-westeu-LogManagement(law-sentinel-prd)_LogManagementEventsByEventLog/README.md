# Count of Events grouped by Event Log

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'Count of Events grouped by Event Log' 
   version: 2 
   query: >
    Event | summarize AggregatedValue = count() by EventLog
    // Oql: Type=Event | Measure count() by EventLog // Args: {OQ: True; WorkspaceId:
    00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF:
    True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/law-sentinel
  -prd/savedSearches/LogManagement(law-sentinel-prd)_LogManagement|EventsByEventLo
  g
 
 name: 'LogManagement(law-sentinel-prd)_LogManagement|EventsByEventLog' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
