# Count of Events with level "Warning" grouped by Event ID

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'Count of Events with level "Warning" grouped by Event ID' 
   version: 2 
   query: >
    Event | where EventLevelName == "warning" | summarize AggregatedValue = count()
    by EventID
    // Oql: Type=Event EventLevelName=warning | Measure count() by EventID // Args:
    {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT:
    True; SortI: True; SortF: True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/savedSearches/LogManagement(log-buisecops-cybermxdr-westeu)_L
  ogManagement|CountOfWarningEvents
 
 name: 'LogManagement(log-buisecops-cybermxdr-westeu)_LogManagement|CountOfWarningEvents' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
