# Count of Events grouped by Event Source

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'Count of Events grouped by Event Source' 
   version: 2 
   query: >
    Event | summarize AggregatedValue = count() by Source
    // Oql: Type=Event | Measure count() by Source // Args: {OQ: True; WorkspaceId:
    00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF:
    True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/Red_Team_RG/p
  roviders/Microsoft.OperationalInsights/workspaces/KObusTest/savedSearches/LogMan
  agement(KObusTest)_LogManagement|EventsByEventSource
 
 name: 'LogManagement(KObusTest)_LogManagement|EventsByEventSource' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
