# All Events with level "Warning"

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'All Events with level "Warning"' 
   version: 2 
   query: >
    Event | where EventLevelName == "warning" | sort by TimeGenerated desc
    // Oql: Type=Event EventLevelName=warning // Args: {OQ: True; WorkspaceId: 00000
    000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True}
    // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/Red_Team_RG/p
  roviders/Microsoft.OperationalInsights/workspaces/KObusTest/savedSearches/LogMan
  agement(KObusTest)_LogManagement|WarningEvents
 
 name: 'LogManagement(KObusTest)_LogManagement|WarningEvents' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
