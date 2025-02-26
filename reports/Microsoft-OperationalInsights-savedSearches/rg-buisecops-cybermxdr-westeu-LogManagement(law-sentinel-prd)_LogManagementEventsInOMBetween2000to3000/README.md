# Events in the Operations Manager Event Log whose Event ID is in the range between 2000 and 3000

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: >
    Events in the Operations Manager Event Log whose Event ID is in the range between
    2000 and 3000
 
   version: 2 
   query: >
    Event | where EventLog == "Operations Manager" and EventID >= 2000 and EventID <=
    3000 | sort by TimeGenerated desc
    // Oql: Type=Event EventLog="Operations Manager" EventID:[2000..3000] // Args:
    {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PTT:
    True; SortI: True; SortF: True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/law-sentinel
  -prd/savedSearches/LogManagement(law-sentinel-prd)_LogManagement|EventsInOMBetwe
  en2000to3000
 
 name: 'LogManagement(law-sentinel-prd)_LogManagement|EventsInOMBetween2000to3000' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
