# IIS Log Entries for a specific client IP Address (replace with your own)

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'IIS Log Entries for a specific client IP Address (replace with your own)' 
   version: 2 
   query: >
    search cIP == "192.168.0.1" | extend Type = $table | where Type == W3CIISLog |
    sort by TimeGenerated desc | project csUriStem, scBytes, csBytes, TimeTaken, sc
    Status
    // Oql: Type=W3CIISLog cIP="192.168.0.1" | Select csUriStem,scBytes,csBytes,Time
    Taken,scStatus // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-00000000
    0000} // Settings: {PEF: True; SortI: True; SortF: True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/law-sentinel
  -prd/savedSearches/LogManagement(law-sentinel-prd)_LogManagement|IISLogEntriesFo
  rClientIP
 
 name: 'LogManagement(law-sentinel-prd)_LogManagement|IISLogEntriesForClientIP' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
