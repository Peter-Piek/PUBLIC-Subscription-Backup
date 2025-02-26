# Shows which pages people are getting a 404 for

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'Shows which pages people are getting a 404 for' 
   version: 2 
   query: >
    search scStatus == 404 | extend Type = $table | where Type == W3CIISLog | summarize
    AggregatedValue = count() by csUriStem
    // Oql: Type=W3CIISLog scStatus=404 | Measure count() by csUriStem // Args: {OQ:
    True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True;
    SortI: True; SortF: True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/Red_Team_RG/p
  roviders/Microsoft.OperationalInsights/workspaces/KObusTest/savedSearches/LogMan
  agement(KObusTest)_LogManagement|Show404PagesList
 
 name: 'LogManagement(KObusTest)_LogManagement|Show404PagesList' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
