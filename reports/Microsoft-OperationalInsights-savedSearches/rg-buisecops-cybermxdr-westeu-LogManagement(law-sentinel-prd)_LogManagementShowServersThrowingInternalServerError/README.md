# Shows servers that are throwing internal server error

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'Shows servers that are throwing internal server error' 
   version: 2 
   query: >
    search scStatus == 500 | extend Type = $table | where Type == W3CIISLog | summarize
    AggregatedValue = count() by sComputerName
    // Oql: Type=W3CIISLog scStatus=500 | Measure count() by sComputerName // Args:
    {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF:
    True; SortI: True; SortF: True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/law-sentinel
  -prd/savedSearches/LogManagement(law-sentinel-prd)_LogManagement|ShowServersThro
  wingInternalServerError
 
 name: >
  LogManagement(law-sentinel-prd)_LogManagement|ShowServersThrowingInternalServerE
  rror
 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
