# Count of IIS Log Entries by URL requested by client (without query strings)

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'Count of IIS Log Entries by URL requested by client (without query strings)' 
   version: 2 
   query: >
    search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue
    = count() by csUriStem
    // Oql: Type=W3CIISLog | Measure count() by csUriStem // Args: {OQ: True; WorkspaceId:
    00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF:
    True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/law-sentinel
  -prd/savedSearches/LogManagement(law-sentinel-prd)_LogManagement|CountOfIISLogEn
  triesByURLRequestedByClient
 
 name: >
  LogManagement(law-sentinel-prd)_LogManagement|CountOfIISLogEntriesByURLRequested
  ByClient
 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
