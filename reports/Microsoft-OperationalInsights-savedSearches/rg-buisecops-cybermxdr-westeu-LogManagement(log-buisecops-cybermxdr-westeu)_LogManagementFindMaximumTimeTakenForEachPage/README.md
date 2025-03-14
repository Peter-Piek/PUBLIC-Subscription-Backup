# Find the maximum time taken for each page

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'Find the maximum time taken for each page' 
   version: 2 
   query: >
    search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue
    = max(TimeTaken) by csUriStem
    // Oql: Type=W3CIISLog | Measure Max(TimeTaken) by csUriStem // Args: {OQ: True;
    WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI:
    True; SortF: True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/savedSearches/LogManagement(log-buisecops-cybermxdr-westeu)_L
  ogManagement|FindMaximumTimeTakenForEachPage
 
 name: >
  LogManagement(log-buisecops-cybermxdr-westeu)_LogManagement|FindMaximumTimeTaken
  ForEachPage
 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
