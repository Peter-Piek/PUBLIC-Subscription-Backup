# Total Bytes received by each IIS Computer

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'Total Bytes received by each IIS Computer' 
   version: 2 
   query: >
    search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue
    = sum(csBytes) by Computer | limit 500000
    // Oql: Type=W3CIISLog | Measure Sum(csBytes) by Computer | top 500000 // Args:
    {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF:
    True; SortI: True; SortF: True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/law-sentinel
  -prd/savedSearches/LogManagement(law-sentinel-prd)_LogManagement|TotalBytesRecei
  vedByEachIISComputer
 
 name: >
  LogManagement(law-sentinel-prd)_LogManagement|TotalBytesReceivedByEachIISCompute
  r
 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
