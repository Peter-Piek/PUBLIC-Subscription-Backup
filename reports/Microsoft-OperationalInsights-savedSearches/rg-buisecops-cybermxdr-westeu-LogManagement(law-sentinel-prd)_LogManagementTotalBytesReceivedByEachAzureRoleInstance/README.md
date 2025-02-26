# Total Bytes received by each Azure Role Instance

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'Total Bytes received by each Azure Role Instance' 
   version: 2 
   query: >
    search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue
    = sum(csBytes) by RoleInstance
    // Oql: Type=W3CIISLog | Measure Sum(csBytes) by RoleInstance // Args: {OQ: True;
    WorkspaceId: 00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI:
    True; SortF: True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/law-sentinel
  -prd/savedSearches/LogManagement(law-sentinel-prd)_LogManagement|TotalBytesRecei
  vedByEachAzureRoleInstance
 
 name: >
  LogManagement(law-sentinel-prd)_LogManagement|TotalBytesReceivedByEachAzureRoleI
  nstance
 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
