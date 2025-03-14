# Which Management Group is generating the most data points?

```
--- 
 properties: 
   category: 'General Exploration' 
   displayName: 'Which Management Group is generating the most data points?' 
   version: 2 
   query: >
    search * | summarize AggregatedValue = count() by ManagementGroupName
    // Oql: * | Measure count() by ManagementGroupName // Args: {OQ: True; WorkspaceId:
    00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF:
    True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/savedSearches/LogManagement(log-buisecops-cybermxdr-westeu)_G
  eneral|dataPointsPerManagementGroup
 
 name: >
  LogManagement(log-buisecops-cybermxdr-westeu)_General|dataPointsPerManagementGro
  up
 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
