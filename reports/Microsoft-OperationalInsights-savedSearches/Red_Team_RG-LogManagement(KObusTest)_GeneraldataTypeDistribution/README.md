# Distribution of data Types

```
--- 
 properties: 
   category: 'General Exploration' 
   displayName: 'Distribution of data Types' 
   version: 2 
   query: >
    search * | extend Type = $table | summarize AggregatedValue = count() by Type
    // Oql: * | Measure count() by Type // Args: {OQ: True; WorkspaceId: 00000000-00
    00-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} //
    Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/Red_Team_RG/p
  roviders/Microsoft.OperationalInsights/workspaces/KObusTest/savedSearches/LogMan
  agement(KObusTest)_General|dataTypeDistribution
 
 name: 'LogManagement(KObusTest)_General|dataTypeDistribution' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
