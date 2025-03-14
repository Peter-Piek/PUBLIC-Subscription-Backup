# All Syslog Records grouped by Facility

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'All Syslog Records grouped by Facility' 
   version: 2 
   query: >
    Syslog | summarize AggregatedValue = count() by Facility
    // Oql: Type=Syslog | Measure count() by Facility // Args: {OQ: True; WorkspaceId:
    00000000-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF:
    True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/Red_Team_RG/p
  roviders/Microsoft.OperationalInsights/workspaces/KObusTest/savedSearches/LogMan
  agement(KObusTest)_LogManagement|AllSyslogByFacility
 
 name: 'LogManagement(KObusTest)_LogManagement|AllSyslogByFacility' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
