# All Syslogs

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'All Syslogs' 
   version: 2 
   query: >
    Syslog | sort by TimeGenerated desc
    // Oql: Type=Syslog // Args: {OQ: True; WorkspaceId: 00000000-0000-0000-0000-000
    000000000} // Settings: {PTT: True; SortI: True; SortF: True} // Version: 0.1.12
    2
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/law-sentinel
  -prd/savedSearches/LogManagement(law-sentinel-prd)_LogManagement|AllSyslog
 
 name: 'LogManagement(law-sentinel-prd)_LogManagement|AllSyslog' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
