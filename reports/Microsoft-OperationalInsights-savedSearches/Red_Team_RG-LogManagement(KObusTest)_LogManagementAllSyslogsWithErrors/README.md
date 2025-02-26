# All Syslog Records with Errors

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'All Syslog Records with Errors' 
   version: 2 
   query: >
    Syslog | where SeverityLevel == "error" | sort by TimeGenerated desc
    // Oql: Type=Syslog SeverityLevel=error // Args: {OQ: True; WorkspaceId: 0000000
    0-0000-0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True}
    // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/Red_Team_RG/p
  roviders/Microsoft.OperationalInsights/workspaces/KObusTest/savedSearches/LogMan
  agement(KObusTest)_LogManagement|AllSyslogsWithErrors
 
 name: 'LogManagement(KObusTest)_LogManagement|AllSyslogsWithErrors' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
