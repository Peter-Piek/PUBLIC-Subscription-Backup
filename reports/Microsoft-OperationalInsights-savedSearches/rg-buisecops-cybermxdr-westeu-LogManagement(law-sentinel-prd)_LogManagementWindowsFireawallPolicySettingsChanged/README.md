# Windows Firewall Policy settings have changed

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'Windows Firewall Policy settings have changed' 
   version: 2 
   query: >
    Event | where EventLog == "Microsoft-Windows-Windows Firewall With Advanced
    Security/Firewall" and EventID == 2008 | sort by TimeGenerated desc
    // Oql: Type=Event EventLog="Microsoft-Windows-Windows Firewall With Advanced
    Security/Firewall" EventID=2008 // Args: {OQ: True; WorkspaceId: 00000000-0000-
    0000-0000-000000000000} // Settings: {PTT: True; SortI: True; SortF: True} //
    Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/law-sentinel
  -prd/savedSearches/LogManagement(law-sentinel-prd)_LogManagement|WindowsFireawal
  lPolicySettingsChanged
 
 name: >
  LogManagement(law-sentinel-prd)_LogManagement|WindowsFireawallPolicySettingsChan
  ged
 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
