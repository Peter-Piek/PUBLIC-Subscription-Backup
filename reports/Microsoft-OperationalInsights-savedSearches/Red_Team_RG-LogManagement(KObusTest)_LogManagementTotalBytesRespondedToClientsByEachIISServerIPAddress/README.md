# Total Bytes responded back to clients by each IIS ServerIP Address

```
--- 
 properties: 
   category: 'Log Management' 
   displayName: 'Total Bytes responded back to clients by each IIS ServerIP Address' 
   version: 2 
   query: >
    search * | extend Type = $table | where Type == W3CIISLog | summarize AggregatedValue
    = sum(scBytes) by sIP
    // Oql: Type=W3CIISLog | Measure Sum(scBytes) by sIP // Args: {OQ: True; WorkspaceId:
    00000000-0000-0000-0000-000000000000} // Settings: {PEF: True; SortI: True; SortF:
    True} // Version: 0.1.122
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/Red_Team_RG/p
  roviders/Microsoft.OperationalInsights/workspaces/KObusTest/savedSearches/LogMan
  agement(KObusTest)_LogManagement|TotalBytesRespondedToClientsByEachIISServerIPAd
  dress
 
 name: >
  LogManagement(KObusTest)_LogManagement|TotalBytesRespondedToClientsByEachIISServ
  erIPAddress
 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
