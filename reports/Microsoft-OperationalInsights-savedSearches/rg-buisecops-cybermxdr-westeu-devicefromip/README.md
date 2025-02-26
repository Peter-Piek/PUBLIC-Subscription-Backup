# Parser for Devicefromip

```
--- 
 properties: 
   category: 'Microsoft Sentinel Parser' 
   displayName: 'Parser for Devicefromip' 
   version: 2 
   functionAlias: 'Devicefromip' 
   query: >
    let DeviceFromIP2 = (T:(IP:string), Timestamp:datetime = datetime(null))
    {
    let t = coalesce(Timestamp, now());
    let lastReportIds = DeviceNetworkInfo
    | where Timestamp between(max_of(t - 1d, ago(30d)) .. t)
    | summarize arg_max(Timestamp, ReportId) by DeviceId;
    let adapters = DeviceNetworkInfo
    | where Timestamp between(max_of(t - 1d, ago(30d)) .. t)
    | lookup kind = inner lastReportIds on ReportId, DeviceId
    | mv-expand todynamic(IPAddresses)
    | project DeviceId, IP = tostring(IPAddresses.IPAddress);
    T | join adapters on IP | project-away IP1
    };

 
   tags: 
    - 
      name: 'description' 
      value: null 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/savedSearches/devicefromip
 
 name: 'devicefromip' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
