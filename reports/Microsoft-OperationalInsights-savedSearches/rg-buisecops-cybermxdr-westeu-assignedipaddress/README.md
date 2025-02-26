# Parser for AssignedIPAddress

```
--- 
 properties: 
   category: 'Microsoft Sentinel Parser' 
   displayName: 'Parser for AssignedIPAddress' 
   version: 2 
   functionAlias: 'AssignedIPAddress' 
   query: >
    let AssignedIPAddresses = (Device:string, Timestamp:datetime = datetime(null))
    {
    let t = coalesce(Timestamp, now());
    let adapters = materialize(
    DeviceNetworkInfo
    | where Timestamp between(max_of(t - 1d, ago(30d)) .. t)
    | where DeviceId == Device or DeviceName == Device
    | top 500 by Timestamp);
    let lastReportId = tolong(toscalar(adapters | summarize arg_max(Timestamp, ReportId)
    | project ReportId));
    adapters | where ReportId == lastReportId
    | project Timestamp, NetworkAdapterType, IpAddresses = todynamic(tostring(IPAddr
    esses)), ConnectedNetworks
    | mv-expand IpAddresses
    | project Timestamp, IPAddress = tostring(IpAddresses.IPAddress), IPType = tostr
    ing(IpAddresses.AddressType), NetworkAdapterType, ConnectedNetworks
    };

 
   tags: 
    - 
      name: 'description' 
      value: null 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/savedSearches/assignedipaddress
 
 name: 'assignedipaddress' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
