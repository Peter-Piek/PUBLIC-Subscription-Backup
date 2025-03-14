# SymantecVIP

```
--- 
 properties: 
   category: 'Microsoft Sentinel Parser' 
   displayName: 'SymantecVIP' 
   version: 2 
   functionAlias: 'SymantecVIP' 
   query: >
    let forwarder_host_names = dynamic(["datasource"]);
    let datasource = union isfuzzy=true  (datatable(Source: string)[]), (_GetWatchli
    st('ASimSourceType') | where SearchKey == 'SymantecVIP' | project Source);
    Syslog
    | where CollectorHostName in (forwarder_host_names) or Computer in (forwarder_host_names)
    or CollectorHostName in (datasource) or Computer in (datasource)
    | where Facility == "local5"
    | extend parser = extract_all(@'^([A-Z]+)\s\"([0-9\.\-\s\:GMT]+)\"\s(\S+)\s([\w]
    +)\:(\d+)\s(\d+)\s(\d+)\s(\d+)\s\"text\=([\S\s]+)\"\sThread-(\d+)\s(.*)',dynamic
    ([1,2,3,4,5,6,7,8,9,10,11]), SyslogMessage)
    | mv-expand todynamic(parser)
    | extend
    LogLevel = tostring(parser[0]),
    LogTime = todatetime(parser[1]),
    ClientIP = tostring(parser[2]),
    Component = tostring(parser[3]),
    TransactionID = tostring(parser[5]),
    SessionID= tostring(parser[7]),
    ErrorCode = tostring(parser[6]),
    RawMessage = split(tostring(parser[8]),","),
    ThreadID = tostring(parser[9]),
    SourceClassName = tostring(parser[10])
    | extend Message = extract(@"([\w\s\-\_\[\]\\]+)\.",1,tostring(RawMessage[0]))
    | extend User = extract(@"(for\s)?(U|u)ser\s\[(\S+)\]",3,tostring(RawMessage[0])
    )
    | extend Reason = extract(@'reason=(\d+)+\s([\w\s]+)',2,tostring(RawMessage[1]))
    | extend TokenID = extract(@'tokenid=([A-Z0-9]+)',1,tostring(RawMessage[1]))
    | extend AccessResult = extract(@"Access\s(GRANTED|DENIED)",1,tostring(RawMessag
    e[0]))
    | extend AuthResult = extract(@"Authentication\s(\S+)\s",1,tostring(RawMessage[0
    ]))
    | extend StatusMessage = extract(@'StatusMessage:\s(0x0:\s)?([\w\s]+)[&."]',2,to
    string(RawMessage[1]))
    | extend RADIUSAuth = extract(@'Acces-(\S+)\s',1,tostring(RawMessage[0]))
    | extend StatusCode = extract(@'StatusCode\:\s(\d+)',1,tostring(RawMessage[0]))
    | project-away parser

 
   tags: 
    - 
      name: 'description' 
      value: null 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/savedSearches/symantecvip
 
 name: 'symantecvip' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
