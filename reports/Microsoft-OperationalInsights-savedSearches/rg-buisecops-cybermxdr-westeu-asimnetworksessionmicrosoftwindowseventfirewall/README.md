# Network Session ASIM  parser for Microsoft Windows Firewall Events

```
--- 
 properties: 
   category: 'ASIM' 
   displayName: 'Network Session ASIM  parser for Microsoft Windows Firewall Events' 
   version: 2 
   functionAlias: 'ASimNetworkSessionMicrosoftWindowsEventFirewall' 
   functionParameters: 'disabled:bool=False' 
   query: >
    // Data tables for mapping raw values into string
    let LayerCodeTable = datatable (LayerCode:string,LayerName:string)[
    '%%14596', 'IP Packet',
    '%%14597', 'Transport',
    '%%14598', 'Forward',
    '%%14599', 'Stream',
    '%%14600', 'Datagram Data',
    '%%14601', 'ICMP Error',
    '%%14602', 'MAC 802.3',
    '%%14603', 'MAC Native',
    '%%14604', 'vSwitch',
    '%%14608', 'Resource Assignment',
    '%%14609', 'Listen',
    '%%14610', 'Receive/Accept',
    '%%14611', 'Connect',
    '%%14612', 'Flow Established',
    '%%14614', 'Resource Release',
    '%%14615', 'Endpoint Closure',
    '%%14616', 'Connect Redirect',
    '%%14617', 'Bind Redirect',
    '%%14624', 'Stream Packet'];
    let ProtocolTable = datatable (Protocol:int, NetworkProtocol: string)[
    1, 'ICMP',
    3, 'GGP',
    6, 'TCP',
    8, 'EGP',
    12, 'PUP',
    17, 'UDP',
    20, 'HMP',
    27, 'RDP',
    46, 'RSVP',
    47, 'PPTP data over GRE',
    50, 'ESP',
    51, 'AH',
    66, 'RVD',
    88, 'IGMP',
    89, 'OSPF'];
    let Directions = datatable (DirectionCode:string,NetworkDirection:string, isOutB
    ound:bool)[
    '%%14592', 'Inbound', false,
    '%%14593', 'Outbound', true,
    '%%14594', 'Forward',false,
    '%%14595', 'Bidirectional', false,
    '%%14609', 'Listen', false];
    //////////////////////////////////////////////////////
    // this query extract the data from WindowsEvent table
    //////////////////////////////////////////////////////
    let parser = (disabled: bool=false) {
    let WindowsFirewall_WindowsEvent=(){
    WindowsEvent | where not(disabled)
    | project EventID, EventData, Computer, TimeGenerated, _ResourceId,
    _SubscriptionId, Type
    | where EventID between (5150 .. 5159)
    | project-rename DvcHostname = Computer
    | extend
    EventSeverity=tostring(EventData.Severity),
    LayerCode = tostring(EventData.LayerName),
    NetworkRuleNumber = toint(EventData.FilterRTID),
    Protocol = toint(EventData.Protocol),
    DirectionCode = iff(EventID in (5154, 5155, 5158, 5159), "%%14609",tos
    tring(EventData.Direction))
    | lookup Directions on DirectionCode
    | extend  SrcAppName = iff(isOutBound, tostring(EventData.Application), ""
    ),
    DstAppName = iff(not(isOutBound), tostring(EventData.Applicati
    on), ""),
    SrcIpAddr = tostring(EventData.SourceAddress),
    DstIpAddr = tostring(EventData.DestAddress),
    SrcDvcId = iff(isOutBound, tostring(EventData.RemoteMachineID)
    , ""),
    DstDvcId = iff(not(isOutBound), tostring(EventData.RemoteMachi
    neID), ""),
    SrcPortNumber=toint(EventData.SourcePort),
    DstPortNumber=toint(EventData.DestPort),
    SrcProcessId =  iff(isOutBound, tostring(EventData.ProcessId),
    ""),
    DstProcessId =  iff(not(isOutBound), tostring(EventData.Proces
    sId), ""),
    DstUserId = iff(isOutBound, tostring(EventData.RemoteUserID),
    ""),
    SrcUserId = iff(not(isOutBound), tostring(EventData.RemoteUser
    ID), ""),
    DstHostname = iff(isOutBound, "", DvcHostname),
    SrcHostname = iff(isOutBound, DvcHostname, "")
    | project-away EventData
    };
    // Main query -> outputs both schemas as one normalized table
    WindowsFirewall_WindowsEvent
    | extend
    DvcAction = iff(EventID in (5154, 5156, 5158), "Allow", "Deny"),
    DvcOs = 'Windows',
    DstAppType = "Process",
    SrcUserIdType = iff (SrcUserId <> "S-1-0-0", "SID", ""),
    SrcUserId = iff (SrcUserId <> "S-1-0-0", SrcUserId, ""),
    DstUserIdType = iff (DstUserId <> "S-1-0-0", "SID", ""),
    DstUserId = iff (DstUserId <> "S-1-0-0", DstUserId, ""),
    SrcAppType = "Process",
    EventType = "NetworkSession",
    EventSchema = "NetworkSession",
    EventSchemaVersion="0.2.0",
    EventCount=toint(1),
    EventVendor = "Microsoft",
    EventProduct = "Windows Firewall",
    EventResult = iff(EventID in (5154, 5156, 5158), "Success", "Failure
    "),
    EventStartTime = TimeGenerated,
    EventEndTime = TimeGenerated,
    EventSeverity = iff(EventID  in (5154, 5156, 5158), "Informational",
    "Low"),
    EventOriginalType = tostring(EventID),
    DstDvcIdType = iff (DstDvcId != "", "SID", ""),
    SrcDvcIdType = iff (SrcDvcId != "", "SID", "")
    // aliases
    | extend
    Dvc = DvcHostname,
    Hostname = DstHostname,
    IpAddr = SrcIpAddr,
    Src = SrcIpAddr,
    Dst = DstIpAddr,
    Rule = tostring (NetworkRuleNumber)
    | lookup LayerCodeTable on LayerCode
    | lookup ProtocolTable on Protocol
    | project-away LayerCode, DirectionCode, Protocol, isOutBound, LayerName, Ev
    entID,_ResourceId,_SubscriptionId
    };
    parser(disabled=disabled)
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/savedSearches/asimnetworksessionmicrosoftwindowseventfirewall
 
 name: 'asimnetworksessionmicrosoftwindowseventfirewall' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
