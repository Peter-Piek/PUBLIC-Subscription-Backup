# SymantecEndpointProtection

```
--- 
 properties: 
   category: 'Microsoft Sentinel Parser' 
   displayName: 'SymantecEndpointProtection' 
   version: 2 
   functionAlias: 'SymantecEndpointProtection' 
   query: >
    let datasource = union isfuzzy=true  (datatable(Source: string)[]), (_GetWatchli
    st('ASimSourceType') | where SearchKey == 'SymantecEndpointProtection' | project
    Source);
    let forwarder_host_names = dynamic(["server1", "server2"]);  // server1 and server2
    are examples, replace this list with your SEP device names
    Syslog
    | where CollectorHostName in (forwarder_host_names) or Computer in (forwarder_host_names)
    or CollectorHostName in (datasource) or Computer in (datasource) or ProcessName
    =~ "SymantecServer"
    | extend ServerName = extract(@"^([\w\-\_]+)?(,|\Site:)",1,SyslogMessage)
    // Administrative Log Header
    | extend AdministrativeLogsParser = iif(SyslogMessage has ("Admin:"), extract_al
    l(@"Site:\s([^,]+)\,Server\sName\:\s([^,]+)\,Domain\sName\:\s([^,]+)?\,Admin\:\s
    ([^,]+)?\,Event\sDescription\:\s([^#]+)?(#|$)",dynamic([1,2,3,4,5,6,7]),
    SyslogMessage)[0], dynamic(""))
    | extend LogType = iif(isnotempty(AdministrativeLogsParser),"Administrative Logs",
    "")
    // Agent System Log Header
    | extend AgentSystemLogsParser = iif(SyslogMessage has ("Category:"),extract_all
    (@'^([^,]+)\,Category:\s([\d]+)\,([^,]+)\,\"?Event\sDescription:\s([^,]+\"?)(\,E
    vent time:\s([^,]+)\,Group Name:\s([^,]+)$?)?',dynamic([1,2,3,4,6,7]), SyslogMessage)[0],
    dynamic(""))
    | extend LogType = iif(isempty(LogType) and isnotempty(AgentSystemLogsParser),"A
    gent System Logs",LogType)
    // Agent Activity Log Header
    | extend AgentActivityLogsParser = iif(SyslogMessage has_all ("Site:","Server
    Name:", ",Domain Name:"),extract_all(@"Site:\s([^,]+)\,Server\sName\:\s([^,]+)\
    ,Domain\sName\:\s([^,]+)?\,([^,]+)?\,([^,]+)?\,([^,]+)?\,([^,]+)?",dynamic([1,2,
    3,4,5,6,7]), SyslogMessage)[0], dynamic(""))
    | extend LogType = iif(isempty(LogType) and isnotempty(AgentActivityLogsParser),
    "Agent Activity Logs", LogType)
    // Agent Behavior Log Header
    | extend AgentBehaviorLogsParser = iif(SyslogMessage has ("Begin:"), extract_all
    (@"^([^,]+)?\,([^,]+)?\,([^,]+)?\,([^,]+)?\,([^,]+)?\,Begin:\s([^,]+)?\,End Time
    :\s([^,]+)?\,Rule:\s([^,]+)?\,(\d+)?\,([^,]+)?\,([\S\s]+)",dynamic([1,2,3,4,5,6,
    7,8,9,10,11]),SyslogMessage)[0], dynamic(""))
    | extend AgentBehaviorLogsSubstring = tostring(AgentBehaviorLogsParser[10])
    | extend AgentBehaviorLogsParser2 = iif(SyslogMessage has_all ("User Name:","Domain
    Name:", "Action Type:"),extract_all(@"([^,]+)?\,([^,]+)?\,User Name:\s([^,]+)?\,Domain
    Name:\s([^,]+)?\,Action Type:\s([^,]+)?\,File size \(bytes\):\s(\d+)?\,Device I
    D:\s([^,]+)?",dynamic([1,2,3,4,5,6,7,8]),AgentBehaviorLogsSubstring)[0], dynamic
    (""))
    | extend LogType = iif(isempty(LogType) and isnotempty(AgentBehaviorLogsParser)
    and isnotempty(AgentBehaviorLogsParser2),"Agent Behavior Logs",LogType)
    // Agent Traffic Log Header
    | extend AgentTrafficLogsParser = iif(SyslogMessage has ("Local Host IP:"),extra
    ct_all(@"^([^,]+)\,Local Host IP:\s([^,]+)?\,Local Port:\s([^,]+)?\,Local Host
    MAC:\s([^,]+)?\,Remote Host IP:\s([^,]+)?\,Remote Host Name:\s([^,]+)?\,Remote
    Port:\s([^,]+)?\,Remote Host MAC:\s([^,]+)?\,([^,]+)?\,([^,]+)?\,Begin:\s([^,]+
    )?\,End Time:\s([^,]+)?\,([\s\S]+)",dynamic([1,2,3,4,5,6,7,8,9,10,11,12,13]),Sys
    logMessage)[0], dynamic(""))
    | extend AgentTrafficLogsSubstring  = tostring(AgentTrafficLogsParser[12])
    | extend AgentTrafficLogsParser2 = iif(SyslogMessage has("Occurrences:"),extract
    _all(@"Occurrences:\s([^,]+)?\,Application:\s([^,]+)?\,Rule:\s([^,]+)?\,Location
    :\s([^,]+)?\,User Name:\s([^,]+)?\,Domain Name:\s([^,]+)?\,Action:\s([^,]+)?\,SH
    A-256:\s([^,]+)?\,MD-5:\s([^,]+)?",dynamic([1,2,3,4,5,6,7,8,9,10,11,12]),AgentTr
    afficLogsSubstring)[0], dynamic(""))
    | extend LogType = iif(isempty(LogType) and isnotempty(AgentTrafficLogsParser) and
    isnotempty(AgentTrafficLogsParser2),"Agent Traffic Logs",LogType)
    // Agent Security Log Header
    | extend AgentSecurityLogsParser = iif(SyslogMessage has ("Local Host IP:"),extr
    act_all(@'^([^,]+)\,(Event Description:\s([^,]+)?|\"Event Description:\s([^"]+)?
    \")\,Local Host IP:\s([^,]+)?\,Local Host MAC:\s([^,]+)?\,Remote Host
    Name:\s([^,]+)?\,Remote Host IP:\s([^,]+)?\,Remote Host MAC:\s([^,]+)?\,([^,]+)
    ?\,([^,]+)?\,(Intrusion ID:\s)?([^,]+)?\,Begin:\s([^,]+)?\,End Time:\s([^,]+)?\,
    ([\s\S]+)',dynamic([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]),SyslogMessage)[0],
    dynamic(""))
    | extend  AgentSecurityLogsSubstring = tostring(AgentSecurityLogsParser[15])
    | extend AgentSecurityLogsParser2 = iif(SyslogMessage has ("CIDS Signature SubID"),
    extract_all(@'Occurrences:\s([^,]+)?\,Application:\s([^,]+)?\,Location:\s([^,]+
    )?\,User Name:\s([^,]+)?\,Domain Name:\s([^,]+)?\,Local Port:\s([^,]+)?\,Remote
    Port:\s([^,]+)?\,CIDS Signature ID:\s([^,]+)?\,CIDS Signature string:\s([^,]+)?\,CIDS
    Signature SubID:\s([^,]+)?\,\"?Intrusion URL:\s([^\,]+|[^\"]+)?\"?\,Intrusion
    Payload URL:\s([^,]+)?\,SHA-256:\s([^,]+)?\,MD-5:\s([^,]+)?',dynamic([1,2,3,4,5
    ,6,7,8,9,10,11,12,13]),AgentSecurityLogsSubstring)[0],dynamic(""))
    | extend LogType = iif(isempty(LogType) and isnotempty(AgentSecurityLogsParser)
    and isnotempty(AgentSecurityLogsParser2),"Agent Security Logs",LogType)
    // Agent Packet Log Header
    | extend AgentPacketLogsParser = iif(SyslogMessage has ("Local Host IP:"),
    extract_all(@"Local Host IP:\s([^,]+)?\,Local Port:\s([^,]+)?\,Remote Host
    IP:\s([^,]+)?\,Remote Host Name:\s([^,]+)?\,Remote Port:\s([^,]+)?\,([^,]+)?\,A
    pplication:\s([^,]+)?\,Action:\s([^,]+)?\,",dynamic([1,2,3,4,5,6,7]), SyslogMessage)[0],
    dynamic(""))
    | extend LogType = iif(isempty(LogType) and isnotempty(AgentPacketLogsParser),"A
    gent Packet Logs",LogType)
    // Agent Risk Log Header
    | extend AgentRiskLogsParser = iif(SyslogMessage has "Risk name:", extract_all(@'^([^,]+)\,IP
    Address:\s([^,]+)?\,Computer name:\s([^,]+)?\,Source:\s([^,]+)?\,Risk name:\s([
    ^,]+)?\,Occurrences:\s([^,]+)?\,(File path:\s([^,]+)?|File path:\s\"([^"]+)\"?\"
    )\,Description:\s([^,]+)?\,Actual action:\s([^,]+)?\,Requested action:\s([^,]+)?\,Secondary
    action:\s([^,]+)?\,Event time:\s([^,]+)?\,Event Insert Time:\s([^,]+)?\,([\s\S]
    +)',dynamic([1,2,3,4,5,6,8,9,10,11,12,13,14,15,16]), SyslogMessage)[0], dynamic
    (""))
    | extend AgentRiskLogsSubstring  = tostring(AgentRiskLogsParser[14])
    | extend AgentRiskLogsParser2 = iif(SyslogMessage has ("URL Tracking Status:"),
    extract_all(@"^End Time:\s([^,]+)?\,Last update time:\s([^,]+)?\,Domain
    Name:\s([^,]+)?\,Group Name:\s([^,]+)?\,Server Name:\s([^,]+)?\,User
    Name:\s([^,]+)?\,Source Computer Name:\s([^,]+)?\,Source Computer IP:\s([^,]+)?
    \,Disposition:\s([^,]+)?\,Download site:\s([^,]+)?\,Web domain:\s([^,]+)?\,Downloaded
    by:\s([^,]+)?\,Prevalence:\s([^,]+)?\,Confidence:\s([^,]+)?\,URL Tracking Statu
    s:\s([^,]+)?\,([\s\S]+)",dynamic([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16]),Agent
    RiskLogsSubstring)[0], dynamic(""))
    | extend AgentRiskLogsSubstring2  = tostring(AgentRiskLogsParser2[15])
    | extend AgentRiskLogsParser3 = iif(SyslogMessage has ("Sensitivity:"),
    extract_all(@"^First Seen:\s([^,]+)?\,Sensitivity:\s([^,]+)?\,Permitted application
    reason:\s([^,]+)?\,Application hash:\s([^,]+)?\,Hash type:\s([^,]+)?\,Company
    name:\s([^,]+)?\,Application name:\s([^,]+)?\,Application version:\s([^,]+)?\,A
    pplication type:\s([^,]+)?\,File size \(bytes\):\s([^,]+)?\,Category
    set:\s([^,]+)?\,Category type:\s([^,]+)?\,Location:\s([^,]+)?\,Intensive Protection
    Level:\s([^,]+)?\,Certificate issuer:\s([^,]+)?\,([\s\S]+)",dynamic([1,2,3,4,5,
    6,7,8,9,10,11,12,13,14,15,16]),AgentRiskLogsSubstring2)[0], dynamic(""))
    | extend AgentRiskLogsSubstring3  = tostring(AgentRiskLogsParser3[15])
    | extend AgentRiskLogsParser4 = iif(SyslogMessage has ("Certificate signer:"),
    extract_all(@"^Certificate signer:\s([^,]+)?\,Certificate thumbprint:\s([^,]+)?
    \,Signing timestamp:\s([^,]+)?\,Certificate serial number:\s([^,]+)?(\,|$)",dyna
    mic([1,2,3,4]),AgentRiskLogsSubstring3)[0], dynamic(""))
    | extend SiteName = case(LogType has "Administrative Logs", tostring(Administrat
    iveLogsParser[0]),
    LogType has "Agent Activity Logs", tostring(AgentActivityLogsParser[
    0]), ""),
    ServerName = case(LogType has "Administrative Logs", tostring(Administr
    ativeLogsParser[1]),
    LogType has "Agent Risk Logs", tostring(AgentRiskLogsParser2[4]), ""
    ),
    DomainName = case(LogType has "Administrative Logs", tostring(Administr
    ativeLogsParser[2]),
    LogType has "Agent Activity Logs", tostring(AgentActivityLogsParser[
    6]),
    LogType has "Agent Behavior Logs", tostring(AgentBehaviorLogsParser2
    [4]),
    LogType has "Agent Traffic Logs", tostring(AgentTrafficLogsParser2[5
    ]),
    LogType has "Agent Security Logs", tostring(AgentSecurityLogsParser2
    [4]),
    LogType has "Agent Risk Logs", tostring(AgentRiskLogsParser2[2]), ""
    ),
    AdminName = tostring(AdministrativeLogsParser[3]),
    EventDescription = case(LogType has "Administrative Logs", tostring(Adm
    inistrativeLogsParser[4]),
    LogType has "Agent System Logs", tostring(AgentSystemLogsParser[3]),
    
    LogType has "Agent Activity Logs", tostring(AgentActivityLogsParser[
    3]),
    LogType has "Agent Behavior Logs", extract(@"([\S\s]+)\-\sCaller\sMD
    5",1,tostring(AgentBehaviorLogsParser[3])),
    LogType has "Agent Security Logs", iif(isempty(tostring(AgentSecurit
    yLogsParser[2])),tostring(AgentSecurityLogsParser[3]),tostring(AgentSecurityLogs
    Parser[2])), LogType has "Agent System Logs", tostring(AgentSystemLogsParser[3])
    ,
    LogType has "Agent Risk Logs", tostring(AgentRiskLogsParser[8]), "")
    ,
    Category = toint(AgentSystemLogsParser[1]),
    EventSource = tostring(AgentSystemLogsParser[2]),
    EventTimestamp = tostring(AgentSystemLogsParser[4]),
    GroupName = case(LogType has "Agent System Logs", tostring(AgentSystemL
    ogsParser[5]),
    LogType has "Agent Risk Logs", tostring(AgentRiskLogsParser2[3]), ""
    ),
    SEPMDomainName = tostring(AgentActivityLogsParser[2]),
    HostName = tostring(AgentActivityLogsParser[4]),
    UserName = case(LogType has "Agent Activity Logs", tostring(AgentActivi
    tyLogsParser[5]),
    LogType has "Agent Behavior Logs", tostring(AgentBehaviorLogsParser2
    [3]),
    LogType has "Agent Traffic Logs", tostring(AgentTrafficLogsParser2[4
    ]),
    LogType has "Agent Security Logs", tostring(AgentSecurityLogsParser2
    [3]),
    LogType has "Agent Risk Logs", tostring(AgentRiskLogsParser2[5]),"")
    ,
    IpAddr = tostring(AgentBehaviorLogsParser[1]),
    Action = case(LogType has "Agent Behavior Logs", tostring(AgentBehavior
    LogsParser[2]),
    LogType has "Agent Traffic Logs", tostring(AgentTrafficLogsParser2[6
    ]),
    LogType has "Agent Packet Logs", tostring(AgentPacketLogsParser[6]),
    
    LogType has "Agent Risk Logs", tostring(AgentRiskLogsParser[0]), "")
    ,
    CallerMD5Hash = extract(@"Caller\sMD5\=(\S+)",1,tostring(AgentBehaviorL
    ogsParser[3])),
    ApiName = tostring(AgentBehaviorLogsParser[4]),
    EventStartTime = case(LogType has "Agent Behavior Logs", todatetime(Age
    ntBehaviorLogsParser[5]),
    LogType has "Agent Traffic Logs", todatetime(AgentTrafficLogsParser[
    10]),
    LogType has "Agent Security Logs", todatetime(AgentSecurityLogsParse
    r[13]),
    LogType has "Agent Risk Logs", todatetime(AgentRiskLogsParser[12]),
    datetime(null)),
    EventEndTime = case(LogType has "Agent Behavior Logs", todatetime(Agent
    BehaviorLogsParser[6]),
    LogType has "Agent Traffic Logs", todatetime(AgentTrafficLogsParser[
    11]),
    LogType has "Agent Security Logs", todatetime(AgentSecurityLogsParse
    r[14]),
    LogType has "Agent Risk Logs", todatetime(AgentRiskLogsParser[14]),
    LogType has "Agent Risk Logs", todatetime(AgentRiskLogsParser2[0]),
    datetime(null)),
    SecurityRuleName = tostring(AgentBehaviorLogsParser[7]),
    CallerProcessId = toint(AgentBehaviorLogsParser[8]),
    CallerProcessName = tostring(AgentBehaviorLogsParser[9]),
    AgentBehaviorLogsSubstring = tostring(AgentBehaviorLogsParser[10]),
    CallerReturnAddr = tostring(AgentBehaviorLogsParser2[0]),
    CallerReturnModuleName = tostring(AgentBehaviorLogsParser2[1]),
    Parameters = tostring(AgentBehaviorLogsParser2[2]),
    ActionType = tostring(AgentBehaviorLogsParser2[5]),
    FileSize = case(LogType has "Agent Behavior Logs", toint(AgentBehaviorL
    ogsParser2[6]),
    LogType has "Agent Risk Logs", toint(AgentRiskLogsParser3[9]), int(n
    ull)),
    DeviceId = tostring(AgentBehaviorLogsParser2[7]),
    LocalHostIpAddr = case(LogType has "Agent Traffic Logs", tostring(Agent
    TrafficLogsParser[1]),
    LogType has "Agent Security Logs", tostring(AgentSecurityLogsParser[
    4]),
    LogType has "Agent Packet Logs", tostring(AgentPacketLogsParser[0]),
    ""),
    LocalPortNumber = case(LogType has "Agent Traffic Logs", toint(AgentTra
    fficLogsParser[2]),
    LogType has "Agent Security Logs", toint(AgentSecurityLogsParser2[5]
    ),
    LogType has "Agent Packet Logs", toint(AgentPacketLogsParser[1]), in
    t(null)),
    LocalHostMacAddr = case(LogType has "Agent Traffic Logs", tostring(Agen
    tTrafficLogsParser[3]),
    LogType has "Agent Security Logs", tostring(AgentSecurityLogsParser[
    5]), ""),
    RemoteHostIpAddr = case(LogType has "Agent Traffic Logs", tostring(Agen
    tTrafficLogsParser[4]),
    LogType has "Agent Security Logs", tostring(AgentSecurityLogsParser[
    7]),
    LogType has "Agent Packet Logs", tostring(AgentPacketLogsParser[2]),
    ""),
    RemoteHostName = case(LogType has "Agent Traffic Logs", tostring(AgentT
    rafficLogsParser[5]),
    LogType has "Agent Security Logs", tostring(AgentSecurityLogsParser[
    6]),
    LogType has "Agent Packet Logs", tostring(AgentPacketLogsParser[3]),
    ""),
    RemotePortNumber = case(LogType has "Agent Traffic Logs", toint(AgentTr
    afficLogsParser[6]),
    LogType has "Agent Security Logs", toint(AgentSecurityLogsParser2[6]
    ),
    LogType has "Agent Packet Logs", toint(AgentPacketLogsParser[4]), in
    t(null)),
    RemoteHostMacAddr = case(LogType has "Agent Traffic Logs", tostring(Age
    ntTrafficLogsParser[7]),
    LogType has "Agent Security Logs", tostring(AgentSecurityLogsParser[
    8]), ""),
    NetworkProtocol = case(LogType has "Agent Traffic Logs", tostring(Agent
    TrafficLogsParser[8]),
    LogType has "Agent Security Logs", tostring(AgentSecurityLogsParser[
    10]), ""),
    TrafficDirection = case(LogType has "Agent Traffic Logs", tostring(Agen
    tTrafficLogsParser[9]),
    LogType has "Agent Security Logs", tostring(AgentSecurityLogsParser[
    9]), ""),
    AgentTrafficLogsSubstring  = tostring(AgentTrafficLogsParser[12]),
    Occurrences = case(LogType has "Agent Traffic Logs", toint(AgentTraffic
    LogsParser2[0]),
    LogType has "Agent Security Logs", toint(AgentSecurityLogsParser2[0]
    ),
    LogType has "Agent Risk Logs", toint(AgentRiskLogsParser[5]), int(nu
    ll)),
    ApplicationName = case(LogType has "Agent Traffic Logs", tostring(Agent
    TrafficLogsParser2[1]),
    LogType has "Agent Security Logs", tostring(AgentSecurityLogsParser2
    [0]),
    LogType has "Agent Risk Logs", AgentRiskLogsParser3[6], ""),
    RuleName = tostring(AgentTrafficLogsParser2[2]),
    Location = case(LogType has "Agent Traffic Logs", tostring(AgentTraffic
    LogsParser2[3]),
    LogType has "Agent Security Logs", tostring(AgentSecurityLogsParser2
    [2]),
    LogType has "Agent Risk Logs", tostring(AgentRiskLogsParser3[12]), "
    "),
    Sha256 = case(LogType has "Agent Traffic Logs", tostring(AgentTrafficLo
    gsParser2[8]),
    LogType has "Agent Security Logs", tostring(AgentSecurityLogsParser2
    [11]), ""),
    Md5 = case(LogType has "Agent Traffic Logs", tostring(AgentTrafficLogsP
    arser2[10]),
    LogType has "Agent Security Logs", tostring(AgentSecurityLogsParser2
    [12]), ""),
    IntrusionId = tostring(AgentSecurityLogsParser[11]),
    CidsSignatureId = tostring(AgentSecurityLogsParser2[7]),
    CidsSignatureString = tostring(AgentSecurityLogsParser2[8]),
    CidsSignatureSubId = toint(AgentSecurityLogsParser2[9]),
    IntrusionUrl = tostring(AgentSecurityLogsParser2[10]),
    Application = tostring(AgentPacketLogsParser[5]),
    SrcIpAddr = tostring(AgentRiskLogsParser[1]),
    SrcHostName = tostring(AgentRiskLogsParser[2]),
    Source = tostring(AgentRiskLogsParser[3]),
    RiskName = tostring(AgentRiskLogsParser[4]),
    FilePath = iif(isempty(tostring(AgentRiskLogsParser[6])),tostring(Agent
    RiskLogsParser[7]),tostring(AgentRiskLogsParser[6])),
    ActualAction = tostring(AgentRiskLogsParser[9]),
    RequestedAction = tostring(AgentRiskLogsParser[10]),
    SecondaryAction = tostring(AgentRiskLogsParser[11]),
    EventInsertTime = todatetime(AgentRiskLogsParser[13]),
    LastUpdateTime = todatetime(AgentRiskLogsParser2[1]),
    SrcComputerName = tostring(AgentRiskLogsParser2[6]),
    SrcComputerIpAddr = tostring(AgentRiskLogsParser2[7]),
    Disposition = tostring(AgentRiskLogsParser2[8]),
    DownloadSite = tostring(AgentRiskLogsParser2[9]),
    WebDomain = tostring(AgentRiskLogsParser2[10]),
    DownloadedBy = tostring(AgentRiskLogsParser2[11]),
    Prevalence = tostring(AgentRiskLogsParser2[12]),
    Confidence = tostring(AgentRiskLogsParser2[13]),
    UrlTrackingStatus = tostring(AgentRiskLogsParser2[14]),
    FirstSeen = tostring(AgentRiskLogsParser3[0]),
    Sensitivity = tostring(AgentRiskLogsParser3[1]),
    PermittedApplicationReason = tostring(AgentRiskLogsParser3[2]),
    ApplicationHash = tostring(AgentRiskLogsParser3[3]),
    HashType = tostring(AgentRiskLogsParser3[4]),
    CompanyName = tostring(AgentRiskLogsParser3[5]),
    ApplicationVersion = tostring(AgentRiskLogsParser3[7]),
    ApplicationType = tostring(AgentRiskLogsParser3[8]),
    CategorySet = tostring(AgentRiskLogsParser3[10]),
    CategoryType = tostring(AgentRiskLogsParser3[11]),
    IntensiveProtectionLevel = tostring(AgentRiskLogsParser3[13]),
    CertificateIssuer = tostring(AgentRiskLogsParser3[14]),
    CertificateSigner = tostring(AgentRiskLogsParser4[0]),
    CertificateThumbprint = tostring(AgentRiskLogsParser4[1]),
    SigningTimestamp = tostring(AgentRiskLogsParser4[2]),
    CertificateSerialNumber = tostring(AgentRiskLogsParser4[3])
    | extend LogType = case(LogType !in ("Agent System Logs","Agent Activity Logs","Agent
    Behavior Logs", "Agent Traffic Logs","Agent Security Logs", "Agent Packet Logs",
    "Agent Risk Logs", "Administrative Logs"), iif(isempty(LogType),"Other", LogType),
    LogType)
    | project-away *Parser*, *Substring*

 
   tags: 
    - 
      name: 'description' 
      value: null 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/savedSearches/symantecendpointprotection
 
 name: 'symantecendpointprotection' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
