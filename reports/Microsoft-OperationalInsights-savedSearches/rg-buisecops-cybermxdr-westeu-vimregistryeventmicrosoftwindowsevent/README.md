# Registry Event ASIM filtering parser for Microsoft Windows Events and Security Events (registry creation event)

```
--- 
 properties: 
   category: 'ASIM' 
   displayName: >
    Registry Event ASIM filtering parser for Microsoft Windows Events and Security
    Events (registry creation event)
 
   version: 2 
   functionAlias: 'vimRegistryEventMicrosoftWindowsEvent' 
   functionParameters: >
    starttime:datetime=datetime(null),endtime:datetime=datetime(null),eventtype_in:d
    ynamic=dynamic([]),actorusername_has_any:dynamic=dynamic([]),registrykey_has_any
    :dynamic=dynamic([]),registryvalue_has_any:dynamic=dynamic([]),registrydata_has_
    any:dynamic=dynamic([]),dvchostname_has_any:dynamic=dynamic([]),disabled:bool=Fa
    lse
 
   query: >
    let parser = (
    starttime: datetime=datetime(null),
    endtime: datetime=datetime(null),
    eventtype_in: dynamic=dynamic([]),
    actorusername_has_any: dynamic=dynamic([]),
    registrykey_has_any: dynamic =dynamic([]),
    registryvalue_has_any: dynamic =dynamic([]),
    registrydata_has_any: dynamic =dynamic([]),
    dvchostname_has_any: dynamic=dynamic([]),
    disabled: bool=false
    ) {
    let ASIM_GetAccountType = (sid: string) {
    iif (
    sid in ("S-1-0-0", "S-1-5-18", "S-1-5-19", "S-1-5-20"),
    "Simple"
    ,
    "Windows"
    )
    };
    let ASIM_ParseWindowsEvents = (WindowsEvent: (EventData: dynamic)) {
    WindowsEvent
    | extend
    ActorUsername = iif(isnotempty(EventData.SubjectDomainName), strcat(
    EventData.SubjectDomainName, @'\', EventData.SubjectUserName), EventData.Subject
    UserName)
    ,
    ActorDomainName = tostring(EventData.SubjectDomainName)
    ,
    ActorUserId = tostring(EventData.SubjectUserSid)
    ,
    ActorSessionId = tostring(EventData.SubjectLogonId)
    ,
    ActingProcessName = tostring(EventData.ProcessName)
    ,
    ActingProcessId = tostring(toint(tolong(EventData.ProcessId)))
    ,
    RegistryKey = iif(
    EventData.ObjectName startswith @"\REGISTRY\MACHINE",
    replace_string(tostring(EventData.ObjectName), @"\REGISTRY\MACHINE",
    "HKEY_LOCAL_MACHINE")
    ,
    replace_string(tostring(EventData.ObjectName), @"\REGISTRY\USER",
    "HKEY_USERS")
    )
    };
    let Event4663TypeLookup = datatable (AccessMask: string, EventType: string)
    [
    "0x1", "RegistryValueRead"
    ,
    "0x10", "RegistryKeyNotify"
    ,
    "0x10000", "RegistryKeyDeleted"
    ,
    "0x2", "RegistryValueSet"
    ,
    "0x20000", "MetadataAccessed"
    ,
    "0x20006", "RegistryValueSet"
    ,
    "0x40000", "MetadataModified"
    ,
    "0x8", "RegistrySubkeyEnumerated"
    ];
    let Event4567TypeLookup = datatable (EventOriginalSubType: string, EventType:
    string)
    [
    "%%1904", "RegistryValueSet"
    ,
    "%%1905", "RegistryValueSet"
    ,
    "%%1906", "RegistryValueDeleted"
    ];
    let RegistryType = datatable (TypeCode: string, TypeName: string)
    [
    "%%1872", "REG_NONE"
    ,
    "%%1873", "REG_SZ"
    ,
    "%%1874", "REG_EXPAND_SZ"
    ,
    "%%1875", "REG_BINARY"
    ,
    "%%1876", "REG_DWORD"
    ,
    "%%1879", "REG_MULTI_SZ"
    ,
    "%%1883", "REG_QWORD"
    ];
    union isfuzzy=false
    (
    WindowsEvent
    | where not(disabled)
    | where (isnull(starttime) or TimeGenerated >= starttime)
    and (isnull(endtime) or TimeGenerated <= endtime)
    | where EventID == 4663 and EventData.ObjectType == "Key"
    | where (array_length(actorusername_has_any) == 0 or (EventData.SubjectDomainName
    has_any (actorusername_has_any)) or (EventData.SubjectUserName has_any
    (actorusername_has_any)) or (strcat(EventData.SubjectDomainName, '\\',
    EventData.SubjectUserName) has_any (actorusername_has_any))) and
    (array_length(registryvalue_has_any) == 0) and
    (array_length(registrydata_has_any) == 0) and
    (array_length(dvchostname_has_any) == 0 or Computer has_any (dvchost
    name_has_any))
    | extend
    AccessMask = tostring(EventData.AccessMask)
    ,
    Type = "WindowsEvent"
    | lookup Event4663TypeLookup on AccessMask
    | extend EventType = iif(isempty(EventType), "Other", EventType)
    | where (array_length(eventtype_in) == 0 or EventType in~ (eventtype_in)
    )
    | invoke ASIM_ParseWindowsEvents()
    | where (array_length(registrykey_has_any) == 0 or RegistryKey has_any (
    registrykey_has_any))
    | project
    TimeGenerated,
    Computer,
    EventID,
    EventType,
    ActorUsername,
    ActorDomainName,
    ActorUserId,
    ActorSessionId,
    ActingProcessName,
    ActingProcessId,
    RegistryKey,
    _ResourceId,
    Type
    ),
    (
    union isfuzzy=false
    (
    WindowsEvent
    | where not(disabled)
    | where (isnull(starttime) or TimeGenerated >= starttime)
    and (isnull(endtime) or TimeGenerated <= endtime)
    | where EventID == 4657
    | where (array_length(actorusername_has_any) == 0 or (EventData.SubjectDomainName
    has_any (actorusername_has_any)) or (EventData.SubjectUserName has_any
    (actorusername_has_any)) or (strcat(EventData.SubjectDomainName, '\\',
    EventData.SubjectUserName) has_any (actorusername_has_any))) and
    (array_length(registryvalue_has_any) == 0 or (EventData.ObjectValueName)
    has_any (registryvalue_has_any)) and
    (array_length(registrydata_has_any) == 0 or (EventData.NewValue)
    has_any (registrydata_has_any)) and
    (array_length(dvchostname_has_any) == 0 or Computer has_any (dvc
    hostname_has_any))
    | invoke ASIM_ParseWindowsEvents()
    | where (array_length(registrykey_has_any) == 0 or RegistryKey has_any
    (registrykey_has_any))
    | extend
    EventOriginalSubType = tostring(EventData.OperationType)
    ,
    OldValue = tostring(EventData.OldValue)
    ,
    NewValue = tostring(EventData.NewValue)
    ,
    RegistryValue = tostring(EventData.ObjectValueName)
    ,
    NewValueType = tostring(EventData.NewValueType)
    ,
    OldValueType = tostring(EventData.OldValueType)
    | lookup Event4567TypeLookup on EventOriginalSubType
    | extend EventType = iif(isempty(EventType), "Other", EventType)
    | where (array_length(eventtype_in) == 0 or EventType in~ (eventtype
    _in))
    | project
    TimeGenerated,
    Computer,
    EventID,
    EventType,
    ActorUsername,
    ActorDomainName,
    ActorUserId,
    ActorSessionId,
    ActingProcessName,
    ActingProcessId,
    RegistryKey,
    _ResourceId,
    RegistryValue,
    Type,
    NewValueType,
    OldValueType,
    EventOriginalSubType,
    OldValue,
    NewValue
    )
    | lookup RegistryType on $left.NewValueType == $right.TypeCode
    | project-rename RegistryValueType = TypeName
    | lookup RegistryType on $left.OldValueType == $right.TypeCode
    | project-rename RegistryPreviousValueType = TypeName
    | extend
    RegistryValueData = iff (EventOriginalSubType == "%%1906", OldValue,
    NewValue)
    ,
    RegistryPreviousKey = iff (EventOriginalSubType == "%%1905", RegistryKey,
    "")
    ,
    RegistryPreviousValue = iff (EventOriginalSubType == "%%1905",
    RegistryValue, "")
    ,
    RegistryPreviousValueData = iff (EventOriginalSubType == "%%1905",
    OldValue, "")
    | project-away
    NewValueType,
    OldValueType,
    EventOriginalSubType,
    OldValue,
    NewValue
    )
    | invoke _ASIM_ResolveFQDN ("Computer")
    | extend
    ActorUserIdType = iff (ActorUserId <> "S-1-0-0", "SID", ""),
    ActorUserId = iff (ActorUserId <> "S-1-0-0", ActorUserId, "")
    | project-rename
    DvcDomainType = DomainType
    ,
    DvcHostname = ExtractedHostname
    | extend
    DvcFQDN = iif(DvcDomainType == "FQDN", FQDN, "")
    ,
    DvcDomain = iif(isnotempty(Domain), Domain, "")
    ,
    Dvc = iif(DvcDomainType == "FQDN", FQDN, "DvcHostname")
    | extend
    ActorUserType = _ASIM_GetWindowsUserType(ActorUsername, ActorUserId)
    ,
    ActorUsernameType = ASIM_GetAccountType(ActorUserId)
    | extend
    User = ActorUsername
    ,
    UserId = ActorUserId
    ,
    ActorUserSid = ActorUserId
    ,
    Process = ActingProcessName
    ,
    Dvc = iif(DvcDomainType == "FQDN", Computer, "")
    ,
    EventStartTime = TimeGenerated
    ,
    EventEndTime = TimeGenerated
    ,
    EventOriginalType = tostring(EventID)
    | extend
    EventSchemaVersion = "0.1"
    ,
    EventSchema = "RegistryEvent"
    ,
    EventCount = toint(1)
    ,
    EventResult = "Success"
    ,
    EventVendor = "Microsoft"
    ,
    EventProduct = "Security Events"
    ,
    DvcOs = "Windows"
    | project-away ActorDomainName,ActorUserSid,ActorUserType,Computer,Domain,Dv
    cDomainType,DvcDomain,DvcFQDN,EventID,FQDN,UserId,_ResourceId
    };
    parser (
    starttime                = starttime,
    endtime                  = endtime,
    eventtype_in             = eventtype_in,
    actorusername_has_any    = actorusername_has_any,
    registrykey_has_any = registrykey_has_any,
    registryvalue_has_any = registryvalue_has_any,
    registrydata_has_any = registrydata_has_any,
    dvchostname_has_any= dvchostname_has_any,
    disabled                 = disabled
    )
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/savedSearches/vimregistryeventmicrosoftwindowsevent
 
 name: 'vimregistryeventmicrosoftwindowsevent' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
