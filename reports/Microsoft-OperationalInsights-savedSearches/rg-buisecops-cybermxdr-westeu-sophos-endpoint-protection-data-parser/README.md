# Sophos Endpoint Protection Data Parser

```
--- 
 properties: 
   category: 'Microsoft Sentinel Parser' 
   displayName: 'Sophos Endpoint Protection Data Parser' 
   version: 2 
   functionAlias: 'SophosEPEvent' 
   query: >
    let SophosEP_CL = view() {
    SophosEP_CL
    | extend EventVendor = 'Sophos'
    | extend EventProduct = 'Endpoint Protection'
    | extend TimeGenerated = created_at_t
    | extend
    DstUserSid = column_ifexists('user_id_s', ''),
    CustomerId = column_ifexists('customer_id_g', ''),
    EventSeverity = column_ifexists('severity_s', ''),
    Created = column_ifexists('created_at_t', ''),
    SrcIpAddr = column_ifexists('source_info_ip_s', ''),
    ThreatName  = column_ifexists('threat_s', ''),
    EndpointId  = column_ifexists('endpoint_id_g', ''),
    SrcDvcType  = column_ifexists('endpoint_type_s', ''),
    EventSubType  = column_ifexists('origin_s', ''),
    EventEndTime  = column_ifexists('when_t', ''),
    Source  = column_ifexists('source_s', ''),
    DvcAction  = column_ifexists('type_s', ''),
    EventMessage  = column_ifexists('name_s', ''),
    DvcHostname  = column_ifexists('location_s', ''),
    EventOriginalUid  = column_ifexists('id_g', ''),
    ThreatCategory  = column_ifexists('group_s', ''),
    EventType  = column_ifexists('datastream_s', ''),
    AppSha256 = column_ifexists('appSha256_s', ''),
    CoreRemedyItems= column_ifexists('core_remedy_items_items_s', ''),
    CoreRemedyTotalItems= toint(column_ifexists('core_remedy_items_totalItems_d'
    , ''))
    };
    let SophosEPEvents_CL=view() {
    SophosEPEvents_CL
    };
    let SophosEPAlerts_CL=view() {
    SophosEPAlerts_CL
    };
    union withsource='SourceTable' isfuzzy= true
    SophosEP_CL,
    SophosEPEvents_CL,
    SophosEPAlerts_CL
    | project
    TimeGenerated,
    SourceTable,
    CustomerId,
    EventSeverity,
    Created,
    EventEndTime,
    DvcAction,
    EventMessage,
    SrcIpAddr,
    ThreatName,
    EndpointId,
    SrcDvcType,
    EventSubType,
    Source,
    DvcHostname,
    EventOriginalUid,
    ThreatCategory,
    DstUserSid,
    CoreRemedyItems,
    CoreRemedyTotalItems,
    AppSha256,
    EventType,
    EventVendor,
    EventProduct

 
   tags: 
    - 
      name: 'description' 
      value: null 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/savedSearches/sophos endpoint protection data parser
 
 name: 'sophos endpoint protection data parser' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
