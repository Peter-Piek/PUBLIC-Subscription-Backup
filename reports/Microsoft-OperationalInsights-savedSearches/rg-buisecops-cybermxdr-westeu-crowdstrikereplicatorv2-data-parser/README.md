# Union Parser for all CrowdStrike Falcon Data Replicator events

```
--- 
 properties: 
   category: 'CrowdStrikeParser' 
   displayName: 'Union Parser for all CrowdStrike Falcon Data Replicator events' 
   version: 2 
   functionAlias: 'CrowdStrikeReplicatorV2' 
   functionParameters: >
    starttime:datetime=datetime(null),endtime:datetime=datetime(null),tablesRequired
    :dynamic=dynamic([]),eventTypesRequired:dynamic=dynamic([])
 
   query: >
    let parser = (
    starttime:datetime=datetime(null),
    endtime:datetime=datetime(null),
    tablesRequired:dynamic=dynamic([]),
    eventTypesRequired:dynamic=dynamic([])
    )
    {
    union isfuzzy=true
    (
    ASimDnsActivityLogs
    | where EventVendor == "CrowdStrike" and EventProduct == "Falcon Data Re
    plicator"
    | where array_length(tablesRequired) == 0 or "DNS" in~ (tablesRequired)
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0 or EventOriginalType in~ (
    eventTypesRequired)
    ),
    (
    ASimFileEventLogs_CL
    | where EventVendor == "CrowdStrike" and EventProduct == "Falcon Data Re
    plicator"
    | where array_length(tablesRequired) == 0 or "File" in~ (tablesRequired)
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0 or EventOriginalType in~ (
    eventTypesRequired)
    ),
    (
    ASimFileEventLogs
    | where EventVendor == "CrowdStrike" and EventProduct == "Falcon Data Re
    plicator"
    | where array_length(tablesRequired) == 0 or "File" in~ (tablesRequired)
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0 or EventOriginalType in~ (
    eventTypesRequired)
    ),
    (
    ASimProcessEventLogs
    | where EventVendor == "CrowdStrike" and EventProduct == "Falcon Data Re
    plicator"
    | where array_length(tablesRequired) == 0 or "Process" in~ (tablesRequir
    ed)
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0 or EventOriginalType in~ (
    eventTypesRequired)
    ),
    (
    ASimProcessEventLogs_CL
    | where EventVendor == "CrowdStrike" and EventProduct == "Falcon Data Re
    plicator"
    | where array_length(tablesRequired) == 0 or "Process" in~ (tablesRequir
    ed)
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0 or EventOriginalType in~ (
    eventTypesRequired)
    ),
    (
    ASimAuthenticationEventLogs
    | where EventVendor == "CrowdStrike" and EventProduct == "Falcon Data Re
    plicator"
    | where array_length(tablesRequired) == 0 or "Auth" in~ (tablesRequired)
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0 or EventOriginalType in~ (
    eventTypesRequired)
    ),
    (
    ASimAuthenticationEventLogs_CL
    | where EventVendor == "CrowdStrike" and EventProduct == "Falcon Data Re
    plicator"
    | where array_length(tablesRequired) == 0 or "Auth" in~ (tablesRequired)
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0 or EventOriginalType in~ (
    eventTypesRequired)
    ),
    (
    ASimNetworkSessionLogs
    | where EventVendor == "CrowdStrike" and EventProduct == "Falcon Data Re
    plicator"
    | where array_length(tablesRequired) == 0 or "Network" in~ (tablesRequir
    ed)
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0 or EventOriginalType in~ (
    eventTypesRequired)
    ),
    (
    ASimAuditEventLogs
    | where EventVendor == "CrowdStrike" and EventProduct == "Falcon Data Re
    plicator"
    | where array_length(tablesRequired) == 0 or "Audit" in~ (tablesRequired
    )
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0 or EventOriginalType in~ (
    eventTypesRequired)
    ),
    (
    ASimRegistryEventLogs_CL
    | where EventVendor == "CrowdStrike" and EventProduct == "Falcon Data Re
    plicator"
    | where array_length(tablesRequired) == 0 or "Registry" in~ (tablesRequi
    red)
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0 or EventOriginalType in~ (
    eventTypesRequired)
    ),
    (
    ASimRegistryEventLogs
    | where EventVendor == "CrowdStrike" and EventProduct == "Falcon Data Re
    plicator"
    | where array_length(tablesRequired) == 0 or "Registry" in~ (tablesRequi
    red)
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0 or EventOriginalType in~ (
    eventTypesRequired)
    ),
    (
    ASimUserManagementLogs_CL
    | where EventVendor == "CrowdStrike" and EventProduct == "Falcon Data Re
    plicator"
    | where array_length(tablesRequired) == 0 or "User" in~ (tablesRequired)
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0 or EventOriginalType in~ (
    eventTypesRequired)
    ),
    (
    ASimUserManagementActivityLogs
    | where EventVendor == "CrowdStrike" and EventProduct == "Falcon Data Re
    plicator"
    | where array_length(tablesRequired) == 0 or "User" in~ (tablesRequired)
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0 or EventOriginalType in~ (
    eventTypesRequired)
    ),
    (
    CrowdStrike_Additional_Events_CL
    | where array_length(tablesRequired) == 0 or "Additional" in~ (tablesReq
    uired)
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0 or name in~ (eventTypesReq
    uired)
    ),
    (
    CrowdStrike_Secondary_Data_CL
    | where array_length(tablesRequired) == 0 or "Secondary" in~ (tablesRequ
    ired)
    | where (isnull(starttime) or TimeGenerated>=starttime)
    and     (isnull(endtime) or TimeGenerated<=endtime)
    | where array_length(eventTypesRequired) == 0
    )
    };
    parser(
    starttime=starttime,
    endtime=endtime,
    tablesRequired=tablesRequired,
    eventTypesRequired=eventTypesRequired
    )

 
   tags: 
    - 
      name: 'description' 
      value: null 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/savedSearches/crowdstrikereplicatorv2 data parser
 
 name: 'crowdstrikereplicatorv2 data parser' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
