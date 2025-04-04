# SUNSPOT malware hashes

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/7e3833b2-46fa
  -4101-99b5-e87848b2a5b8
 
 name: '7e3833b2-46fa-4101-99b5-e87848b2a5b8' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   incidentConfiguration: 
     createIncident: true 
     groupingConfiguration: 
       enabled: null 
       reopenClosedIncident: null 
       lookbackDuration: 'PT5M' 
       matchingMethod: 'AllEntities' 
       groupByEntities: null 
       groupByAlertDetails: null 
       groupByCustomDetails: null 
   entityMappings: 
    - 
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'HostName' 
         columnName: 'HostName' 
       - 
         identifier: 'DnsDomain' 
         columnName: 'DnsDomain' 
   severity: 'Medium' 
   query: >
    let SUNSPOT_Hashes = dynamic(["c45c9bda8db1d470f1fd0dcc346dc449839eb5ce9a948c703
    69230af0b3ef168", "0819db19be479122c1d48743e644070a8dc9a1c852df9a8c0dc2343e904da
    389"]);
    union isfuzzy=true(
    DeviceEvents
    | where InitiatingProcessSHA256 in (SUNSPOT_Hashes)),
    (DeviceImageLoadEvents
    | where InitiatingProcessSHA256 in (SUNSPOT_Hashes))
    | extend timestamp=TimeGenerated
    | extend HostName = tostring(split(DeviceName, '.', 0)[0]), DnsDomain = tostring
    (strcat_array(array_slice(split(DeviceName, '.'), 1, -1), '.'))
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Persistence' 
   techniques: 
    - 'T1554' 
   displayName: 'SUNSPOT malware hashes' 
   enabled: true 
   description: >
    This query uses Microsoft Defender for Endpoint data to look for IoCs associated
    with the SUNSPOT malware shared by Crowdstrike.
    More details:
    - https://www.crowdstrike.com/blog/sunspot-malware-technical-analysis/
    - https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-your-softwa
    re-build-process-with-azure-sentinel/ba-p/2140807
 
   alertRuleTemplateName: '53e936c6-6c30-4d12-8343-b8a0456e8429' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
