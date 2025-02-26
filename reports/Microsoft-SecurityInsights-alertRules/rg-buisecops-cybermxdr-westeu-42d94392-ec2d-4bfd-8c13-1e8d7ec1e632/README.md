# SUNBURST network beacons

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/42d94392-ec2d
  -4bfd-8c13-1e8d7ec1e632
 
 name: '42d94392-ec2d-4bfd-8c13-1e8d7ec1e632' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let SunburstURL=dynamic(["panhardware.com","databasegalore.com","avsvmcloud.com"
    ,"freescanonline.com","thedoccloud.com","deftsecurity.com"]);
    DeviceNetworkEvents
    | where ActionType == "ConnectionSuccess"
    | where RemoteUrl in(SunburstURL)
    | extend timestamp = TimeGenerated,AccountEntity = iff(isnotempty(InitiatingProc
    essAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),HashA
    lgorithm = 'MD5'
    | extend HostName = tostring(split(DeviceName, '.', 0)[0]), DnsDomain = tostring
    (strcat_array(array_slice(split(DeviceName, '.'), 1, -1), '.'))
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
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
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'Name' 
         columnName: 'AccountEntity' 
    - 
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'HostName' 
         columnName: 'HostName' 
       - 
         identifier: 'DnsDomain' 
         columnName: 'DnsDomain' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'RemoteIP' 
    - 
      entityType: 'URL' 
      fieldMappings: 
       - 
         identifier: 'Url' 
         columnName: 'RemoteUrl' 
    - 
      entityType: 'FileHash' 
      fieldMappings: 
       - 
         identifier: 'Algorithm' 
         columnName: 'HashAlgorithm' 
       - 
         identifier: 'Value' 
         columnName: 'InitiatingProcessMD5' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Execution' 
    - 'Persistence' 
    - 'InitialAccess' 
   techniques: 
    - 'T1195' 
    - 'T1059' 
    - 'T1546' 
   subTechniques: null 
   displayName: 'SUNBURST network beacons' 
   enabled: true 
   description: >
    Identifies SolarWinds SUNBURST domain beacon IOCs in DeviceNetworkEvents
    References:
    - https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverage
    s-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
    - https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f
 
   alertRuleTemplateName: 'ce1e7025-866c-41f3-9b08-ec170e05e73e' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
