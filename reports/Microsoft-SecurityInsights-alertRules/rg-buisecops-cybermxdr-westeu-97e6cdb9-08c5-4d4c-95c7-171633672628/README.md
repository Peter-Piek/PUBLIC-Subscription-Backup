# TEARDROP memory-only dropper

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/97e6cdb9-08c5
  -4d4c-95c7-171633672628
 
 name: '97e6cdb9-08c5-4d4c-95c7-171633672628' 
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
      entityType: 'FileHash' 
      fieldMappings: 
       - 
         identifier: 'Algorithm' 
         columnName: 'FileHashType' 
       - 
         identifier: 'Value' 
         columnName: 'InitiatingProcessSHA1' 
   severity: 'High' 
   query: >
    DeviceEvents
    | where ActionType has "ExploitGuardNonMicrosoftSignedBlocked"
    | where InitiatingProcessFileName has "svchost.exe" and FileName has "NetSetupSv
    c.dll"
    | extend timestamp = TimeGenerated, AccountEntity = iff(isnotempty(InitiatingPro
    cessAccountUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),File
    HashType = "SHA1"
    | extend HostName = tostring(split(DeviceName, '.', 0)[0]), DnsDomain = tostring
    (strcat_array(array_slice(split(DeviceName, '.'), 1, -1), '.'))
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Execution' 
    - 'Persistence' 
    - 'DefenseEvasion' 
   techniques: 
    - 'T1543' 
    - 'T1059' 
    - 'T1027' 
   displayName: 'TEARDROP memory-only dropper' 
   enabled: true 
   description: >
    Identifies SolarWinds TEARDROP memory-only dropper IOCs in Window's defender Exploit
    Guard activity
    References:
    - https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverage
    s-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
    - https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f
 
   alertRuleTemplateName: '738702fd-0a66-42c7-8586-e30f0583f8fe' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
