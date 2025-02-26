# SUNBURST and SUPERNOVA backdoor hashes

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/cf3b6a9d-6d36
  -49bb-8699-3de2720a6fcb
 
 name: 'cf3b6a9d-6d36-49bb-8699-3de2720a6fcb' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'High' 
   query: >
    let SunburstMD5=dynamic(["b91ce2fa41029f6955bff20079468448","02af7cec58b9a5da1c5
    42b5a32151ba1","2c4a910a1299cdae2a4e55988a2f102e","846e27a652a5e1bfbd0ddd38a16dc
    865","4f2eb62fa529c0283b28d05ddd311fae"]);
    let SupernovaMD5="56ceb6d0011d87b6e4d7023d7ef85676";
    DeviceFileEvents
    | where MD5 in(SunburstMD5) or MD5 in(SupernovaMD5)
    | extend timestamp = TimeGenerated, Account = iff(isnotempty(InitiatingProcessAc
    countUpn), InitiatingProcessAccountUpn, InitiatingProcessAccountName),AlgorithmE
    ntity = "MD5" ,FileHashEntity = MD5
 
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
         columnName: 'Account' 
    - 
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'HostName' 
         columnName: 'DeviceName' 
    - 
      entityType: 'FileHash' 
      fieldMappings: 
       - 
         identifier: 'Algorithm' 
         columnName: 'AlgorithmEntity' 
       - 
         identifier: 'Value' 
         columnName: 'FileHashEntity' 
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
   displayName: 'SUNBURST and SUPERNOVA backdoor hashes' 
   enabled: true 
   description: >
    Identifies SolarWinds SUNBURST and SUPERNOVA backdoor file hash IOCs in DeviceFi
    leEvents
    References:
    - https://www.fireeye.com/blog/threat-research/2020/12/evasive-attacker-leverage
    s-solarwinds-supply-chain-compromises-with-sunburst-backdoor.html
    - https://gist.github.com/olafhartong/71ffdd4cab4b6acd5cbcd1a0691ff82f
 
   alertRuleTemplateName: 'a3c144f9-8051-47d4-ac29-ffb0c312c910' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
