# New EXE deployed via Default Domain or Default Domain Controller Policies

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/6739ee37-0ff7
  -470c-98de-882d75d4001d
 
 name: '6739ee37-0ff7-470c-98de-882d75d4001d' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P14D' 
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
         identifier: 'FullName' 
         columnName: 'Computer' 
   severity: 'High' 
   query: >
    let known_processes = (
    SecurityEvent
    // If adjusting Query Period or Frequency update these
    | where TimeGenerated between(ago(14d)..ago(1d))
    | where EventID == 4688
    | where NewProcessName has_any ("Policies\\{6AC1786C-016F-11D2-945F-00C04fB984
    F9}", "Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}")
    | summarize by Process);
    SecurityEvent
    // If adjusting Query Period or Frequency update these
    | where TimeGenerated > ago(1d)
    | where EventID == 4688
    | where NewProcessName has_any ("Policies\\{6AC1786C-016F-11D2-945F-00C04fB984
    F9}", "Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}")
    | where Process !in (known_processes)
    // This will likely apply to multiple hosts so summarize these data
    | summarize FirstSeen=min(TimeGenerated), LastSeen=max(TimeGenerated) by Process,
    NewProcessName, CommandLine, Computer
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Execution' 
    - 'LateralMovement' 
   techniques: 
    - 'T1072' 
    - 'T1570' 
   displayName: 'New EXE deployed via Default Domain or Default Domain Controller Policies' 
   enabled: true 
   description: >
    This detection highlights executables deployed to hosts via either the Default
    Domain or Default Domain Controller Policies. These policies apply to all hosts
    or Domain Controllers and best practice is that these policies should not be used
    for deployment of files.
    A threat actor may use these policies to deploy files or scripts to all hosts in
    a domain.
 
   alertRuleTemplateName: '05b4bccd-dd12-423d-8de4-5a6fb526bb4f' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
