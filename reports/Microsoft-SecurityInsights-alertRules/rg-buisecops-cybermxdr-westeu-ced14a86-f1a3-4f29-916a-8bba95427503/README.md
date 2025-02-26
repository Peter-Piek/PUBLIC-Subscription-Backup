# Potential re-named sdelete usage

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/ced14a86-f1a3
  -4f29-916a-8bba95427503
 
 name: 'ced14a86-f1a3-4f29-916a-8bba95427503' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'PT1H' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Low' 
   query: >
    SecurityEvent
    | where EventID == 4688
    | where Process !~ "sdelete.exe"
    | where CommandLine has_all ("accepteula", "-r", "-s", "-q", "c:/")
    | where CommandLine !has ("sdelete")
 
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
         identifier: 'FullName' 
         columnName: 'Account' 
    - 
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'FullName' 
         columnName: 'Computer' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'DefenseEvasion' 
    - 'Impact' 
   techniques: 
    - 'T1485' 
    - 'T1036' 
   subTechniques: null 
   displayName: 'Potential re-named sdelete usage' 
   enabled: true 
   description: >
    This detection looks for command line parameters associated with the use of
    Sysinternals sdelete (https://docs.microsoft.com/sysinternals/downloads/sdelete
    ) to delete multiple files on a host's C drive.
    A threat actor may re-name the tool to avoid detection and then use it for destructive
    attacks on a host.
 
   alertRuleTemplateName: '720d12c6-a08c-44c4-b18f-2236412d59b0' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
