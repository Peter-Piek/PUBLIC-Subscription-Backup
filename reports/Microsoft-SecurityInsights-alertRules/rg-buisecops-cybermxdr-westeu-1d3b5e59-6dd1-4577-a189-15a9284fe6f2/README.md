# Sdelete deployed via GPO and run recursively

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/1d3b5e59-6dd1
  -4577-a189-15a9284fe6f2
 
 name: '1d3b5e59-6dd1-4577-a189-15a9284fe6f2' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    SecurityEvent
    | where EventID == 4688
    | where Process =~ "svchost.exe"
    | where CommandLine has "-k GPSvcGroup" or CommandLine has "-s gpsvc"
    | extend timekey = bin(TimeGenerated, 1m)
    | project timekey, NewProcessId, Computer
    | join kind=inner (SecurityEvent
    | where EventID == 4688
    | where Process =~ "sdelete.exe" or CommandLine has "sdelete"
    | where ParentProcessName endswith "svchost.exe"
    | where CommandLine has_all ("-s", "-r")
    | extend newProcess = Process
    | extend timekey = bin(TimeGenerated, 1m)
    ) on $left.NewProcessId == $right.ProcessId, timekey, Computer
 
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
    - 'Impact' 
   techniques: 
    - 'T1485' 
   subTechniques: null 
   displayName: 'Sdelete deployed via GPO and run recursively' 
   enabled: true 
   description: >
    This query looks for the Sdelete process being run recursively after being deployed
    to a host via GPO. Attackers could use this technique to deploy Sdelete to multiple
    host and delete data on them.
 
   alertRuleTemplateName: 'd9f28fdf-abc8-4f1a-a7e7-1aaec87a2fc5' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
