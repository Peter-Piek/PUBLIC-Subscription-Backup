# Gain Code Execution on ADFS Server via SMB + Remote Service or Scheduled Task

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/2d761179-f06c
  -4cc3-becd-3ab048697b03
 
 name: '2d761179-f06c-4cc3-becd-3ab048697b03' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P7D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let timeframe = 1d;
    // Adjust for a longer timeframe for identifying ADFS Servers
    let lookback = 6d;
    // Identify ADFS Servers
    let ADFS_Servers = (
    SecurityEvent
    | where TimeGenerated > ago(timeframe+lookback)
    | where EventID == 4688 and SubjectLogonId != "0x3e4"
    | where NewProcessName has "Microsoft.IdentityServer.ServiceHost.exe"
    | distinct Computer
    );
    SecurityEvent
    | where TimeGenerated > ago(timeframe)
    | where Computer in~ (ADFS_Servers)
    | where Account !endswith "$"
    // Check for scheduled task events
    | where EventID in (4697, 4698, 4699, 4700, 4701, 4702)
    | extend EventDataParsed = parse_xml(EventData)
    | extend SubjectLogonId = tostring(EventDataParsed.EventData.Data[3]["#text"])
    // Check specifically for access to IPC$ share and PIPE\svcctl and PIPE\atsvc for
    Service Control Services and Schedule Control Services
    | union (
    SecurityEvent
    | where TimeGenerated > ago(timeframe)
    | where Computer in~ (ADFS_Servers)
    | where Account !endswith "$"
    | where EventID == 5145
    | where RelativeTargetName =~ "svcctl" or RelativeTargetName  =~ "atsvc"
    )
    // Check for lateral movement
    | join kind=inner
    (SecurityEvent
    | where TimeGenerated > ago(timeframe)
    | where Account !endswith "$"
    | where EventID == 4624 and LogonType == 3
    ) on $left.SubjectLogonId == $right.TargetLogonId
    | project TimeGenerated, Account, Computer, EventID, RelativeTargetName
    | extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity
    = Account
 
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
         columnName: 'AccountCustomEntity' 
    - 
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'FullName' 
         columnName: 'HostCustomEntity' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'LateralMovement' 
   techniques: 
    - 'T1210' 
   subTechniques: null 
   displayName: 'Gain Code Execution on ADFS Server via SMB + Remote Service or Scheduled Task' 
   enabled: true 
   description: >
    This query detects instances where an attacker has gained the ability to execute
    code on an ADFS Server through SMB and Remote Service or Scheduled Task.
 
   alertRuleTemplateName: '12dcea64-bec2-41c9-9df2-9f28461b1295' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
