# Heartbeat stopped [custom]

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/731206f3-0674
  -4dc8-a80a-b297520dfe2b
 
 name: '731206f3-0674-4dc8-a80a-b297520dfe2b' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P2D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    Heartbeat
    | where TimeGenerated > ago(24hr)
    |extend LocalIP = iff(isnotempty(parse_json(ComputerPrivateIPs.[0])),parse_json(
    ComputerPrivateIPs.[0]),"")
    | summarize LastHeartbeat=max(TimeGenerated) by Computer, LocalIP
    | where LastHeartbeat < ago(1h)
    | project LastHeartbeat, Computer, LocalIP
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   incidentConfiguration: 
     createIncident: true 
     groupingConfiguration: 
       enabled: true 
       reopenClosedIncident: null 
       lookbackDuration: 'PT8H' 
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
         columnName: 'Computer' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: null 
   techniques: null 
   subTechniques: null 
   displayName: 'Heartbeat stopped [custom]' 
   enabled: true 
   description: >
    A computer has stopped sending heartbeats to the workspace. Please check the Host
    is up and that the Microsoft Monitoring Agent service is running
 
   alertRuleTemplateName: null 
   lastModifiedUtc: 2024-10-30T13:02:29
```
