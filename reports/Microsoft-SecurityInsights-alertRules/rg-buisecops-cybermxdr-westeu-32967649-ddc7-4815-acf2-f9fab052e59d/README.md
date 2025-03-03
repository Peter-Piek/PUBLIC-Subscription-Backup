# Multiple Teams deleted by a single user

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/32967649-ddc7
  -4815-acf2-f9fab052e59d
 
 name: '32967649-ddc7-4815-acf2-f9fab052e59d' 
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
         columnName: 'AccountName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'AccountUPNSuffix' 
   severity: 'Low' 
   query: >
    // Adjust this value to change how many Teams should be deleted before including
    let max_delete_count = 3;
    // Adjust this value to change the timewindow the query runs over
    OfficeActivity
    | where OfficeWorkload =~ "MicrosoftTeams"
    | where Operation =~ "TeamDeleted"
    | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated), DeletedTeams
    = make_set(TeamName, 1000) by UserId
    | where array_length(DeletedTeams) > max_delete_count
    | extend AccountName = tostring(split(UserId, "@")[0]), AccountUPNSuffix =
    tostring(split(UserId, "@")[1])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: 
    - 'T1485' 
    - 'T1489' 
   displayName: 'Multiple Teams deleted by a single user' 
   enabled: true 
   description: >
    This detection flags the occurrences of deleting multiple teams within an hour.
    This data is a part of Office 365 Connector in Microsoft Sentinel.
 
   alertRuleTemplateName: '173f8699-6af5-484a-8b06-8c47ba89b380' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
