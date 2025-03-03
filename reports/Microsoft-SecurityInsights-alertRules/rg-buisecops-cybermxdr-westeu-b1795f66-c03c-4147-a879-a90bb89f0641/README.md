# External user added and removed in short timeframe

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/b1795f66-c03c
  -4147-a879-a90bb89f0641
 
 name: 'b1795f66-c03c-4147-a879-a90bb89f0641' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'PT1H' 
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
    let TeamsAddDel = (Op:string){
    OfficeActivity
    | where OfficeWorkload =~ "MicrosoftTeams"
    | where Operation == Op
    | where Members has ("#EXT#")
    | mv-expand Members
    | extend UPN = tostring(Members.UPN)
    | where UPN has ("#EXT#")
    | project TimeGenerated, Operation, UPN, UserId, TeamName
    };
    let TeamsAdd = TeamsAddDel("MemberAdded")
    | project TimeAdded=TimeGenerated, Operation, UPN, UserWhoAdded = UserId, TeamNa
    me;
    let TeamsDel = TeamsAddDel("MemberRemoved")
    | project TimeDeleted=TimeGenerated, Operation, UPN, UserWhoDeleted = UserId, Te
    amName;
    TeamsAdd
    | join kind=inner (TeamsDel) on UPN
    | where TimeDeleted > TimeAdded
    | project TimeAdded, TimeDeleted, UPN, UserWhoAdded, UserWhoDeleted, TeamName
    | extend AccountName = tostring(split(UPN, "@")[0]), AccountUPNSuffix =
    tostring(split(UPN, "@")[1])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Persistence' 
   techniques: 
    - 'T1136' 
   displayName: 'External user added and removed in short timeframe' 
   enabled: true 
   description: >
    This detection flags the occurances of external user accounts that are added to a
    Team and then removed within
    one hour.
 
   alertRuleTemplateName: 'bff093b2-500e-4ae5-bb49-a5b1423cbd5b' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
