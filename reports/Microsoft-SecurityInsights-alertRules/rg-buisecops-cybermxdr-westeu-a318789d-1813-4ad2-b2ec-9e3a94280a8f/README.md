# Successful sign-in from Russia / Ukraine [custom]

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/a318789d-1813
  -4ad2-b2ec-9e3a94280a8f
 
 name: 'a318789d-1813-4ad2-b2ec-9e3a94280a8f' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT30M' 
   queryPeriod: 'PT30M' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   incidentConfiguration: 
     createIncident: true 
     groupingConfiguration: 
       enabled: null 
       reopenClosedIncident: null 
       lookbackDuration: 'PT5H' 
       matchingMethod: 'AllEntities' 
       groupByEntities: null 
       groupByAlertDetails: null 
       groupByCustomDetails: null 
   customDetails: 
     UserAgent: 'UserAgent' 
     Country: 'Location' 
   entityMappings: 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'FullName' 
         columnName: 'UserPrincipalName' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'IPAddress' 
   severity: 'High' 
   query: >
    //V1//
    let country_code = dynamic(["RU", "UA"]);
    union
    (SigninLogs
    | where Location in (country_code)
    | where ResultType == 0),
    (AADNonInteractiveUserSignInLogs
    | where Location in (country_code)
    | where ResultType == 0)
    | summarize
    StartTime = min(TimeGenerated),
    EndTime = max(TimeGenerated),
    IP_List=make_set(IPAddress),
    Application_List=make_set(AppDisplayName),
    Location_List=make_set(Location),
    count()
    by UserPrincipalName, UserAgent, ResultType
    | project FirstSeen=StartTime,LastSeen=EndTime , UserPrincipalName, UserAgent,
    Location=Location_List, IPAddress=IP_List, count_

 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'InitialAccess' 
   techniques: null 
   displayName: 'Successful sign-in from Russia / Ukraine [custom]' 
   enabled: true 
   description: 'Detecting sign-ins from Russia / Ukraine in response to threat of attack' 
   alertRuleTemplateName: null 
   lastModifiedUtc: 2024-10-30T13:02:03
```
