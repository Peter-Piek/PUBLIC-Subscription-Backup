# Anomaly Sign In Event from an IP

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/146888bd-afd3
  -42b7-848a-57d4f1a04521
 
 name: '146888bd-afd3-42b7-848a-57d4f1a04521' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'PT1H' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let LookBack = 1h;
    let Data = (
    SigninLogs
    | where TimeGenerated >= ago(LookBack)
    | where parse_json(NetworkLocationDetails)[0].networkType != "trustedNamedLocation"
    // Excludes known tagged networks
    // Counts the number of sign in events in the last hour every 15 minutes by IP
    | make-series EventCounts = count() on TimeGenerated from ago(LookBack) to now()
    step 15m by IPAddress
    );
    let AnomalyAlert = (
    Data
    | extend (Anomalies, Score, Baseline) = series_decompose_anomalies(EventCounts,1
    .5,-1,'linefit')
    | mv-expand EventCounts,TimeGenerated,Anomalies to typeof(double),Baseline to
    typeof(long),Score to typeof(double)
    | where Anomalies > 0
    );
    AnomalyAlert
    | join kind = inner (SigninLogs
    | where TimeGenerated between (ago(LookBack) .. now())
    | where parse_json(NetworkLocationDetails)[0].networkType != "trustedNamedLocati
    on"
    | extend PasswordResult = tostring(parse_json(AuthenticationDetails).authenticat
    ionStepResultDetail)
    | summarize UserCount = dcount(UserPrincipalName), UserList = make_set(UserPrincipalName),
    AppName = make_set(AppDisplayName), PasswordResult = make_list(PasswordResult)
    by IPAddress) on IPAddress
    | where PasswordResult has "Correct Password"
    | where UserCount > 1 // looks for events targeting more than one user.
 
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
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'IPAddress' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'InitialAccess' 
   techniques: 
    - 'T1078' 
   subTechniques: null 
   displayName: 'Anomaly Sign In Event from an IP' 
   enabled: true 
   description: >
    Identifies sign-in anomalies from an IP in the last hour, targeting multiple users
    where the password is correct after multiple attempts
 
   alertRuleTemplateName: '9c1e9381-79dd-4ddf-9570-b73a1dc59fe0' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
