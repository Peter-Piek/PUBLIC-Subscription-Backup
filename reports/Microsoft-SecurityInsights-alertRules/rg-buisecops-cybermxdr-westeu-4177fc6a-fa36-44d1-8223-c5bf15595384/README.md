# TI Map URL Entity to AuditLogs

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/4177fc6a-fa36
  -44d1-8223-c5bf15595384
 
 name: '4177fc6a-fa36-44d1-8223-c5bf15595384' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'P14D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h;
    let ioc_lookBack = 14d;
    let AuditEvents = materialize(AuditLogs
    | where TimeGenerated >= ago(dt_lookBack)
    // Extract the URL that is contained within the JSON data
    | extend Url = extract("(http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?
    :%[0-9a-fA-F][0-9a-fA-F]))+);", 1,tostring(TargetResources))
    | where isnotempty(Url)
    | extend userPrincipalName = tostring(parse_json(tostring(InitiatedBy.user)).u
    serPrincipalName)
    | extend TargetResourceDisplayName = tostring(TargetResources[0].displayName)
    | extend Audit_TimeGenerated = TimeGenerated);
    let AuditUrls = AuditEvents | distinct Url = tolower(Url) | summarize make_list(
    Url);
    ThreatIntelligenceIndicator
    | where isnotempty(Url)
    | where TimeGenerated >= ago(ioc_lookBack)
    | where tolower(Url) in (AuditUrls)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    | where Description !contains_cs "State: inactive;" and Description !contains_cs
    "State: falsepos;"
    // using innerunique to keep perf fast and result set low, we only need one match
    to indicate potential malicious activity that needs to be investigated
    | join kind=innerunique (AuditEvents) on Url
    | where Audit_TimeGenerated < ExpirationDateTime
    | summarize Audit_TimeGenerated = arg_max(Audit_TimeGenerated, *) by IndicatorId,
    Url
    | project Audit_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, ExpirationDateTime, ConfidenceScore,
    OperationName, Identity, userPrincipalName, TargetResourceDisplayName, Url
    | extend timestamp = Audit_TimeGenerated, AccountCustomEntity = userPrincipalName,
    HostCustomEntity = TargetResourceDisplayName, URLCustomEntity = Url
 
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
    - 
      entityType: 'URL' 
      fieldMappings: 
       - 
         identifier: 'Url' 
         columnName: 'URLCustomEntity' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Impact' 
   techniques: null 
   subTechniques: null 
   displayName: 'TI Map URL Entity to AuditLogs' 
   enabled: true 
   description: >
    This query identifies any URL indicators of compromise (IOCs) from threat intelligence
    (TI) by searching for matches in AuditLogs.
 
   alertRuleTemplateName: '712fab52-2a7d-401e-a08c-ff939cc7c25e' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
