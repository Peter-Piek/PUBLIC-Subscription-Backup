# TI Map IP Entity to SigninLogs

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/37d662cf-bd08
  -4cec-8f9f-26f6fab7aedb
 
 name: '37d662cf-bd08-4cec-8f9f-26f6fab7aedb' 
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
    let Signins = materialize(union isfuzzy=true
    (SigninLogs
    | where TimeGenerated >= ago(dt_lookBack)),
    (AADNonInteractiveUserSignInLogs
    | where TimeGenerated >= ago(dt_lookBack)
    | extend Status = todynamic(Status), LocationDetails = todynamic(LocationDetai
    ls)));
    let SigninIPs = Signins | summarize make_list(IPAddress);
    let TI = materialize(ThreatIntelligenceIndicator
    | where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempt
    y(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
    | where TimeGenerated >= ago(ioc_lookBack)
    | extend TI_ipEntity = coalesce(NetworkIP, EmailSourceIpAddress, NetworkDestinationIP,
    NetworkSourceIP)
    | where TI_ipEntity in (SigninIPs)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    | where Description !contains_cs "State: inactive;" and Description !contains_cs
    "State: falsepos;");
    TI
    // using innerunique to keep perf fast and result set low, we only need one match
    to indicate potential malicious activity that needs to be investigated
    | join kind=innerunique (Signins) on $left.TI_ipEntity == $right.IPAddress
    | project-rename SigninLogs_TimeGenerated = TimeGenerated
    | where SigninLogs_TimeGenerated < ExpirationDateTime
    | extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Statu
    s.additionalDetails), StatusReason = tostring(Status.failureReason)
    | summarize SigninLogs_TimeGenerated = arg_max(SigninLogs_TimeGenerated, *) by
    IndicatorId, IPAddress
    | project SigninLogs_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, Url, ExpirationDateTime, ConfidenceScore, TI_ipEntity, IPAddress,
    UserPrincipalName, AppDisplayName, StatusCode, StatusDetails, StatusReason,
    NetworkIP, NetworkDestinationIP, NetworkSourceIP, EmailSourceIpAddress, Type
    | extend timestamp = SigninLogs_TimeGenerated, Name = tostring(split(UserPrincip
    alName, '@', 0)[0]), UPNSuffix = tostring(split(UserPrincipalName, '@', 1)[0])
 
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
         identifier: 'Name' 
         columnName: 'Name' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'UPNSuffix' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'IPAddress' 
    - 
      entityType: 'URL' 
      fieldMappings: 
       - 
         identifier: 'Url' 
         columnName: 'Url' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Impact' 
   techniques: null 
   subTechniques: null 
   displayName: 'TI Map IP Entity to SigninLogs' 
   enabled: true 
   description: >
    This query maps any IP indicators of compromise (IOCs) from threat intelligence
    (TI), by searching for matches in SigninLogs.
 
   alertRuleTemplateName: 'f2eb15bd-8a88-4b24-9281-e133edfba315' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
