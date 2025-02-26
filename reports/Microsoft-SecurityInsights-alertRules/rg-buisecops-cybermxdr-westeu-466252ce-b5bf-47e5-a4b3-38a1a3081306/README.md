# TI map Email entity to SigninLogs

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/466252ce-b5bf
  -47e5-a4b3-38a1a3081306
 
 name: '466252ce-b5bf-47e5-a4b3-38a1a3081306' 
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
    let emailregex = @'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$';
    let Signins = materialize(union isfuzzy=true
    ( SigninLogs | where TimeGenerated >= ago(dt_lookBack)),
    ( AADNonInteractiveUserSignInLogs | where TimeGenerated >= ago(dt_lookBack)
    | extend Status = todynamic(Status), LocationDetails = todynamic(LocationDet
    ails))
    | where isnotempty(UserPrincipalName) and UserPrincipalName matches regex emailr
    egex
    | extend UserPrincipalName = tolower(UserPrincipalName)
    | extend Status = todynamic(Status), LocationDetails = todynamic(LocationDetails
    )
    | extend StatusCode = tostring(Status.errorCode), StatusDetails = tostring(Statu
    s.additionalDetails)
    | extend State = tostring(LocationDetails.state), City = tostring(LocationDetail
    s.city), Region = tostring(LocationDetails.countryOrRegion)
    | extend SigninLogs_TimeGenerated = TimeGenerated);
    let SigninUPNs = Signins | distinct UserPrincipalName | summarize make_list(User
    PrincipalName);
    ThreatIntelligenceIndicator
    //Filtering the table for Email related IOCs
    | where isnotempty(EmailSenderAddress)
    | where TimeGenerated >= ago(ioc_lookBack)
    | where EmailSenderAddress in (SigninUPNs)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    | where Description !contains_cs "State: inactive;" and Description !contains_cs
    "State: falsepos;"
    | join kind=innerunique (Signins) on $left.EmailSenderAddress == $right.UserPrin
    cipalName
    | where SigninLogs_TimeGenerated < ExpirationDateTime
    | summarize SigninLogs_TimeGenerated = arg_max(SigninLogs_TimeGenerated, *) by
    IndicatorId, UserPrincipalName
    | project SigninLogs_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, Url, ExpirationDateTime, ConfidenceScore, EmailSenderName, EmailRecipient,
    EmailSourceDomain, EmailSourceIpAddress, EmailSubject, FileHashValue, FileHashType,
    IPAddress, UserPrincipalName, AppDisplayName, StatusCode, StatusDetails, NetworkIP,
    NetworkDestinationIP, NetworkSourceIP, Type
    | extend Name = tostring(split(UserPrincipalName, '@', 0)[0]), UPNSuffix = tostr
    ing(split(UserPrincipalName, '@', 1)[0])
    | extend timestamp = SigninLogs_TimeGenerated
 
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
   displayName: 'TI map Email entity to SigninLogs' 
   enabled: true 
   description: 'Identifies a match in SigninLogs table from any Email IOC from TI' 
   alertRuleTemplateName: '30fa312c-31eb-43d8-b0cc-bcbdfb360822' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
