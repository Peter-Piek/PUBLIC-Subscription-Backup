# TI map Email entity to SecurityAlert

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/6fc5045a-e8c5
  -4166-93c2-707388526aa2
 
 name: '6fc5045a-e8c5-4166-93c2-707388526aa2' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'P14D' 
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
         columnName: 'Name' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'UPNSuffix' 
    - 
      entityType: 'URL' 
      fieldMappings: 
       - 
         identifier: 'Url' 
         columnName: 'Url' 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h;
    let ioc_lookBack = 14d;
    let emailregex = @'^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$';
    ThreatIntelligenceIndicator
    //Filtering the table for Email related IOCs
    | where isnotempty(EmailSenderAddress)
    | where TimeGenerated >= ago(ioc_lookBack)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    // using innerunique to keep perf fast and result set low, we only need one match
    to indicate potential malicious activity that needs to be investigated
    | join kind=innerunique (
    SecurityAlert
    | where TimeGenerated >= ago(dt_lookBack)
    | extend MSTI = case(AlertName has "TI map" and VendorName == "Microsoft" and
    ProductName == 'Azure Sentinel', true, false)
    | where MSTI == false
    // Converting Entities into dynamic data type and use mv-expand to unpack the
    array
    | extend EntitiesDynamicArray = parse_json(Entities) | mv-expand EntitiesDyn
    amicArray
    // Parsing relevant entity column to filter type account and creating new
    column by combining account and UPNSuffix
    | extend Entitytype = tostring(parse_json(EntitiesDynamicArray).Type), EntityName
    = tostring(parse_json(EntitiesDynamicArray).Name),
    EntityUPNSuffix = tostring(parse_json(EntitiesDynamicArray).UPNSuffix)
    | where Entitytype =~ "account"
    | extend EntityEmail = tolower(strcat(EntityName, "@", EntityUPNSuffix))
    | where EntityEmail matches regex emailregex
    | extend Alert_TimeGenerated = TimeGenerated
    )
    on $left.EmailSenderAddress == $right.EntityEmail
    | where Alert_TimeGenerated < ExpirationDateTime
    | summarize Alert_TimeGenerated = arg_max(Alert_TimeGenerated, *) by IndicatorId,
    AlertName
    | project Alert_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, Url, ExpirationDateTime, ConfidenceScore,
    EmailSenderName, EmailRecipient, EmailSourceDomain, EmailSourceIpAddress, EmailSubject,
    FileHashValue, FileHashType, EntityEmail, AlertName, AlertType,
    AlertSeverity, Entities, ProviderName, VendorName
    | extend Name = tostring(split(EntityEmail, '@', 0)[0]), UPNSuffix =
    tostring(split(EntityEmail, '@', 1)[0])
    | extend timestamp = Alert_TimeGenerated
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map Email entity to SecurityAlert' 
   enabled: true 
   description: >
    Identifies a match in SecurityAlert table from any Email IOC from TI which will
    extend coverage to datatypes such as MCAS, StorageThreatProtection and many oth
    ers
 
   alertRuleTemplateName: 'a2e36ce0-da4d-4b6e-88c6-4e40161c5bfc' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
