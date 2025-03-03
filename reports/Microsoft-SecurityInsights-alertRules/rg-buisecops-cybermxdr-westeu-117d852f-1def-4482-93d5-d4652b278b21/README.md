# TI map Domain entity to SecurityAlert

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/117d852f-1def
  -4482-93d5-d4652b278b21
 
 name: '117d852f-1def-4482-93d5-d4652b278b21' 
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
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'HostName' 
         columnName: 'HostName' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'IP_addr' 
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
    let SecurityAlerts = SecurityAlert
    | where TimeGenerated > ago(dt_lookBack)
    | extend domain = todynamic(dynamic_to_json(extract_all(@"(((xn--)?[a-z0-9\-]+\.
    )+([a-z]+|(xn--[a-z0-9]+)))", dynamic([1]), tolower(Entities))))
    | where isnotempty(domain)
    | mv-expand domain
    | extend domain = tostring(domain)
    | extend EntitiesDynamicArray = parse_json(Entities)
    | mv-apply EntitiesDynamicArray on
    (summarize
    HostName = take_anyif(tostring(EntitiesDynamicArray.HostName),
    EntitiesDynamicArray.Type == "host"),
    IP_addr = take_anyif(tostring(EntitiesDynamicArray.Address),
    EntitiesDynamicArray.Type == "ip")
    )
    | extend Alert_TimeGenerated = TimeGenerated
    | extend Alert_Description = Description;
    let AlertDomains = SecurityAlerts
    | distinct domain
    | summarize make_list(domain);
    let Domain_Indicators = materialize(ThreatIntelligenceIndicator
    | where isnotempty(DomainName)
    | where TimeGenerated >= ago(ioc_lookBack)
    | extend TI_DomainEntity = tolower(DomainName)
    | where TI_DomainEntity in (AlertDomains)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    | where Description !contains_cs "State: inactive;" and Description !contains_cs
    "State: falsepos;");
    Domain_Indicators
    // Using innerunique to keep performance fast and result set low, we only need one
    match to indicate potential malicious activity that needs to be investigated
    | join kind=innerunique (SecurityAlerts) on $left.TI_DomainEntity == $right.doma
    in
    | where Alert_TimeGenerated < ExpirationDateTime
    | summarize Alert_TimeGenerated = arg_max(Alert_TimeGenerated, *) by IndicatorId,
    AlertName
    | project Alert_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, ExpirationDateTime, ConfidenceScore, DomainName, AlertName,
    Alert_Description, ProviderName, AlertSeverity, ConfidenceLevel, HostName, IP_addr,
    Url, Entities, Type, TI_DomainEntity
    | extend timestamp = Alert_TimeGenerated
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map Domain entity to SecurityAlert' 
   enabled: true 
   description: 'Identifies a match in SecurityAlert table from any Domain IOC from TI' 
   alertRuleTemplateName: '87890d78-3e05-43ec-9ab9-ba32f4e01250' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
