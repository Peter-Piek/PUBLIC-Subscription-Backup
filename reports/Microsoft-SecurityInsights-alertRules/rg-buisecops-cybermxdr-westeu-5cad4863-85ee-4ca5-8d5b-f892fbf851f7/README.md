# TI map Domain entity to Syslog

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/5cad4863-85ee
  -4ca5-8d5b-f892fbf851f7
 
 name: '5cad4863-85ee-4ca5-8d5b-f892fbf851f7' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'P14D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h;  // Define the time range to look back for syslog data (1
    hour)
    let ioc_lookBack = 14d;  // Define the time range to look back for threat intelligence
    indicators (14 days)
    // Create a list of top-level domains (TLDs) from the threat feed for later vali
    dation
    let list_tlds = ThreatIntelligenceIndicator
    | where isnotempty(DomainName)
    | where TimeGenerated > ago(ioc_lookBack)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    | extend parts = split(DomainName, '.')
    | extend tld = parts[(array_length(parts)-1)]
    | summarize count() by tostring(tld)
    | summarize make_list(tld);
    // Fetch the latest active domain indicators from the threat intelligence data
    within the specified time range
    let Domain_Indicators = ThreatIntelligenceIndicator
    | where isnotempty(DomainName)
    | where TimeGenerated >= ago(ioc_lookBack)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    | extend TI_DomainEntity = DomainName;
    // Join the threat intelligence indicators with syslog data on matching domain e
    ntities
    Domain_Indicators
    | join kind=innerunique (
    Syslog
    | where TimeGenerated > ago(dt_lookBack)
    // Extract domain patterns from syslog messages
    | extend domain = extract("(([a-z0-9]+(-[a-z0-9]+)*\\.)+[a-z]{2,})",1, tolow
    er(SyslogMessage))
    | where isnotempty(domain)
    | extend parts = split(domain, '.')
    // Split out the top-level domain (TLD)
    | extend tld = parts[(array_length(parts)-1)]
    // Validate parsed domain by checking if the TLD is in the list of TLDs in our
    threat feed
    | where tld in~ (list_tlds)
    | extend Syslog_TimeGenerated = TimeGenerated
    ) on $left.TI_DomainEntity==$right.domain
    | where Syslog_TimeGenerated < ExpirationDateTime
    // Retrieve the latest syslog timestamp for each indicator and domain combinat
    ion
    | summarize Syslog_TimeGenerated = arg_max(Syslog_TimeGenerated, *) by IndicatorId,
    domain
    // Select the desired columns for the final result set
    | project Syslog_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, ExpirationDateTime, ConfidenceScore, SyslogMessage, Computer,
    ProcessName, domain, HostIP, Url, Type, TI_DomainEntity
    // Extract the hostname from the Computer field
    | extend HostName = tostring(split(Computer, '.', 0)[0])
    // Extract the DNS domain from the Computer field
    | extend DnsDomain = tostring(strcat_array(array_slice(split(Computer, '.'), 1,
    -1), '.'))
    // Assign the Syslog_TimeGenerated value to the timestamp field
    | extend timestamp = Syslog_TimeGenerated
 
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
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'HostName' 
         columnName: 'HostName' 
       - 
         identifier: 'DnsDomain' 
         columnName: 'DnsDomain' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'HostIP' 
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
   displayName: 'TI map Domain entity to Syslog' 
   enabled: true 
   description: 'Identifies a match in Syslog table from any Domain IOC from TI' 
   alertRuleTemplateName: '532f62c1-fba6-4baa-bbb6-4a32a4ef32fa' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
