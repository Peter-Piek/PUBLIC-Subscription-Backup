# TI map Domain entity to DnsEvents

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/235e8e36-b8c1
  -4ae8-9337-9d49d168d4ea
 
 name: '235e8e36-b8c1-4ae8-9337-9d49d168d4ea' 
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
         identifier: 'DnsDomain' 
         columnName: 'DnsDomain' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'ClientIP' 
    - 
      entityType: 'URL' 
      fieldMappings: 
       - 
         identifier: 'Url' 
         columnName: 'Url' 
   severity: 'Medium' 
   query: >
    // Define the lookback periods for time-based filters
    let dt_lookBack = 1h; // Look back 1 hour for DNS events
    let ioc_lookBack = 14d; // Look back 14 days for threat intelligence indicators
    // Fetch threat intelligence indicators related to domains
    let Domain_Indicators = ThreatIntelligenceIndicator
    // Filter out indicators without domain names
    | where isnotempty(DomainName)
    | where TimeGenerated >= ago(ioc_lookBack)
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now()
    | extend TI_DomainEntity = DomainName;
    // Create a list of TLDs in our threat feed for later validation
    let maxListSize = 100000; // Define the maximum allowed size for each list
    let list_tlds = Domain_Indicators
    | extend parts = split(DomainName, '.')
    | extend tld = parts[(array_length(parts)-1)]
    | summarize count() by tostring(tld)
    | project tld
    | summarize make_list(tld, maxListSize);
    // Perform a join between domain indicators and DNS events to identify potential
    malicious activity
    Domain_Indicators
    // Use innerunique to keep performance fast and result set low, as we only need
    one match to indicate potential malicious activity that needs investigation
    | join kind=innerunique (
    DnsEvents
    | where TimeGenerated > ago(dt_lookBack)
    // Extract domain patterns from syslog message
    | where isnotempty(Name)
    | extend parts = split(Name, '.')
    | extend tld = parts[(array_length(parts)-1)]
    // Validate parsed domain by checking if the TLD is in the list of TLDs in our
    threat feed
    | where tld in~ (list_tlds)
    | extend DNS_TimeGenerated = TimeGenerated
    ) on $left.TI_DomainEntity==$right.Name
    // Filter out DNS events that occurred after the expiration of the corresponding
    indicator
    | where DNS_TimeGenerated < ExpirationDateTime
    // Group the results by IndicatorId and Name, and keep the DNS event with the
    latest timestamp
    | summarize DNS_TimeGenerated = arg_max(DNS_TimeGenerated, *) by IndicatorId,
    Name
    // Select the desired output fields
    | project DNS_TimeGenerated, Description, ActivityGroupNames, IndicatorId,
    ThreatType, ExpirationDateTime, ConfidenceScore, Url, Computer, ClientIP, Name,
    QueryType, Type, TI_DomainEntity
    // Extract hostname and DNS domain from the Computer field
    | extend HostName = tostring(split(Computer, '.', 0)[0]), DnsDomain = tostring
    (strcat_array(array_slice(split(Computer, '.'), 1, -1), '.'))
    // Rename the timestamp field
    | extend timestamp = DNS_TimeGenerated
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map Domain entity to DnsEvents' 
   enabled: true 
   description: 'Identifies a match in DnsEvents from any Domain IOC from TI' 
   alertRuleTemplateName: '85aca4d1-5d15-4001-abd9-acb86ca1786a' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
