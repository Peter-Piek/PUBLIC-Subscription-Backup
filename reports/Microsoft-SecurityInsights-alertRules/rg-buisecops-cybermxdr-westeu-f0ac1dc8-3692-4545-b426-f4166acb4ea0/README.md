# TI Map IP Entity to Azure SQL Security Audit Events

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/f0ac1dc8-3692
  -4545-b426-f4166acb4ea0
 
 name: 'f0ac1dc8-3692-4545-b426-f4166acb4ea0' 
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
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'ClientIP' 
   severity: 'Medium' 
   query: >
    let dt_lookBack = 1h; // Look back 1 hour for AzureDiagnostics logs
    let ioc_lookBack = 14d; // Look back 14 days for threat intelligence indicators
    // Fetch threat intelligence indicators related to IP addresses
    let IP_Indicators = ThreatIntelligenceIndicator
    | where isnotempty(NetworkIP) or isnotempty(EmailSourceIpAddress) or isnotempt
    y(NetworkDestinationIP) or isnotempty(NetworkSourceIP)
    | where TimeGenerated >= ago(ioc_lookBack)
    | extend TI_ipEntity = iff(isnotempty(NetworkIP), NetworkIP, NetworkDestinatio
    nIP)
    | extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(NetworkSourceIP),
    NetworkSourceIP, TI_ipEntity)
    | extend TI_ipEntity = iff(isempty(TI_ipEntity) and isnotempty(EmailSourceIpAd
    dress), EmailSourceIpAddress, TI_ipEntity)
    | where ipv4_is_private(TI_ipEntity) == false and  TI_ipEntity !startswith "fe80"
    and TI_ipEntity !startswith "::" and TI_ipEntity !startswith "127."
    | summarize LatestIndicatorTime = arg_max(TimeGenerated, *) by IndicatorId
    | where Active == true and ExpirationDateTime > now();
    // Perform a join between IP indicators and AzureDiagnostics logs for SQL Security
    Audit events
    IP_Indicators
    // Use innerunique to keep performance fast and result set low, as we only need
    one match to indicate potential malicious activity that needs investigation
    | join kind=innerunique (
    AzureDiagnostics
    | where TimeGenerated >= ago(dt_lookBack)
    | where ResourceProvider == 'MICROSOFT.SQL'
    | where Category == 'SQLSecurityAuditEvents'
    | extend SQLSecurityAuditEvents_TimeGenerated = TimeGenerated
    | extend ClientIP = column_ifexists("client_ip_s", "Not Available")
    | extend Action = column_ifexists("action_name_s", "Not Available")
    | extend Application = column_ifexists("application_name_s", "Not Availabl
    e")
    | extend HostName = column_ifexists("host_name_s", "Not Available")
    )
    on $left.TI_ipEntity == $right.ClientIP
    // Filter out logs that occurred after the expiration of the corresponding ind
    icator
    | where SQLSecurityAuditEvents_TimeGenerated < ExpirationDateTime
    // Group the results by IndicatorId and ClientIP, and keep the log entry with
    the latest timestamp
    | summarize SQLSecurityAuditEvents_TimeGenerated = arg_max(SQLSecurityAuditEve
    nts_TimeGenerated, *) by IndicatorId, ClientIP
    // Select the desired output fields
    | project SQLSecurityAuditEvents_TimeGenerated, Description, ActivityGroupNames,
    IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
    TI_ipEntity, ResourceId, ClientIP, Action, Application, HostName, NetworkIP,
    NetworkDestinationIP, NetworkSourceIP, EmailSourceIpAddress, Type
    // Rename the timestamp field
    | extend timestamp = SQLSecurityAuditEvents_TimeGenerated
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI Map IP Entity to Azure SQL Security Audit Events' 
   enabled: true 
   description: >
    This query maps any IP indicators of compromise (IOCs) from threat intelligence
    (TI), by searching for matches in SQL Security Audit Events.
 
   alertRuleTemplateName: 'd0aa8969-1bbe-4da3-9e76-09e5f67c9d85' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
