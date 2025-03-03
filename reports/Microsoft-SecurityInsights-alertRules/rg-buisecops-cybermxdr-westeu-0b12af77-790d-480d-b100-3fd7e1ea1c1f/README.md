# TI map IP entity to Azure Key Vault logs

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/0b12af77-790d
  -480d-b100-3fd7e1ea1c1f
 
 name: '0b12af77-790d-480d-b100-3fd7e1ea1c1f' 
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
    - 
      entityType: 'AzureResource' 
      fieldMappings: 
       - 
         identifier: 'ResourceId' 
         columnName: 'ResourceId' 
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
    // Perform a join between IP indicators and AzureDiagnostics logs for Key Vault
    events
    IP_Indicators
    // Use innerunique to keep performance fast and result set low, as we only need
    one match to indicate potential malicious activity that needs investigation
    | join kind=innerunique (
    AzureDiagnostics
    | where ResourceType =~ "VAULTS"
    | where TimeGenerated >= ago(dt_lookBack)
    | extend KeyVaultEvents_TimeGenerated = TimeGenerated, ClientIP = CallerIP
    Address
    )
    on $left.TI_ipEntity == $right.ClientIP
    // Filter out logs that occurred after the expiration of the corresponding ind
    icator
    | where KeyVaultEvents_TimeGenerated < ExpirationDateTime
    // Group the results by IndicatorId and ClientIP, and keep the log entry with
    the latest timestamp
    | summarize KeyVaultEvents_TimeGenerated = arg_max(KeyVaultEvents_TimeGenerate
    d, *) by IndicatorId, ClientIP
    // Select the desired output fields
    | project KeyVaultEvents_TimeGenerated, Description, ActivityGroupNames,
    IndicatorId, ThreatType, Url, ExpirationDateTime, ConfidenceScore,
    TI_ipEntity, ClientIP, ResourceId, SubscriptionId, OperationName, ResultType,
    CorrelationId, id_s, clientInfo_s, httpStatusCode_d,
    identity_claim_appid_g, identity_claim_http_schemas_microsoft_com_identity_c
    laims_objectidentifier_g, Type
    // Rename the timestamp field
    | extend timestamp = KeyVaultEvents_TimeGenerated
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: null 
   displayName: 'TI map IP entity to Azure Key Vault logs' 
   enabled: true 
   description: 'Identifies a match in Azure Key Vault logs from any IP IOC from TI' 
   alertRuleTemplateName: '57c7e832-64eb-411f-8928-4133f01f4a25' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
