# AV detections related to Dev-0530 actors

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/92747a64-4eac
  -4f04-8700-3a7dbb4a56c8
 
 name: '92747a64-4eac-4f04-8700-3a7dbb4a56c8' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
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
         identifier: 'FullName' 
         columnName: 'CompromisedEntity' 
       - 
         identifier: 'HostName' 
         columnName: 'HostName' 
       - 
         identifier: 'DnsDomain' 
         columnName: 'HostNameDomain' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'PublicIP' 
   severity: 'High' 
   query: >
    let Dev0530_threats = dynamic(["Trojan:Win32/SiennaPurple.A", "Ransom:Win32/SiennaBlue.A",
    "Ransom:Win32/SiennaBlue.B"]);
    SecurityAlert
    | where ProviderName == "MDATP"
    | extend ThreatName = tostring(parse_json(ExtendedProperties).ThreatName)
    | extend ThreatFamilyName = tostring(parse_json(ExtendedProperties).ThreatFamily
    Name)
    | where ThreatName in~ (Dev0530_threats) or ThreatFamilyName in~ (Dev0530_threat
    s)
    | extend CompromisedEntity = tolower(CompromisedEntity)
    | join kind=inner (DeviceInfo
    | extend DeviceName = tolower(DeviceName)
    ) on $left.CompromisedEntity == $right.DeviceName
    | summarize by bin(TimeGenerated, 1d), DisplayName, ThreatName, ThreatFamilyName,
    PublicIP, AlertSeverity, Description, tostring(LoggedOnUsers), DeviceId, TenantId,
    CompromisedEntity, tostring(LoggedOnUsers), ProductName, Entities
    | extend HostName = tostring(split(CompromisedEntity, ".")[0]), DomainIndex = to
    int(indexof(CompromisedEntity, '.'))
    | extend HostNameDomain = iff(DomainIndex != -1, substring(CompromisedEntity,
    DomainIndex + 1), CompromisedEntity)
    | project-away DomainIndex
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: 
    - 'T1486' 
   displayName: 'AV detections related to Dev-0530 actors' 
   enabled: true 
   description: >
    This query looks for Microsoft Defender AV detections related to  Dev-0530 actors.
    In Microsoft Sentinel the SecurityAlerts table includes only the Device Name of
    the affected device,
    this query joins the DeviceInfo table to clearly connect other information such
    as Device group, ip, logged on users etc. This would allow the Microsoft Sentinel
    analyst to have more context related to the alert, if available.
 
   alertRuleTemplateName: '5f171045-88ab-4634-baae-a7b6509f483b' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
