# AV detections related to Europium actors

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/58448235-4432
  -4d78-bd42-31cec72b6742
 
 name: '58448235-4432-4d78-bd42-31cec72b6742' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'High' 
   query: >
    let Europium_threats = dynamic(["TrojanDropper:ASP/WebShell!MSR", "Trojan:Win32/BatRunGoXml",
    "DoS:Win64/WprJooblash", "Ransom:Win32/Eagle!MSR", "Trojan:Win32/Debitom.A"]);
    DeviceInfo
    | extend DeviceName = tolower(DeviceName)
    | join kind=inner ( SecurityAlert
    | where ProviderName == "MDATP"
    | extend ThreatName = tostring(parse_json(ExtendedProperties).ThreatName)
    | extend ThreatFamilyName = tostring(parse_json(ExtendedProperties).ThreatFamily
    Name)
    | where ThreatName in~ (Europium_threats) or ThreatFamilyName in~ (Europium_thre
    ats)
    | extend CompromisedEntity = tolower(CompromisedEntity)
    ) on $left.DeviceName == $right.CompromisedEntity
    | summarize by DisplayName, ThreatName, ThreatFamilyName, PublicIP, AlertSeverity,
    Description, tostring(LoggedOnUsers), DeviceId, TenantId, bin(TimeGenerated, 1d),
    CompromisedEntity, tostring(LoggedOnUsers), ProductName, Entities
    | extend HostName = tostring(split(CompromisedEntity, ".")[0]), DomainIndex = to
    int(indexof(CompromisedEntity, '.'))
    | extend HostNameDomain = iff(CompromisedEntity != -1, substring(CompromisedEntity,
    DomainIndex + 1), CompromisedEntity)
 
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
         identifier: 'FullName' 
         columnName: 'CompromisedEntity' 
       - 
         identifier: 'HostName' 
         columnName: 'HostName' 
       - 
         identifier: 'NTDomain' 
         columnName: 'HostNameDomain' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'PublicIP' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Impact' 
   techniques: 
    - 'T1486' 
   subTechniques: null 
   displayName: 'AV detections related to Europium actors' 
   enabled: true 
   description: >
    This query looks for Microsoft Defender AV detections related to  Europium actor.
    In Microsoft Sentinel the SecurityAlerts table includes only the Device Name of
    the affected device,
    this query joins the DeviceInfo table to clearly connect other information such
    as Device group, ip, etc. This would allow the Microsoft Sentinel analyst to have
    more context related to the alert, if available.
    Reference: https://www.microsoft.com/security/blog/2022/09/08/microsoft-investi
    gates-iranian-attacks-against-the-albanian-government
 
   alertRuleTemplateName: '186970ee-5001-41c1-8c73-3178f75ce96a' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
