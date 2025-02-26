# AV detections related to Hive Ransomware

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/d6654868-1b9a
  -41e3-99cf-411dc680aaf0
 
 name: 'd6654868-1b9a-41e3-99cf-411dc680aaf0' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'High' 
   query: >
    let Hive_threats = dynamic(["Ransom:Win64/Hive", "Ransom:Win32/Hive"]);
    DeviceInfo
    | extend DeviceName = tolower(DeviceName)
    | join kind=inner ( SecurityAlert
    | where ProviderName == "MDATP"
    | extend ThreatName = tostring(parse_json(ExtendedProperties).ThreatName)
    | extend ThreatFamilyName = tostring(parse_json(ExtendedProperties).ThreatFamily
    Name)
    | where ThreatName in~ (Hive_threats) or ThreatFamilyName in~ (Hive_threats)
    | extend CompromisedEntity = tolower(CompromisedEntity)
    ) on $left.DeviceName == $right.CompromisedEntity
    | summarize by bin(TimeGenerated, 1d), DisplayName, ThreatName, ThreatFamilyName,
    PublicIP, AlertSeverity, Description, tostring(LoggedOnUsers), DeviceId, TenantId
    , CompromisedEntity, tostring(LoggedOnUsers), ProductName, Entities
    | extend HostName = tostring(split(CompromisedEntity, ".")[0]), DomainIndex = to
    int(indexof(CompromisedEntity, '.'))
    | extend HostNameDomain = iff(DomainIndex != -1, substring(CompromisedEntity,
    DomainIndex + 1), CompromisedEntity)
    | project-away DomainIndex
 
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
         identifier: 'DnsDomain' 
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
   displayName: 'AV detections related to Hive Ransomware' 
   enabled: true 
   description: >
    This query looks for Microsoft Defender AV detections related to Hive Ransomware
    . In Microsoft Sentinel the SecurityAlerts table includes only the Device Name
    of the affected device,
    this query joins the DeviceInfo table to clearly connect other information such
    as Device group, ip, logged on users etc. This would allow the Microsoft Sentinel
    analyst to have more context related to the alert, if available.
 
   alertRuleTemplateName: '4e5914a4-2ccd-429d-a845-fa597f0bd8c5' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
