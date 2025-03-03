# AV detections related to Zinc actors

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/219d6afb-7d2c
  -4baa-b1b4-a02e4337318b
 
 name: '219d6afb-7d2c-4baa-b1b4-a02e4337318b' 
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
         columnName: 'PublicIP' 
   severity: 'High' 
   query: >
    let Zinc_threats = dynamic(["Trojan:Win32/ZetaNile.A", "Trojan:Win32/EventHorizo
    n.A", "Trojan:Win32/FoggyBrass.A", "Trojan:Win32/FoggyBrass.B", "Trojan:Win32/Ph
    antomStar.A","Trojan:Win32/PhantomStar.C","TrojanDropper:Win32/PhantomStar.A"]);
    DeviceInfo
    | extend DeviceName = tolower(DeviceName)
    | join kind=inner ( SecurityAlert
    | where ProviderName == "MDATP"
    | extend ThreatName = tostring(parse_json(ExtendedProperties).ThreatName)
    | extend ThreatFamilyName = tostring(parse_json(ExtendedProperties).ThreatFamily
    Name)
    | where ThreatName in~ (Zinc_threats) or ThreatFamilyName in~ (Zinc_threats)
    | extend CompromisedEntity = tolower(CompromisedEntity)
    ) on $left.DeviceName == $right.CompromisedEntity
    | summarize by DisplayName, ThreatName, ThreatFamilyName, PublicIP, AlertSeverity,
    Description, tostring(LoggedOnUsers), DeviceId, TenantId , bin(TimeGenerated,
    1d), CompromisedEntity, tostring(LoggedOnUsers), ProductName, Entities
    | extend HostName = tostring(split(CompromisedEntity, '.', 0)[0]), DnsDomain = t
    ostring(strcat_array(array_slice(split(CompromisedEntity, '.'), 1, -1), '.'))
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Impact' 
   techniques: 
    - 'T1486' 
   displayName: 'AV detections related to Zinc actors' 
   enabled: true 
   description: >
    This query looks for Microsoft Defender AV detections related to  Zinc threat
    actor. In Microsoft Sentinel the SecurityAlerts table includes only the Device
    Name of the affected device,
    this query joins the DeviceInfo table to clearly connect other information such
    as Device group, ip, etc.
    This would allow the Microsoft Sentinel analyst to have more context related to
    the alert, if available.
    Reference: https://www.microsoft.com/security/blog/2022/09/29/zinc-weaponizing-
    open-source-software/
 
   alertRuleTemplateName: '3705158d-e008-49c9-92dd-e538e1549090' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
