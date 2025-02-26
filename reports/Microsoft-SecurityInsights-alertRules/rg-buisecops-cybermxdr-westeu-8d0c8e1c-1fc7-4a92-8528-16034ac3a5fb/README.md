# AV detections related to SpringShell Vulnerability

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/8d0c8e1c-1fc7
  -4a92-8528-16034ac3a5fb
 
 name: '8d0c8e1c-1fc7-4a92-8528-16034ac3a5fb' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'High' 
   query: >
    let SpringShell_threats = dynamic(["Trojan:Python/SpringShellExpl",
    "Exploit:Python/SpringShell", "Backdoor:PHP/Remoteshell.V", "SpringShell"]);
    DeviceInfo
    | extend DeviceName = tolower(DeviceName)
    | join kind=inner ( SecurityAlert
    | where ProviderName =~ "MDATP"
    | extend ThreatName = tostring(parse_json(ExtendedProperties).ThreatName)
    | extend ThreatFamilyName = tostring(parse_json(ExtendedProperties).ThreatFamily
    Name)
    | where ThreatName in~ (SpringShell_threats) or ThreatFamilyName in~ (SpringShel
    l_threats)
    | extend CompromisedEntity = tolower(CompromisedEntity)
    ) on $left.DeviceName == $right.CompromisedEntity
    | summarize by DisplayName, ThreatName, ThreatFamilyName, PublicIP, AlertSeverity,
    Description, tostring(LoggedOnUsers), DeviceId, TenantId , bin(TimeGenerated,
    1d), CompromisedEntity, tostring(LoggedOnUsers), ProductName, Entities
    | extend HostName = iff(CompromisedEntity has '.', substring(CompromisedEntity,0
    ,indexof(CompromisedEntity,'.')),CompromisedEntity)
    | extend DnsDomain = iff(CompromisedEntity has '.', substring(CompromisedEntity,
    indexof(CompromisedEntity,'.')+1),"")
 
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
         columnName: 'PublicIP' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'InitialAccess' 
   techniques: 
    - 'T1190' 
   subTechniques: null 
   displayName: 'AV detections related to SpringShell Vulnerability' 
   enabled: true 
   description: >
    This query looks for Microsoft Defender AV detections related to the SpringShell
    vulnerability. In Microsoft Sentinel, the SecurityAlerts table includes only the
    Device Name of the affected device.
    This query joins the DeviceInfo table to clearly connect other information such
    as device group, IP, logged-on users, etc. This would allow the Microsoft Sentinel
    analyst to have more context related to the alert, if available.
    Reference: https://www.microsoft.com/security/blog/2022/04/04/springshell-rce-
    vulnerability-guidance-for-protecting-against-and-detecting-cve-2022-22965/
 
   alertRuleTemplateName: '3bd33158-3f0b-47e3-a50f-7c20a1b88038' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
