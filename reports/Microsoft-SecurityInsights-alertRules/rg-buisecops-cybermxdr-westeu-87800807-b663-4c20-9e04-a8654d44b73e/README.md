# AV detections related to Tarrask malware

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/87800807-b663
  -4c20-9e04-a8654d44b73e
 
 name: '87800807-b663-4c20-9e04-a8654d44b73e' 
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
    let Tarrask_threats = dynamic(["HackTool:Win64/Tarrask!MS", "HackTool:Win64/Ligolo!MSR",
    "Behavior:Win32/ScheduledTaskHide.A", "Tarrask"]);
    DeviceInfo
    | extend DeviceName = tolower(DeviceName)
    | join kind=rightouter ( SecurityAlert
    | where ProviderName =~ "MDATP"
    | extend ThreatName = tostring(parse_json(ExtendedProperties).ThreatName)
    | extend ThreatFamilyName = tostring(parse_json(ExtendedProperties).ThreatFamily
    Name)
    | where ThreatName in~ (Tarrask_threats) or ThreatFamilyName in~ (Tarrask_threat
    s)
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
   tactics: 
    - 'Persistence' 
   techniques: 
    - 'T1053' 
   displayName: 'AV detections related to Tarrask malware' 
   enabled: true 
   description: >
    This query looks for Microsoft Defender AV detections related to Tarrask malware.
    In Microsoft Sentinel, the SecurityAlerts table
    includes only the Device Name of the affected device, this query joins the
    DeviceInfo table to clearly connect other information such as Device group, ip,
    logged-on users etc.
    This would allow the Microsoft Sentinel analyst to have more context related to
    the alert, if available.
    Reference: https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-u
    ses-scheduled-tasks-for-defense-evasion/
 
   alertRuleTemplateName: '1785d372-b9fe-4283-96a6-3a1d83cabfd1' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
