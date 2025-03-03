# Anomolous Single Factor Signin

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/b8be774b-7f2e
  -4bae-a2f6-e9b432b00eab
 
 name: 'b8be774b-7f2e-4bae-a2f6-e9b432b00eab' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P7D' 
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
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'FullName' 
         columnName: 'UserPrincipalName' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'IPAddress' 
   severity: 'Low' 
   query: >
    let known_locations = (SigninLogs
    | where TimeGenerated between(ago(7d)..ago(1d))
    | where ResultType == 0
    | extend LocationDetail = strcat(Location, "-", LocationDetails.state)
    | summarize by LocationDetail);
    let known_asn = (SigninLogs
    | where TimeGenerated between(ago(7d)..ago(1d))
    | where ResultType == 0
    | summarize by AutonomousSystemNumber);
    SigninLogs
    | where TimeGenerated > ago(1d)
    | where ResultType == 0
    | where isempty(DeviceDetail.deviceId)
    | where AuthenticationRequirement == "singleFactorAuthentication"
    | extend LocationDetail = strcat(Location, "-", LocationDetails.state)
    | where AutonomousSystemNumber !in (known_asn) and LocationDetail !in (known_l
    ocations)
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'InitialAccess' 
   techniques: 
    - 'T1078' 
   displayName: 'Anomolous Single Factor Signin' 
   enabled: true 
   description: >
    Detects successful signins using single factor authentication where the device,
    location, and ASN are abnormal.
    Single factor authentications pose an opportunity to access compromised accounts,
    investigate these for anomalous occurrencess.
    Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-o
    perations-devices#non-compliant-device-sign-in
 
   alertRuleTemplateName: 'f7c3f5c8-71ea-49ff-b8b3-148f0e346291' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
