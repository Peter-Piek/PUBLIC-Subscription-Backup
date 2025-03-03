# Office Policy Tampering

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/05505af2-dec1
  -44f4-90ae-e7316a5a2a3b
 
 name: '05505af2-dec1-44f4-90ae-e7316a5a2a3b' 
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
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'Name' 
         columnName: 'AccountName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'AccountUPNSuffix' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'ClientIP' 
   severity: 'Medium' 
   query: >
    let opList = OfficeActivity
    | summarize by Operation
    //| where Operation startswith "Remove-" or Operation startswith "Disable-"
    | where Operation has_any ("Remove", "Disable")
    | where Operation contains "AntiPhish" or Operation contains "SafeAttachment" or
    Operation contains "SafeLinks" or Operation contains "Dlp" or Operation contains
    "Audit"
    | summarize make_set(Operation, 500);
    OfficeActivity
    // Only admin or global-admin can disable/remove policy
    | where RecordType =~ "ExchangeAdmin"
    | where UserType in~ ("Admin","DcAdmin")
    // Pass in interesting Operation list
    | where Operation in~ (opList)
    | extend ClientIPOnly = case(
    ClientIP has ".", tostring(split(ClientIP,":")[0]),
    ClientIP has "[", tostring(trim_start(@'[[]',tostring(split(ClientIP,"]")[0]))),
    ClientIP
    )
    | extend Port = case(
    ClientIP has ".", (split(ClientIP,":")[1]),
    ClientIP has "[", tostring(split(ClientIP,"]:")[1]),
    ClientIP
    )
    | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated),
    OperationCount = count() by Operation, UserType, UserId, ClientIP = ClientIPOnly,
    Port, ResultStatus, Parameters
    | extend AccountName = tostring(split(UserId, "@")[0]), AccountUPNSuffix =
    tostring(split(UserId, "@")[1])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Persistence' 
    - 'DefenseEvasion' 
   techniques: 
    - 'T1098' 
    - 'T1562' 
   displayName: 'Office Policy Tampering' 
   enabled: true 
   description: >
    Identifies if any tampering is done to either auditlog, ATP Safelink, SafeAttachment,
    AntiPhish or Dlp policy.
    An adversary may use this technique to evade detection or avoid other policy based
    defenses.
    References: https://docs.microsoft.com/powershell/module/exchange/advanced-threa
    t-protection/remove-antiphishrule?view=exchange-ps.
 
   alertRuleTemplateName: 'fbd72eb8-087e-466b-bd54-1ca6ea08c6d3' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
