# Mail redirect via ExO transport rule

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/f7130400-5f6c
  -4bc3-bd30-2526662c4910
 
 name: 'f7130400-5f6c-4bc3-bd30-2526662c4910' 
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
         columnName: 'IPAddress' 
   severity: 'Medium' 
   query: >
    OfficeActivity
    | where OfficeWorkload == "Exchange"
    | where Operation in~ ("New-TransportRule", "Set-TransportRule")
    | mv-apply DynamicParameters = todynamic(Parameters) on (summarize ParsedParameters
    = make_bag(pack(tostring(DynamicParameters.Name), DynamicParameters.Value)))
    | extend RuleName = case(
    Operation =~ "Set-TransportRule", OfficeObjectId,
    Operation =~ "New-TransportRule", ParsedParameters.Name,
    "Unknown")
    | mv-expand ExpandedParameters = todynamic(Parameters)
    | where ExpandedParameters.Name in~ ("BlindCopyTo", "RedirectMessageTo") and isn
    otempty(ExpandedParameters.Value)
    | extend RedirectTo = ExpandedParameters.Value
    | extend ClientIPValues = extract_all(@'\[?(::ffff:)?(?P<IPAddress>(\d+\.\d+\.\d
    +\.\d+)|[^\]]+)\]?([-:](?P<Port>\d+))?', dynamic(["IPAddress", "Port"]), ClientI
    P)[0]
    | project TimeGenerated, RedirectTo, IPAddress = tostring(ClientIPValues[0]), Port
    = tostring(ClientIPValues[1]), UserId, Operation, RuleName, Parameters
    | extend AccountName = tostring(split(UserId, "@")[0]), AccountUPNSuffix =
    tostring(split(UserId, "@")[1])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Collection' 
    - 'Exfiltration' 
   techniques: 
    - 'T1114' 
    - 'T1020' 
   displayName: 'Mail redirect via ExO transport rule' 
   enabled: true 
   description: >
    Identifies when Exchange Online transport rule configured to forward emails.
    This could be an adversary mailbox configured to collect mail from multiple user
    accounts.
 
   alertRuleTemplateName: '500415fb-bba7-4227-a08a-9857fb61b6a7' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
