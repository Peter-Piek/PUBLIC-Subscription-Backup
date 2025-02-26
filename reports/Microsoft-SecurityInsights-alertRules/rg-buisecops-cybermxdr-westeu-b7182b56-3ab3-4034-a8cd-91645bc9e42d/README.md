# Multiple users email forwarded to same destination

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/b7182b56-3ab3
  -4034-a8cd-91645bc9e42d
 
 name: 'b7182b56-3ab3-4034-a8cd-91645bc9e42d' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P7D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let queryfrequency = 1d;
    let queryperiod = 7d;
    OfficeActivity
    | where TimeGenerated > ago(queryperiod)
    | where OfficeWorkload =~ "Exchange"
    //| where Operation in ("Set-Mailbox", "New-InboxRule", "Set-InboxRule")
    | where Parameters has_any ("ForwardTo", "RedirectTo", "ForwardingSmtpAddress")
    | mv-apply DynamicParameters = todynamic(Parameters) on (summarize ParsedParameters
    = make_bag(bag_pack(tostring(DynamicParameters.Name), DynamicParameters.Value))
    )
    | evaluate bag_unpack(ParsedParameters, columnsConflict='replace_source')
    | extend DestinationMailAddress = tolower(case(
    isnotempty(column_ifexists("ForwardTo", "")), column_ifexists("ForwardTo", "
    "),
    isnotempty(column_ifexists("RedirectTo", "")), column_ifexists("RedirectTo",
    ""),
    isnotempty(column_ifexists("ForwardingSmtpAddress", "")), trim_start(@"smtp:",
    column_ifexists("ForwardingSmtpAddress", "")),
    ""))
    | where isnotempty(DestinationMailAddress)
    | mv-expand split(DestinationMailAddress, ";")
    | extend ClientIPValues = extract_all(@'\[?(::ffff:)?(?P<IPAddress>(\d+\.\d+\.\d
    +\.\d+)|[^\]]+)\]?([-:](?P<Port>\d+))?', dynamic(["IPAddress", "Port"]), ClientI
    P)[0]
    | extend ClientIP = tostring(ClientIPValues[0]), Port = tostring(ClientIPValues[
    1])
    | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated),
    DistinctUserCount = dcount(UserId), UserId = make_set(UserId, 250), Ports =
    make_set(Port, 250), EventCount = count() by tostring(DestinationMailAddress),
    ClientIP
    | where DistinctUserCount > 1 and EndTime > ago(queryfrequency)
    | mv-expand UserId to typeof(string)
    | extend AccountName = tostring(split(UserId, "@")[0]), AccountUPNSuffix =
    tostring(split(UserId, "@")[1])
 
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
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Collection' 
    - 'Exfiltration' 
   techniques: 
    - 'T1114' 
    - 'T1020' 
   subTechniques: null 
   displayName: 'Multiple users email forwarded to same destination' 
   enabled: true 
   description: >
    Identifies when multiple (more than one) users mailboxes are configured to forward
    to the same destination.
    This could be an attacker-controlled destination mailbox configured to collect
    mail from multiple compromised user accounts.
 
   alertRuleTemplateName: '871ba14c-88ef-48aa-ad38-810f26760ca3' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
