# New User Assigned to Privileged Role

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/188d5040-c04f
  -4a36-9aa9-b5f25e63d264
 
 name: '188d5040-c04f-4a36-9aa9-b5f25e63d264' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'PT1H' 
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
         columnName: 'TargetName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'TargetUPNSuffix' 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'Name' 
         columnName: 'InitiatorName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'InitiatorUPNSuffix' 
   severity: 'High' 
   query: >
    // Define the start and end times based on input values
    let starttime = now()-1d;
    let endtime = now();
    // Set a lookback period of 14 days
    let lookback = starttime - 1d;
    // Define a reusable function to query audit logs
    let awsFunc = (start:datetime, end:datetime) {
    AuditLogs
    | where TimeGenerated between (start..end)
    | where Category =~ "RoleManagement"
    | where AADOperationType in ("Assign", "AssignEligibleRole")
    | where ActivityDisplayName has_any ("Add eligible member to role", "Add member
    to role")
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type in~ ("User", "ServicePrincipal")
    | extend Target = iff(TargetResource.type =~ "ServicePrincipal", tostring(
    TargetResource.displayName), tostring(TargetResource.userPrincipalName)),
    props = TargetResource.modifiedProperties
    )
    | mv-apply Property = props on
    (
    where Property.displayName =~ "Role.DisplayName"
    | extend RoleName = trim('"', tostring(Property.newValue))
    )
    | where RoleName contains "Admin" and Result == "success"
    };
    // Query for audit events in the current day
    let EventInfo_CurrentDay = awsFunc(starttime, endtime);
    // Query for audit events in the historical period (lookback)
    let EventInfo_historical = awsFunc(lookback, starttime);
    // Find unseen events by performing a left anti-join
    let EventInfo_Unseen = (EventInfo_CurrentDay
    | join kind=leftanti(EventInfo_historical) on Target, RoleName, OperationName
    );
    // Extend and clean up the results
    EventInfo_Unseen
    | extend InitiatingApp = tostring(InitiatedBy.app.displayName)
    | extend Initiator = iif(isnotempty(InitiatingApp), InitiatingApp, tostring(Init
    iatedBy.user.userPrincipalName))
    // You can uncomment the lines below to filter out PIM activations
    // | where Initiator != "MS-PIM"
    // | summarize StartTime=min(TimeGenerated), EndTime=min(TimeGenerated) by
    OperationName, RoleName, Target, Initiator, Result
    // Project specific columns and split them for further analysis
    | project TimeGenerated, OperationName, RoleName, Target, Initiator, Result
    | extend TargetName = tostring(split(Target, '@', 0)[0]),
    TargetUPNSuffix = tostring(split(Target, '@', 1)[0]),
    InitiatorName = tostring(split(Initiator, '@', 0)[0]),
    InitiatorUPNSuffix = tostring(split(Initiator, '@', 1)[0])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'Persistence' 
   techniques: 
    - 'T1078' 
   displayName: 'New User Assigned to Privileged Role' 
   enabled: true 
   description: >
    Identifies when a privileged role is assigned to a new user. Any account eligible
    for a role is now being given privileged access. If the assignment is unexpected
    or into a role that isn't the responsibility of the account holder, investigate
    .
 
   alertRuleTemplateName: '050b9b3d-53d0-4364-a3da-1b678b8211ec' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
