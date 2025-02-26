# Bulk Changes to Privileged Account Permissions

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/cde6bbb1-5225
  -45e4-92ee-28ffa95bea26
 
 name: 'cde6bbb1-5225-45e4-92ee-28ffa95bea26' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT2H' 
   queryPeriod: 'PT2H' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'High' 
   query: >
    let AdminRecords = AuditLogs
    | where Category =~ "RoleManagement"
    | where ActivityDisplayName has_any ("Add eligible member to role", "Add member
    to role")
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type =~ "User"
    | extend Target = tostring(TargetResource.userPrincipalName),
    props = TargetResource.modifiedProperties
    )
    | mv-apply Property = props on
    (
    where Property.displayName =~ "Role.DisplayName"
    | extend RoleName = trim('"',tostring(Property.newValue))
    )
    | where RoleName contains "Admin";
    AdminRecords
    | summarize dcount(Target) by bin(TimeGenerated, 1h)
    | where dcount_Target > 9
    | join kind=rightsemi  (
    AdminRecords
    | extend TimeWindow = bin(TimeGenerated, 1h)
    ) on $left.TimeGenerated == $right.TimeWindow
    | extend InitiatedByUser = iff(isnotempty(InitiatedBy.user.userPrincipalName), t
    ostring(InitiatedBy.user.userPrincipalName), "")
    | extend TargetName = tostring(split(Target,'@',0)[0]), TargetUPNSuffix = tostri
    ng(split(Target,'@',1)[0]),
    InitiatedByUserName = tostring(split(InitiatedByUser,'@',0)[0]),
    InitiatedByUserUPNSuffix = tostring(split(InitiatedByUser,'@',1)[0])
 
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
         columnName: 'TargetName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'TargetUPNSuffix' 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'Name' 
         columnName: 'InitiatedByUserName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'InitiatedByUserUPNSuffix' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'PrivilegeEscalation' 
   techniques: 
    - 'T1078' 
   subTechniques: null 
   displayName: 'Bulk Changes to Privileged Account Permissions' 
   enabled: true 
   description: >
    Identifies when changes to multiple users permissions are changed at once. Investigate
    immediately if not a planned change. This setting could enable an attacker access
    to Azure subscriptions in your environment.
    Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-op
    erations-privileged-identity-management
 
   alertRuleTemplateName: '218f60de-c269-457a-b882-9966632b9dc6' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
