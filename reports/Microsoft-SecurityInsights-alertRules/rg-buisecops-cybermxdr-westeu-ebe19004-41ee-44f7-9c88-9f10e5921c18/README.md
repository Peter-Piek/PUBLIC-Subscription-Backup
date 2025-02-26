# Admin promotion after Role Management Application Permission Grant

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/ebe19004-41ee
  -44f7-9c88-9f10e5921c18
 
 name: 'ebe19004-41ee-44f7-9c88-9f10e5921c18' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'PT2H' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'High' 
   query: >
    let query_frequency = 1h;
    let query_period = 2h;
    AuditLogs
    | where TimeGenerated > ago(query_period)
    | where Category =~ "ApplicationManagement" and LoggedByService =~ "Core Directo
    ry"
    | where OperationName =~ "Add app role assignment to service principal"
    | mv-expand TargetResource = TargetResources
    | mv-expand modifiedProperty = TargetResource["modifiedProperties"]
    | where tostring(modifiedProperty["displayName"]) == "AppRole.Value"
    | extend PermissionGrant = tostring(modifiedProperty["newValue"])
    | where PermissionGrant has "RoleManagement.ReadWrite.Directory"
    | mv-apply modifiedProperty = TargetResource["modifiedProperties"] on (
    summarize modifiedProperties = make_bag(
    bag_pack(tostring(modifiedProperty["displayName"]),
    bag_pack("oldValue", trim(@'[\"\s]+', tostring(modifiedProperty["old
    Value"])),
    "newValue", trim(@'[\"\s]+', tostring(modifiedProperty["newValue
    "])))), 100)
    )
    | project
    PermissionGrant_TimeGenerated = TimeGenerated,
    PermissionGrant_OperationName = OperationName,
    PermissionGrant_Result = Result,
    PermissionGrant,
    AppDisplayName = tostring(modifiedProperties["ServicePrincipal.DisplayName"]
    ["newValue"]),
    AppServicePrincipalId = tostring(modifiedProperties["ServicePrincipal.Object
    ID"]["newValue"]),
    PermissionGrant_InitiatedBy = InitiatedBy,
    PermissionGrant_TargetResources = TargetResources,
    PermissionGrant_AdditionalDetails = AdditionalDetails,
    PermissionGrant_CorrelationId = CorrelationId
    | join kind=inner (
    AuditLogs
    | where TimeGenerated > ago(query_frequency)
    | where Category =~ "RoleManagement" and LoggedByService =~ "Core Directory"
    and AADOperationType =~ "Assign"
    | where isnotempty(InitiatedBy["app"])
    | mv-expand TargetResource = TargetResources
    | mv-expand modifiedProperty = TargetResource["modifiedProperties"]
    | where tostring(modifiedProperty["displayName"]) in ("Role.DisplayName", "R
    oleDefinition.DisplayName")
    | extend RoleAssignment = tostring(modifiedProperty["newValue"])
    | where RoleAssignment contains "Admin"
    | project
    RoleAssignment_TimeGenerated = TimeGenerated,
    RoleAssignment_OperationName = OperationName,
    RoleAssignment_Result = Result,
    RoleAssignment,
    TargetType = tostring(TargetResources[0]["type"]),
    Target = iff(isnotempty(TargetResources[0]["displayName"]), tostring(Tar
    getResources[0]["displayName"]), tolower(TargetResources[0]["userPrincipalName"]
    )),
    TargetId = tostring(TargetResources[0]["id"]),
    RoleAssignment_InitiatedBy = InitiatedBy,
    RoleAssignment_TargetResources = TargetResources,
    RoleAssignment_AdditionalDetails = AdditionalDetails,
    RoleAssignment_CorrelationId = CorrelationId,
    AppServicePrincipalId = tostring(InitiatedBy["app"]["servicePrincipalId"
    ])
    ) on AppServicePrincipalId
    | where PermissionGrant_TimeGenerated < RoleAssignment_TimeGenerated
    | extend
    TargetName = tostring(split(Target, "@")[0]),
    TargetUPNSuffix = tostring(split(Target, "@")[1])
    | project PermissionGrant_TimeGenerated, PermissionGrant_OperationName,
    PermissionGrant_Result, PermissionGrant, AppDisplayName, AppServicePrincipalId,
    PermissionGrant_InitiatedBy, PermissionGrant_TargetResources, PermissionGrant_A
    dditionalDetails, PermissionGrant_CorrelationId, RoleAssignment_TimeGenerated,
    RoleAssignment_OperationName, RoleAssignment_Result, RoleAssignment, TargetType,
    Target, TargetName, TargetUPNSuffix, TargetId, RoleAssignment_InitiatedBy, Role
    Assignment_TargetResources, RoleAssignment_AdditionalDetails, RoleAssignment_Cor
    relationId
 
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
         columnName: 'AppDisplayName' 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'Name' 
         columnName: 'TargetName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'TargetUPNSuffix' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'PrivilegeEscalation' 
    - 'Persistence' 
   techniques: 
    - 'T1098' 
    - 'T1078' 
   subTechniques: null 
   displayName: 'Admin promotion after Role Management Application Permission Grant' 
   enabled: true 
   description: >
    This rule looks for a service principal being granted the Microsoft Graph RoleMa
    nagement.ReadWrite.Directory (application) permission before being used to add an
    Azure AD object or user account to an Admin directory role (i.e. Global Adminis
    trators).
    This is a known attack path that is usually abused when a service principal already
    has the AppRoleAssignment.ReadWrite.All permission granted. This permission allows
    an app to manage permission grants for application permissions to any API.
    A service principal can promote itself or other service principals to admin roles
    (i.e. Global Administrators). This would be considered a privilege escalation t
    echnique.
    Ref : https://docs.microsoft.com/graph/permissions-reference#role-management-per
    missions, https://docs.microsoft.com/graph/api/directoryrole-post-members?view=g
    raph-rest-1.0&tabs=http
 
   alertRuleTemplateName: 'f80d951a-eddc-4171-b9d0-d616bb83efdc' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
