# User added to Azure Active Directory Privileged Groups

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/baf53e80-0e23
  -4bf1-8ae0-bc5ca34c9a81
 
 name: 'baf53e80-0e23-4bf1-8ae0-bc5ca34c9a81' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'PT1H' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let OperationList = dynamic(["Add member to role","Add member to role in PIM
    requested (permanent)"]);
    let PrivilegedGroups = dynamic(["UserAccountAdmins","PrivilegedRoleAdmins","Tena
    ntAdmins"]);
    AuditLogs
    //| where LoggedByService =~ "Core Directory"
    | where Category =~ "RoleManagement"
    | where OperationName in~ (OperationList)
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type =~ "User"
    | extend TargetUserPrincipalName = tostring(TargetResource.userPrincipalNa
    me),
    modProps = TargetResource.modifiedProperties
    )
    | mv-apply Property = modProps on
    (
    where Property.displayName =~ "Role.WellKnownObjectName"
    | extend DisplayName = trim('"',tostring(Property.displayName)),
    GroupName = trim('"',tostring(Property.newValue))
    )
    | extend AppId = InitiatedBy.app.appId,
    InitiatedByDisplayName = case(isnotempty(InitiatedBy.app.displayName),
    InitiatedBy.app.displayName, isnotempty(InitiatedBy.user.displayName),
    InitiatedBy.user.displayName, "not available"),
    ServicePrincipalId = tostring(InitiatedBy.app.servicePrincipalId),
    ServicePrincipalName = tostring(InitiatedBy.app.servicePrincipalName),
    UserId = InitiatedBy.user.id,
    UserIPAddress = InitiatedBy.user.ipAddress,
    UserRoles = InitiatedBy.user.roles,
    UserPrincipalName = tostring(InitiatedBy.user.userPrincipalName)
    | where GroupName in~ (PrivilegedGroups)
    // If you don't want to alert for operations from PIM, remove below filtering for
    MS-PIM.
    //| where InitiatedByDisplayName != "MS-PIM"
    | project TimeGenerated, AADOperationType, Category, OperationName, AADTenantId,
    AppId, InitiatedByDisplayName, ServicePrincipalId, ServicePrincipalName, DisplayName,
    GroupName, UserId, UserIPAddress, UserRoles, UserPrincipalName, TargetUserPrinc
    ipalName
    | extend AccountCustomEntity = case(isnotempty(ServicePrincipalName), ServicePrincipalName,
    
    isnotempty(UserPrincipalName), UserPrincipalName,
    
    "")
    | extend AccountName = tostring(split(AccountCustomEntity,'@',0)[0]), AccountUPNSuffix
    = tostring(split(AccountCustomEntity,'@',1)[0])
    | extend TargetName = tostring(split(TargetUserPrincipalName,'@',0)[0]), TargetUPNSuffix
    = tostring(split(TargetUserPrincipalName,'@',1)[0])
 
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
    - 'Persistence' 
    - 'PrivilegeEscalation' 
   techniques: 
    - 'T1098' 
    - 'T1078' 
   subTechniques: null 
   displayName: 'User added to Azure Active Directory Privileged Groups' 
   enabled: true 
   description: >
    This will alert when a user is added to any of the Privileged Groups.
    For further information on AuditLogs please see https://docs.microsoft.com/azure
    /active-directory/reports-monitoring/reference-audit-activities.
    For Administrator role permissions in Azure Active Directory please see https://
    docs.microsoft.com/azure/active-directory/users-groups-roles/directory-assign-ad
    min-roles
 
   alertRuleTemplateName: '4d94d4a9-dc96-410a-8dea-4d4d4584188b' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
