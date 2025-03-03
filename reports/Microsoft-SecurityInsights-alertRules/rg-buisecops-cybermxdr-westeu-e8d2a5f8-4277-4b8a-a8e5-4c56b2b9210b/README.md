# Service Principal Assigned App Role With Sensitive Access

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/e8d2a5f8-4277
  -4b8a-a8e5-4c56b2b9210b
 
 name: 'e8d2a5f8-4277-4b8a-a8e5-4c56b2b9210b' 
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
         identifier: 'FullName' 
         columnName: 'InitiatingUserPrincipalName' 
       - 
         identifier: 'Name' 
         columnName: 'InitiatingAccountName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'InitiatingAccountUPNSuffix' 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'AadUserId' 
         columnName: 'InitiatingAadUserId' 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'AadUserId' 
         columnName: 'InitiatingAppServicePrincipalId' 
       - 
         identifier: 'ObjectGuid' 
         columnName: 'ServicePrincipalObjectID' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'InitiatingIPAddress' 
   severity: 'Medium' 
   query: >
    // Add other permissions to this list as needed
    let permissions = dynamic([".All", "ReadWrite", "Mail.", "offline_access",
    "Files.Read", "Notes.Read", "ChannelMessage.Read", "Chat.Read", "TeamsActivity.
    Read",
    "Group.Read", "EWS.AccessAsUser.All", "EAS.AccessAsUser.All"]);
    let auditList =
    AuditLogs
    | where OperationName =~ "Add app role assignment to service principal"
    | mv-expand TargetResources[0].modifiedProperties
    | extend TargetResources_0_modifiedProperties = column_ifexists("TargetResources
    _0_modifiedProperties", '')
    | where isnotempty(TargetResources_0_modifiedProperties)
    ;
    let detailsList = auditList
    | where TargetResources_0_modifiedProperties.displayName =~ "AppRole.Value" or T
    argetResources_0_modifiedProperties.displayName =~ "DelegatedPermissionGrant.Sco
    pe"
    | extend Permissions = split((parse_json(tostring(TargetResources_0_modifiedProp
    erties.newValue))), " ")
    | where Permissions has_any (permissions)
    | summarize AddedPermissions=make_set(Permissions,200) by CorrelationId
    | join kind=inner auditList on CorrelationId
    | extend InitiatingAppName = tostring(InitiatedBy.app.displayName)
    | extend InitiatingAppServicePrincipalId = tostring(InitiatedBy.app.servicePrinc
    ipalId)
    | extend InitiatingUserPrincipalName = tostring(InitiatedBy.user.userPrincipalNa
    me)
    | extend InitiatingAadUserId = tostring(InitiatedBy.user.id)
    | extend InitiatingIPAddress = tostring(InitiatedBy.user.ipAddress)
    | extend InitiatedBy = tostring(iff(isnotempty(InitiatingUserPrincipalName),Init
    iatingUserPrincipalName, InitiatingAppName))
    | extend displayName = tostring(TargetResources_0_modifiedProperties.displayName
    ), newValue = tostring(parse_json(tostring(TargetResources_0_modifiedProperties.
    newValue)))
    | where displayName == "ServicePrincipal.ObjectID" or displayName == "ServicePri
    ncipal.DisplayName"
    | extend displayName = case(displayName == "ServicePrincipal.ObjectID",
    "ServicePrincipalObjectID", displayName == "ServicePrincipal.DisplayName", "Ser
    vicePrincipalDisplayName", displayName)
    | project TimeGenerated, CorrelationId, Id, AddedPermissions = tostring(AddedPermissions),
    InitiatingAadUserId, InitiatingAppName, InitiatingAppServicePrincipalId,
    InitiatingIPAddress, InitiatingUserPrincipalName, InitiatedBy, displayName, new
    Value
    ;
    detailsList | project Id, displayName, newValue
    | evaluate pivot(displayName, make_set(newValue))
    | join kind=inner detailsList on Id
    | extend ServicePrincipalObjectID = todynamic(column_ifexists("ServicePrincipalO
    bjectID", "")), ServicePrincipalDisplayName = todynamic(column_ifexists("Service
    PrincipalDisplayName", ""))
    | mv-expand ServicePrincipalObjectID, ServicePrincipalDisplayName
    | project-away Id1, displayName, newValue
    | extend ServicePrincipalObjectID = tostring(ServicePrincipalObjectID),
    ServicePrincipalDisplayName = tostring(ServicePrincipalDisplayName)
    | summarize FirstSeen = min(TimeGenerated), LastSeen = max(TimeGenerated), EventIds
    = make_set(Id,200) by CorrelationId, AddedPermissions, InitiatingAadUserId,
    InitiatingAppName, InitiatingAppServicePrincipalId, InitiatingIPAddress,
    InitiatingUserPrincipalName, InitiatedBy, ServicePrincipalDisplayName, ServiceP
    rincipalObjectID
    | extend InitiatingAccountName = tostring(split(InitiatingUserPrincipalName,
    "@")[0]), InitiatingAccountUPNSuffix = tostring(split(InitiatingUserPrincipalNa
    me, "@")[1])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'PrivilegeEscalation' 
   techniques: 
    - 'T1078' 
   displayName: 'Service Principal Assigned App Role With Sensitive Access' 
   enabled: true 
   description: >
    Detects a Service Principal being assigned an app role that has sensitive access
    such as Mail.Read.
    A threat actor who compromises a Service Principal may assign it an app role to
    allow it to access sensitive data, or to perform other actions.
    Ensure that any assignment to a Service Principal is valid and appropriate.
    Ref: https://docs.microsoft.com/azure/active-directory/fundamentals/security-o
    perations-applications#application-granted-highly-privileged-permissions
 
   alertRuleTemplateName: 'dd78a122-d377-415a-afe9-f22e08d2112c' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
