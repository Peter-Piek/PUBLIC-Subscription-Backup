# Mail.Read Permissions Granted to Application

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/4d0ef66b-2041
  -42ec-bfff-85f856f0f7d0
 
 name: '4d0ef66b-2041-42ec-bfff-85f856f0f7d0' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    AuditLogs
    | where Category =~ "ApplicationManagement"
    | where ActivityDisplayName has_any ("Add delegated permission grant","Add app
    role assignment to service principal")
    | where Result =~ "success"
    | where tostring(InitiatedBy.user.userPrincipalName) has "@" or tostring(Initiat
    edBy.app.displayName) has "@"
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type =~ "ServicePrincipal" and array_length(TargetRes
    ource.modifiedProperties) > 0 and isnotnull(TargetResource.displayName)
    | extend props = TargetResource.modifiedProperties,
    Type = tostring(TargetResource.type),
    PermissionsAddedTo = tostring(TargetResource.displayName)
    )
    | mv-apply Property = props on
    (
    where Property.displayName =~ "DelegatedPermissionGrant.Scope"
    | extend DisplayName = tostring(Property.displayName), Permissions = trim(
    '"',tostring(Property.newValue))
    )
    | where Permissions has_any ("Mail.Read", "Mail.ReadWrite")
    | mv-apply AdditionalDetail = AdditionalDetails on
    (
    where AdditionalDetail.key =~ "User-Agent"
    | extend UserAgent = tostring(AdditionalDetail.value)
    )
    | extend InitiatingUser = tostring(InitiatedBy.user.userPrincipalName)
    | extend UserIPAddress = tostring(InitiatedBy.user.ipAddress)
    | project-away props, TargetResource*, AdditionalDetail*, Property, InitiatedBy
    | join kind=leftouter(
    AuditLogs
    | where ActivityDisplayName has "Consent to application"
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type =~ "ServicePrincipal"
    | extend AppName = tostring(TargetResource.displayName),
    AppId = tostring(TargetResource.id)
    )
    | project AppName, AppId, CorrelationId) on CorrelationId
    | project-reorder TimeGenerated, OperationName, InitiatingUser, UserIPAddress,
    UserAgent, PermissionsAddedTo, Permissions, AppName, AppId, CorrelationId
    | extend timestamp = TimeGenerated, Name = tostring(split(InitiatingUser,'@',0)[
    0]), UPNSuffix = tostring(split(InitiatingUser,'@',1)[0])
 
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
         columnName: 'Name' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'UPNSuffix' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'UserIPAddress' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Persistence' 
   techniques: 
    - 'T1098' 
   subTechniques: null 
   displayName: 'Mail.Read Permissions Granted to Application' 
   enabled: true 
   description: >
    This query look for applications that have been granted (Delegated or App/Role)
    permissions to Read Mail (Permissions field has Mail.Read) and subsequently has
    been consented to. This can help identify applications that have been abused to
    gain access to mailboxes.
 
   alertRuleTemplateName: '2560515c-07d1-434e-87fb-ebe3af267760' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
