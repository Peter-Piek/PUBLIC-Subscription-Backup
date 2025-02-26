# Privileged Role Assigned Outside PIM

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/79ec6b6a-07ce
  -4144-9978-8c7360313e12
 
 name: '79ec6b6a-07ce-4144-9978-8c7360313e12' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Low' 
   query: >
    AuditLogs
    | where Category =~ "RoleManagement"
    | where OperationName has "Add member to role outside of PIM"
    or (LoggedByService =~ "Core Directory" and OperationName =~ "Add member
    to role" and Identity != "MS-PIM")
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type =~ "User"
    | extend TargetUserPrincipalName = tostring(TargetResource.userPrincipalNa
    me)
    )
    | extend InitiatingAppName = tostring(InitiatedBy.app.displayName)
    | extend InitiatingAppServicePrincipalId = tostring(InitiatedBy.app.servicePrinc
    ipalId)
    | extend InitiatingUserPrincipalName = tostring(InitiatedBy.user.userPrincipalNa
    me)
    | extend InitiatingAadUserId = tostring(InitiatedBy.user.id)
    | extend InitiatingIpAddress = tostring(iff(isnotempty(InitiatedBy.user.ipAddres
    s), InitiatedBy.user.ipAddress, InitiatedBy.app.ipAddress))
    | extend TargetName = tostring(split(TargetUserPrincipalName,'@',0)[0]), TargetUPNSuffix
    = tostring(split(TargetUserPrincipalName,'@',1)[0])
    | extend InitiatedByName = tostring(split(InitiatingUserPrincipalName,'@',0)[0])
    , InitiatedByUPNSuffix = tostring(split(InitiatingUserPrincipalName,'@',1)[0])

 
   suppressionDuration: 'PT1H' 
   suppressionEnabled: null 
   incidentConfiguration: 
     createIncident: true 
     groupingConfiguration: 
       enabled: null 
       reopenClosedIncident: null 
       lookbackDuration: 'PT5H' 
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
         columnName: 'InitiatedByName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'InitiatedByUPNSuffix' 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'FullName' 
         columnName: 'TargetUserPrincipalName' 
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
         identifier: 'AadUserId' 
         columnName: 'InitiatingAadUserId' 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'AadUserId' 
         columnName: 'InitiatingAppServicePrincipalId' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'InitiatingIpAddress' 
   templateVersion: '1.0.5' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'PrivilegeEscalation' 
   techniques: 
    - 'T1078' 
   subTechniques: null 
   displayName: 'Privileged Role Assigned Outside PIM' 
   enabled: true 
   description: >
    Identifies a privileged role being assigned to a user outside of PIM
    Ref : https://docs.microsoft.com/azure/active-directory/fundamentals/security-op
    erations-privileged-accounts#things-to-monitor-1
 
   alertRuleTemplateName: '269435e3-1db8-4423-9dfc-9bf59997da1c' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
