# Credential added after admin consented to Application

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/eeeb9044-9efb
  -4d03-b7b0-363a6ea5508e
 
 name: 'eeeb9044-9efb-4d03-b7b0-363a6ea5508e' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P2D' 
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
         columnName: 'Name' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'UPNSuffix' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'Consent_InitiatingIpAddress' 
   severity: 'Medium' 
   query: >
    let auditLookbackStart = 2d;
    let auditLookbackEnd = 1d;
    AuditLogs
    | where TimeGenerated >= ago(auditLookbackStart)
    | where OperationName =~ "Consent to application"
    | where Result =~ "success"
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type =~ "ServicePrincipal"
    | extend targetResourceName = tostring(TargetResource.displayName),
    targetResourceID = tostring(TargetResource.id),
    targetResourceType = tostring(TargetResource.type),
    targetModifiedProp = TargetResource.modifiedProperties
    )
    | mv-apply Property = targetModifiedProp on
    (
    where Property.displayName =~ "ConsentContext.IsAdminConsent"
    | extend isAdminConsent = trim(@'"',tostring(Property.newValue))
    )
    | mv-apply Property = targetModifiedProp on
    (
    where Property.displayName =~ "ConsentAction.Permissions"
    | extend Consent_Permissions = trim(@'"',tostring(Property.newValue))
    )
    | mv-apply Property = targetModifiedProp on
    (
    where Property.displayName =~ "TargetId.ServicePrincipalNames"
    | extend Consent_ServicePrincipalNames = tostring(extract_all(@"([0-9a-fA-
    F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",trim(@'"',t
    ostring(Property.newValue)))[0])
    )
    | extend Consent_InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPrinc
    ipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app
    .displayName))
    | extend Consent_InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress
    ), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
    | join (
    AuditLogs
    | where TimeGenerated  >= ago(auditLookbackEnd)
    | where OperationName =~ "Add service principal credentials"
    | where Result =~ "success"
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type =~ "ServicePrincipal"
    | extend targetResourceName = tostring(TargetResource.displayName),
    targetResourceID = tostring(TargetResource.id),
    targetModifiedProp = TargetResource.modifiedProperties
    )
    | mv-apply Property = targetModifiedProp on
    (
    where Property.displayName =~ "KeyDescription"
    | extend Credential_KeyDescription = trim(@'"',tostring(Property.newValue)
    )
    )
    | mv-apply Property = targetModifiedProp on
    (
    where Property.displayName =~ "Included Updated Properties"
    | extend UpdatedProperties = trim(@'"',tostring(Property.newValue))
    )
    | mv-apply Property = targetModifiedProp on
    (
    where Property.displayName =~ "TargetId.ServicePrincipalNames"
    | extend Credential_ServicePrincipalNames = tostring(extract_all(@"([0-9a-
    fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})",trim(@'"
    ',tostring(Property.newValue)))[0])
    )
    | extend Credential_InitiatingUserOrApp = iff(isnotempty(InitiatedBy.user.userPr
    incipalName),tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.
    app.displayName))
    | extend Credential_InitiatingIpAddress = iff(isnotempty(InitiatedBy.user.ipAddr
    ess), tostring(InitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
    ) on targetResourceName, targetResourceID
    | extend TimeConsent = TimeGenerated, TimeCred = TimeGenerated1
    | where TimeConsent < TimeCred
    | project TimeConsent, TimeCred, Consent_InitiatingUserOrApp, Credential_Initiat
    ingUserOrApp, targetResourceName, targetResourceType, isAdminConsent, Consent_Se
    rvicePrincipalNames, Credential_ServicePrincipalNames, Consent_Permissions,
    Credential_KeyDescription, Consent_InitiatingIpAddress, Credential_InitiatingIp
    Address
    | extend timestamp = TimeConsent, Name = tostring(split(Credential_InitiatingUse
    rOrApp,'@',0)[0]), UPNSuffix = tostring(split(Credential_InitiatingUserOrApp,'@'
    ,1)[0])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'CredentialAccess' 
   techniques: null 
   displayName: 'Credential added after admin consented to Application' 
   enabled: true 
   description: >
    This query will identify instances where Service Principal credentials were added
    to an application by one user after the application was granted admin consent
    rights by another user.
    If a threat actor obtains access to an account with sufficient privileges and
    adds the alternate authentication material triggering this event, the threat actor
    can now authenticate as the Application or Service Principal using this credent
    ial.
    Additional information on OAuth Credential Grants can be found in RFC 6749 Section
    4.4 or https://docs.microsoft.com/azure/active-directory/develop/v2-oauth2-clie
    nt-creds-grant-flow.
    For further information on AuditLogs please see https://docs.microsoft.com/azur
    e/active-directory/reports-monitoring/reference-audit-activities
 
   alertRuleTemplateName: '707494a5-8e44-486b-90f8-155d1797a8eb' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
