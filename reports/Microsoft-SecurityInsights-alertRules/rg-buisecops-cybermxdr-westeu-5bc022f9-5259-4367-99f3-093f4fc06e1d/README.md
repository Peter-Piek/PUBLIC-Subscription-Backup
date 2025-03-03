# Cross-tenant Access Settings Organization Inbound Direct Settings Changed

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/5bc022f9-5259
  -4367-99f3-093f4fc06e1d
 
 name: '5bc022f9-5259-4367-99f3-093f4fc06e1d' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P2D' 
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
         columnName: 'InitiatedByIPAdress' 
   severity: 'Medium' 
   query: >
    //In User & Groups and in Applications, the following "AccessType" values in columns
    PremodifiedInboundSettings and ModifiedInboundSettings are interpreted accordin
    gly:
    // When Access Type in premodified inbound settings value was 1 that means that
    the initial access was allowed. When Access Type in premodified inbound settings
    value was 2 that means that the initial access was blocked.
    // When Access Type in modified inbound settings value is 1 that means that now
    access is allowed. When Access Type in modified inbound settings value is 2 that
    means that now access is blocked.
    AuditLogs
    | where OperationName has "Update a partner cross-tenant access setting"
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type =~ "Policy"
    | extend Properties = TargetResource.modifiedProperties
    )
    | mv-apply Property = Properties on
    (
    where Property.displayName =~ "b2bDirectConnectInbound"
    | extend PremodifiedInboundSettings = trim('"',tostring(Property.oldValue)
    ),
    ModifiedInboundSettings = trim(@'"',tostring(Property.newValue))
    )
    | extend InitiatedByActionUserInformation = iff(isnotempty(InitiatedBy.user.user
    PrincipalName), InitiatedBy.user.userPrincipalName, InitiatedBy.app.displayName)
    | extend InitiatedByIPAdress = InitiatedBy.user.ipAddress
    | where PremodifiedInboundSettings != ModifiedInboundSettings
    | extend Name = tostring(split(InitiatedByActionUserInformation,'@',0)[0]), UPNSuffix
    = tostring(split(InitiatedByActionUserInformation,'@',1)[0])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'InitialAccess' 
    - 'Persistence' 
    - 'Discovery' 
   techniques: 
    - 'T1078' 
    - 'T1136' 
    - 'T1087' 
   displayName: 'Cross-tenant Access Settings Organization Inbound Direct Settings Changed' 
   enabled: true 
   description: >
    Organizations are added in the Cross-tenant Access Settings to control communication
    inbound or outbound for users and applications. This detection notifies when
    Organization Inbound Direct Settings are changed for "Users & Groups" and for "
    Applications".
 
   alertRuleTemplateName: '276d5190-38de-4eb2-9933-b3b72f4a5737' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
