# Suspicious application consent similar to O365 Attack Toolkit

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/dab400ff-505d
  -49cd-acc6-15a8fd9b3793
 
 name: 'dab400ff-505d-49cd-acc6-15a8fd9b3793' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P14D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'High' 
   query: >
    let detectionTime = 1d;
    let joinLookback = 14d;
    let threshold = 5;
    let o365_attack_regex = "contacts.read|user.read|mail.read|notes.read.all|mailbo
    xsettings.readwrite|Files.ReadWrite.All|mail.send|files.read|files.read.all";
    let o365_attack = dynamic(["contacts.read", "user.read", "mail.read", "notes.read.all",
    "mailboxsettings.readwrite", "Files.ReadWrite.All", "mail.send", "files.read",
    "files.read.all"]);
    AuditLogs
    | where TimeGenerated > ago(detectionTime)
    | where LoggedByService =~ "Core Directory"
    | where Category =~ "ApplicationManagement"
    | where OperationName =~ "Consent to application"
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type =~ "ServicePrincipal"
    | extend AppDisplayName = tostring(TargetResource.displayName),
    AppClientId = tostring(TargetResource.id),
    props = TargetResource.modifiedProperties
    )
    | where AppClientId !in ((externaldata(knownAppClientId:string, knownAppDisplayN
    ame:string)[@"https://raw.githubusercontent.com/Azure/Azure-Sentinel/master/Samp
    le%20Data/Feeds/Microsoft.OAuth.KnownApplications.csv"] with (format="csv"))) //
    NOTE: a MATCH from this list will cause the alert to NOT fire - please modify for
    your environment!
    | mv-apply ConsentFull = props on
    (
    where ConsentFull.displayName =~ "ConsentAction.Permissions"
    )
    | parse ConsentFull with * "ConsentType: " GrantConsentType ", Scope: " GrantScope1
    ", CreatedDateTime" * "]" *
    | where GrantConsentType != "AllPrincipals" // NOTE: we are ignoring if OAuth
    application was granted to all users via an admin - but admin due diligence should
    be audited occasionally
    | where ConsentFull has_any (o365_attack)
    | extend GrantScopeCount = countof(tolower(GrantScope1), o365_attack_regex, 'reg
    ex')
    | where GrantScopeCount > threshold
    | extend GrantIpAddress = iff(isnotempty(InitiatedBy.user.ipAddress), tostring(I
    nitiatedBy.user.ipAddress), tostring(InitiatedBy.app.ipAddress))
    | extend GrantInitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName),
    tostring(InitiatedBy.user.userPrincipalName), tostring(InitiatedBy.app.displayNa
    me))
    | mv-apply AdditionalDetail = AdditionalDetails on
    (
    where AdditionalDetail.key =~ "User-Agent"
    | extend GrantUserAgent = AdditionalDetail.value
    )
    | project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy,
    AppDisplayName, GrantIpAddress, GrantUserAgent, AppClientId, OperationName,
    ConsentFull, CorrelationId
    | join kind = leftouter (AuditLogs
    | where TimeGenerated > ago(joinLookback)
    | where LoggedByService =~ "Core Directory"
    | where Category =~ "ApplicationManagement"
    | where OperationName =~ "Add service principal"
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type =~ "ServicePrincipal"
    | extend props = TargetResource.modifiedProperties,
    AppClientId = tostring(TargetResource.id)
    )
    | mv-apply Property = props on
    (
    where Property.displayName =~ "AppAddress" and Property.newValue has "
    AddressType"
    | extend AppReplyURLs = trim('"',tostring(Property.newValue))
    )
    | distinct AppClientId, tostring(AppReplyURLs)
    ) on AppClientId
    | join kind = innerunique (AuditLogs
    | where TimeGenerated > ago(joinLookback)
    | where LoggedByService =~ "Core Directory"
    | where Category =~ "ApplicationManagement"
    | where OperationName =~ "Add OAuth2PermissionGrant" or OperationName =~
    "Add delegated permission grant"
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type =~ "ServicePrincipal" and array_length(T
    argetResource.modifiedProperties) > 0 and isnotnull(TargetResource.displayName)
    | extend GrantAuthentication = tostring(TargetResource.displayName
    )
    )
    | extend GrantOperation = OperationName
    | project GrantAuthentication, GrantOperation, CorrelationId
    ) on CorrelationId
    | project TimeGenerated, GrantConsentType, GrantScope1, GrantInitiatedBy,
    AppDisplayName, AppReplyURLs, GrantIpAddress, GrantUserAgent, AppClientId,
    GrantAuthentication, OperationName, GrantOperation, CorrelationId, ConsentFull
    | extend timestamp = TimeGenerated, Name = tostring(split(GrantInitiatedBy,'@',0
    )[0]), UPNSuffix = tostring(split(GrantInitiatedBy,'@',1)[0])
 
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
         columnName: 'GrantIpAddress' 
    - 
      entityType: 'CloudApplication' 
      fieldMappings: 
       - 
         identifier: 'Name' 
         columnName: 'AppDisplayName' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'CredentialAccess' 
    - 'DefenseEvasion' 
   techniques: 
    - 'T1528' 
    - 'T1550' 
   subTechniques: null 
   displayName: 'Suspicious application consent similar to O365 Attack Toolkit' 
   enabled: true 
   description: >
    This will alert when a user consents to provide a previously-unknown Azure application
    with the same OAuth permissions used by the MDSec O365 Attack Toolkit (https://
    github.com/mdsecactivebreach/o365-attack-toolkit).
    The default permissions/scope for the MDSec O365 Attack toolkit change sometimes
    but often include contacts.read, user.read, mail.read, notes.read.all,
    mailboxsettings.readwrite, files.readwrite.all, mail.send, files.read, and file
    s.read.all.
    Consent to applications with these permissions should be rare, especially as the
    knownApplications list is expanded, especially as the knownApplications list is
    expanded. Public contributions to expand this filter are welcome!
    For further information on AuditLogs please see https://docs.microsoft.com/azure
    /active-directory/reports-monitoring/reference-audit-activities.
 
   alertRuleTemplateName: 'f948a32f-226c-4116-bddd-d95e91d97eb9' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
