# External guest invitation followed by Azure AD PowerShell signin

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/2dd8aa4e-07ac
  -4c5c-af86-75a3b4cc39a3
 
 name: '2dd8aa4e-07ac-4c5c-af86-75a3b4cc39a3' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
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
         identifier: 'Name' 
         columnName: 'InvitedUserName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'InvitedUserUPNSuffix' 
    - 
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'Name' 
         columnName: 'InitiatedByName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'InitiatedByUPNSuffix' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'IPAddress' 
   severity: 'Medium' 
   query: >
    let queryfrequency = 1h;
    let queryperiod = 1d;
    AuditLogs
    | where TimeGenerated > ago(queryperiod)
    | where OperationName in ("Invite external user", "Bulk invite users - started
    (bulk)", "Invite external user with reset invitation status")
    | extend InitiatedBy = iff(isnotempty(InitiatedBy.user.userPrincipalName), Initi
    atedBy.user.userPrincipalName, InitiatedBy.app.displayName)
    // Uncomment the following line to filter events where the inviting user was a
    guest user
    //| where InitiatedBy has_any ("live.com#", "#EXT#")
    | mv-apply TargetResource = TargetResources on
    (
    where TargetResource.type =~ "User"
    | extend InvitedUser = tostring(TargetResource.userPrincipalName)
    )
    | mv-expand UserToCompare = pack_array(InitiatedBy, InvitedUser) to typeof(strin
    g)
    | where UserToCompare has_any ("live.com#", "#EXT#")
    | extend
    parsedUser = replace_string(tolower(iff(UserToCompare startswith "live.com#",
    tostring(split(UserToCompare, "#")[1]), tostring(split(UserToCompare, "#EXT#")[0]))),
    "@", "_"),
    InvitationTime = TimeGenerated
    | join (
    (union isfuzzy=true SigninLogs, AADNonInteractiveUserSignInLogs)
    | where TimeGenerated > ago(queryfrequency)
    | where UserType != "Member"
    | where AppId has_any                       // This web may contain a list of
    these apps: https://msshells.net/
    ("1b730954-1685-4b74-9bfd-dac224a7b894",// Azure Active Directory PowerS
    hell
    "04b07795-8ddb-461a-bbee-02f9e1bf7b46",// Microsoft Azure CLI
    "1950a258-227b-4e31-a9cf-717495945fc2",// Microsoft Azure PowerShell
    "a0c73c16-a7e3-4564-9a95-2bdf47383716",// Microsoft Exchange Online Remote
    PowerShell
    "fb78d390-0c51-40cd-8e17-fdbfab77341b",// Microsoft Exchange REST API
    Based Powershell
    "d1ddf0e4-d672-4dae-b554-9d5bdfd93547",// Microsoft Intune PowerShell
    "9bc3ab49-b65d-410a-85ad-de819febfddc",// Microsoft SharePoint Online
    Management Shell
    "12128f48-ec9e-42f0-b203-ea49fb6af367",// MS Teams Powershell Cmdlets
    "23d8f6bd-1eb0-4cc2-a08c-7bf525c67bcd",// Power BI PowerShell
    "31359c7f-bd7e-475c-86db-fdb8c937548e",// PnP Management Shell
    "90f610bf-206d-4950-b61d-37fa6fd1b224",// Aadrm Admin Powershell
    "14d82eec-204b-4c2f-b7e8-296a70dab67e" // Microsoft Graph PowerShell
    )
    | summarize arg_min(TimeGenerated, *) by UserPrincipalName
    | extend
    parsedUser = replace_string(UserPrincipalName, "@", "_"),
    SigninTime = TimeGenerated
    )
    on parsedUser
    | project InvitationTime, InitiatedBy, OperationName, InvitedUser, SigninTime,
    SigninCategory = Category1, SigninUserPrincipalName = UserPrincipalName, IPAddress,
    AppDisplayName, ResourceDisplayName, UserAgent, InvitationAdditionalDetails =
    AdditionalDetails, InvitationTargetResources = TargetResources
    | extend InvitedUserName = tostring(split(InvitedUser,'@',0)[0]), InvitedUserUPNSuffix
    = tostring(split(InvitedUser,'@',1)[0]),
    InitiatedByName = tostring(split(InitiatedBy,'@',0)[0]), InitiatedByUPNSuffix
    = tostring(split(InitiatedBy,'@',1)[0])
 
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
   displayName: 'External guest invitation followed by Azure AD PowerShell signin' 
   enabled: true 
   description: >
    By default guests have capability to invite more external guest users, guests also
    can do suspicious Azure AD enumeration. This detection look at guests
    users, who have been invited or have invited recently, who also are logging via
    various PowerShell CLI.
    Ref : 'https://danielchronlund.com/2021/11/18/scary-azure-ad-tenant-enumeration-
    using-regular-b2b-guest-accounts/
 
   alertRuleTemplateName: 'acc4c247-aaf7-494b-b5da-17f18863878a' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
