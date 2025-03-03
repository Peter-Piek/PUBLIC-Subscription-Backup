# High-Risk Cross-Cloud User Impersonation

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/7279028c-94f9
  -4f6a-8384-43b2e74fb014
 
 name: '7279028c-94f9-4f6a-8384-43b2e74fb014' 
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
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'SourceIpAddress' 
   severity: 'Medium' 
   query: >
    // Retrieve Azure AD SigninLogs within the last day
    SigninLogs
    // Filter for specific AppDisplayNames, ResultType, and Risk Levels
    | where AppDisplayName in ("Azure Portal", "ADFS Trust", "Microsoft Azure PowerS
    hell")
    and RiskLevelAggregated == "high"
    and RiskLevelDuringSignIn == "high"
    // Summarize AppDisplayNames by relevant attributes
    | extend Result = iff(ResultType == 0, "Successful Signin", "Failed Signin")
    | summarize make_set(AppDisplayName)
    by
    IPAddress,
    signInTime=TimeGenerated,
    UserPrincipalName,
    RiskEventTypes,
    RiskEventTypes_V2
    // Inner join with AWS CloudTrail events
    | join kind=inner (
    AWSCloudTrail
    | where isempty(ErrorMessage)
    | where EventSource in ("iam.amazonaws.com", "identitystore.amazonaws.com",
    "workmail.amazonaws.com", "workdocs.amazonaws.com")
    // List of AWS event names
    | where EventName in~ ("CreateRole", "DeleteRole", "CreateUser", "CreateAccessKey",
    "DeleteAccessKey", "CreateGroup", "AddUserToGroup", "ChangePassword", "DeleteGroup",
    "DeleteUser", "RemoveUserFromGroup", "CreateVirtualMFADevice", "DeleteLoginProfile",
    "CreateOrganization", "SetDefaultMailDomain", "SetMailUserDetails", "CreateMailUser",
    "ResetPassword", "RegisterToWorkMail", "DisableMailUsers", "EnableMailUsers", "
    DeleteServiceSpecificCredential", "CreateServiceSpecificCredential",
    "UpdateAccountEmailAddress", "DeleteGroupPolicy", "UploadServerCertificate")
    // Summarize relevant attributes
    | summarize make_set(RequestParameters), make_set(ResponseElements)
    by
    SourceIpAddress,
    UserIdentityArn,
    UserIdentityType,
    EventName,
    EventTime=TimeGenerated,
    EventSource
    )
    on $left.IPAddress == $right.SourceIpAddress
    // Calculate time difference in hours between AWS event and Azure sign-in
    | extend timedef = datetime_diff("hour", EventTime, signInTime)
    // Filter for time differences within a certain range
    | where timedef between (0 .. 8)
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'PrivilegeEscalation' 
   techniques: 
    - 'T1134' 
    - 'T1078' 
   displayName: 'High-Risk Cross-Cloud User Impersonation' 
   enabled: true 
   description: >
    This detection focuses on identifying high-risk cross-cloud activities and sign-in
    anomalies that may indicate potential security threats. The query starts by
    analyzing Microsoft Entra ID Signin Logs to pinpoint instances where specific
    applications, risk levels, and result types align. It then correlates this
    information with relevant AWS CloudTrail events to identify activities across
    Azure and AWS environments.
 
   alertRuleTemplateName: 'f4a28082-2808-4783-9736-33c1ae117475' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
