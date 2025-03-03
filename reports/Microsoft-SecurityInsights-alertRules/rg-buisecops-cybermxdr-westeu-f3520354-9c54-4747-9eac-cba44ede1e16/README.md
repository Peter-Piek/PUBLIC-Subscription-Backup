# New country signIn with correct password

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/f3520354-9c54
  -4747-9eac-cba44ede1e16
 
 name: 'f3520354-9c54-4747-9eac-cba44ede1e16' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P7D' 
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
         columnName: 'UserPrincipalName' 
       - 
         identifier: 'Name' 
         columnName: 'Name' 
       - 
         identifier: 'NTDomain' 
         columnName: 'Domain' 
   severity: 'Medium' 
   query: >
    // Creating a list of successful sign-in by users in the last 7 days.
    let KnownUserCountry = (
    SigninLogs
    | where TimeGenerated between (ago(7d) .. ago(1d) )
    | where ResultType == 0
    | summarize KnownCountry = make_set(Location,1048576) by UserPrincipalName
    );
    // Identify sign-ins that are no successful but have the auth details indicating
    a correct password.
    SigninLogs
    | where TimeGenerated >= ago(1d)
    | where ResultType != 0
    | extend ParseAuth = parse_json(AuthenticationDetails)
    | extend AuthMethod = tostring(ParseAuth.[0].authenticationMethod),
    PasswordResult = tostring(ParseAuth.[0].authenticationStepResultDetail),
    AuthSucceeded = tostring(ParseAuth.[0].succeeded)
    | where PasswordResult == "Correct Password" or AuthSucceeded == "true"
    | where AuthMethod == "Password"
    | extend failureReason = tostring(Status.failureReason)
    | summarize NewCountry = make_set(Location,1048576), LastObservedTime =
    max(TimeGenerated), AppName = make_set(AppDisplayName,1048576) by UserPrincipalName,
    PasswordResult, AuthSucceeded, failureReason
    // Combining both tables by user
    | join kind=inner KnownUserCountry on UserPrincipalName
    // Compare both arrays and identify if the country has been observed in the past
    .
    | extend CountryDiff = set_difference(NewCountry,KnownCountry)
    | extend CountryDiffCount = array_length(CountryDiff)
    // Count the new column to only alert if there is a difference between both arra
    ys
    | where CountryDiffCount != 0
    | extend NewCountryEvent = CountryDiff
    // Getting UserName and Domain
    | extend Name = split(UserPrincipalName,"@",0),
    Domain = split(UserPrincipalName,"@",1)
    | mv-expand Name,Domain
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'InitialAccess' 
    - 'CredentialAccess' 
   techniques: 
    - 'T1078' 
    - 'T1110' 
   displayName: 'New country signIn with correct password' 
   enabled: true 
   description: >
    Identifies an interrupted sign-in session from a country the user has not sign-in
    before in the last 7 days, where the password was correct. Although the session
    is interrupted by other controls such as multi factor authentication or conditional
    access policies, the user credentials should be reset due to logs indicating a
    correct password was observed during sign-in.
 
   alertRuleTemplateName: '7808c05a-3afd-4d13-998a-a59e2297693f' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
