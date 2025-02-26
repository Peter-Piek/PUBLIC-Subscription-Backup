# High risk Office operation conducted by IP Address that recently attempted to log into a disabled account

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/a252d2e6-bef1
  -43df-bd88-e8bd2850dac4
 
 name: 'a252d2e6-bef1-43df-bd88-e8bd2850dac4' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P8D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let threshold = 100;
    let timeRange = ago(7d);
    let timeBuffer = 1;
    SigninLogs
    | where TimeGenerated > timeRange
    | where ResultType == "50057"
    | summarize StartTime = min(TimeGenerated), EndTime = max(TimeGenerated),
    disabledAccountLoginAttempts = count(),
    disabledAccountsTargeted = dcount(UserPrincipalName), applicationsTargeted =
    dcount(AppDisplayName), disabledAccountSet = make_set(UserPrincipalName),
    applicationSet = make_set(AppDisplayName) by IPAddress, AppId
    | order by disabledAccountLoginAttempts desc
    | join kind=inner (
    // IPs are considered suspicious - and any related successful sign-ins are d
    etected
    SigninLogs
    | where TimeGenerated > timeRange
    | where ResultType == 0
    | summarize successSigninStart = min(TimeGenerated), successSigninEnd =
    max(TimeGenerated), successfulAccountSigninCount = dcount(UserPrincipalName),
    successfulAccountSigninSet = make_set(UserPrincipalName, 15) by IPAddress
    // Assume IPs associated with sign-ins from 100+ distinct user accounts are
    safe
    | where successfulAccountSigninCount < threshold
    ) on IPAddress
    // IPs where attempts to authenticate as disabled user accounts originated, and
    had a non-zero success rate for some other account
    | where successfulAccountSigninCount != 0
    // Successful Account Signins occur within the same lookback period as the failed
    
    | extend SuccessBeforeFailure = iff(successSigninStart >= StartTime and successSigninEnd
    <= EndTime, true, false)
    | project StartTime, EndTime, IPAddress, disabledAccountLoginAttempts,
    disabledAccountsTargeted, disabledAccountSet, applicationSet,
    successfulAccountSigninCount, successfulAccountSigninSet, successSigninStart,
    successSigninEnd, AppId
    | order by disabledAccountLoginAttempts
    // Break up the string of Succesfully signed into accounts into individual event
    s
    | mvexpand successfulAccountSigninSet
    | extend JoinedOnIp = IPAddress
    | join kind = inner (
    OfficeActivity
    | where TimeGenerated > timeRange
    | where Operation in~ ( "Add-MailboxPermission", "Add-MailboxFolderPermissio
    n", "Set-Mailbox", "New-ManagementRoleAssignment", "New-InboxRule", "Set-InboxRule",
    "Set-TransportRule") and not(UserId has_any ('NT AUTHORITY\\SYSTEM (Microsoft.E
    xchange.ServiceHost)', 'NT AUTHORITY\\SYSTEM (w3wp)', 'devilfish-applicationacco
    unt'))
    // Remove port from the end of the IP and/or square brackets around IP, if
    they exist
    | extend JoinedOnIp = case(
    ClientIP matches regex @'\[((25[0-5]2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25
    [0-5]2[0-4][0-9]|[01]?[0-9][0-9]?)\]-\d{1,5}', tostring(extract('\\[([0-9]+\\.[0
    -9]+\\.[0-9]+)\\]-[0-9]+', 1, ClientIP)),
    ClientIP matches regex @'\[((25[0-5]2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25
    [0-5]2[0-4][0-9]|[01]?[0-9][0-9]?)\]', tostring(extract('\\[([0-9]+\\.[0-9]+\\.[
    0-9]+)\\]', 1, ClientIP)),
    ClientIP matches regex @'(((25[0-5]2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[
    0-5]2[0-4][0-9]|[01]?[0-9][0-9]?))-\d{1,5}', tostring(extract('([0-9]+\\.[0-9]+\
    \.[0-9]+)-[0-9]+', 1, ClientIP)),
    ClientIP matches regex @'((25[0-5]2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0
    -5]2[0-4][0-9]|[01]?[0-9][0-9]?)', ClientIP,
    ClientIP matches regex @'\[((?:[0-9a-fA-F]{1,4}::?){1,8}[0-9a-fA-F]{1,4}|\
    d{1,3}(?:\.\d{1,3}){3})\]-\d{1,5}', tostring(extract('\\[((?:[0-9a-fA-F]{1,4}::?
    ){1,8}[0-9a-fA-F]{1,4}|\\d{1,3}(?:\\.\\d{1,3}){3})\\]-[0-9]+', 1, ClientIP)),
    ClientIP matches regex @'\[((?:[0-9a-fA-F]{1,4}::?){1,8}[0-9a-fA-F]{1,4}|\
    d{1,3}(?:\.\d{1,3}){3})\]', tostring(extract('\\[((?:[0-9a-fA-F]{1,4}::?){1,8}[0
    -9a-fA-F]{1,4}|\\d{1,3}(?:\\.\\d{1,3}){3})\\]', 1, ClientIP)),
    ClientIP matches regex @'((?:[0-9a-fA-F]{1,4}::?){1,8}[0-9a-fA-F]{1,4}|\d{
    1,3}(?:\.\d{1,3}){3})-\d{1,5}', tostring(extract('((?:[0-9a-fA-F]{1,4}::?){1,8}[
    0-9a-fA-F]{1,4}|\\d{1,3}(?:\\.\\d{1,3}){3})-[0-9]+', 1, ClientIP)),
    ClientIP matches regex @'((?:[0-9a-fA-F]{1,4}::?){1,8}[0-9a-fA-F]{1,4}|\d{
    1,3}(?:\.\d{1,3}){3})', ClientIP,
    "")
    | where isnotempty(JoinedOnIp)
    | extend OfficeTimeStamp = ElevationTime, UserPrincipalName = UserId
    ) on JoinedOnIp
    // Rare and risky operations only happen within a certain time range of the
    successful sign-in
    | where OfficeTimeStamp >= successSigninStart and datetime_diff('day', OfficeTimeStamp,
    successSigninEnd) <= timeBuffer
    | extend AccountName = tostring(split(UserPrincipalName, "@")[0]), AccountUPNSuffix
    = tostring(split(UserPrincipalName, "@")[1])
 
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
         identifier: 'FullName' 
         columnName: 'UserPrincipalName' 
       - 
         identifier: 'Name' 
         columnName: 'AccountName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'AccountUPNSuffix' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'JoinedOnIp' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'IPAddress' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'ClientIP' 
    - 
      entityType: 'CloudApplication' 
      fieldMappings: 
       - 
         identifier: 'AppId' 
         columnName: 'ApplicationId' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'InitialAccess' 
    - 'Persistence' 
    - 'Collection' 
   techniques: 
    - 'T1078' 
    - 'T1098' 
    - 'T1114' 
   subTechniques: null 
   displayName: >
    High risk Office operation conducted by IP Address that recently attempted to log
    into a disabled account
 
   enabled: true 
   description: >
    It is possible that a disabled user account is compromised and another account on
    the same IP is used to perform operations that are not typical for that user.
    The query filters the SigninLogs for entries where ResultType is indicates a
    disabled account and the TimeGenerated is within a defined time range.
    It then summarizes these entries by IPAddress and AppId, calculating various
    statistics such as number of login attempts, distinct UPNs, App IDs etc and joins
    these results with another set of results from SigninLogs, filtering for entries
    with less than normal number of successful sign-ins.
    It then filters out entries where there were no successful sign-ins or where
    successful sign-ins did not occur within the same lookback period as the failed
    sign-ins, later projecting relevant fields by the count of login attempts, and
    expands the set of successful sign-ins into individual events.
    Finally, it joins these results with entries from OfficeActivity where certain
    operations deemed rare and high risk have been performed, ensuring their occurrance
    within a certain time range of the successful sign-ins.
 
   alertRuleTemplateName: '9adbd1c3-a4be-44ef-ac2f-503fd25692ee' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
