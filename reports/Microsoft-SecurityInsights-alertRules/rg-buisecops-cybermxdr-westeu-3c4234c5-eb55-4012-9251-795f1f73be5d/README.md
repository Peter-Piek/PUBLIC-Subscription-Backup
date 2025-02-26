# Malicious Inbox Rule

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/3c4234c5-eb55
  -4012-9251-795f1f73be5d
 
 name: '3c4234c5-eb55-4012-9251-795f1f73be5d' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    let Keywords = dynamic(["helpdesk", " alert", " suspicious", "fake", "malicious",
    "phishing", "spam", "do not click", "do not open", "hijacked", "Fatal"]);
    OfficeActivity
    | where OfficeWorkload =~ "Exchange"
    | where Operation =~ "New-InboxRule" and (ResultStatus =~ "True" or ResultStatus
    =~ "Succeeded")
    | where Parameters has "Deleted Items" or Parameters has "Junk Email"  or Parameters
    has "DeleteMessage"
    | extend Events=todynamic(Parameters)
    | parse Events  with * "SubjectContainsWords" SubjectContainsWords '}'*
    | parse Events  with * "BodyContainsWords" BodyContainsWords '}'*
    | parse Events  with * "SubjectOrBodyContainsWords" SubjectOrBodyContainsWords '
    }'*
    | where SubjectContainsWords has_any (Keywords)
    or BodyContainsWords has_any (Keywords)
    or SubjectOrBodyContainsWords has_any (Keywords)
    | extend ClientIPAddress = case( ClientIP has ".", tostring(split(ClientIP,":")[
    0]), ClientIP has "[", tostring(trim_start(@'[[]',tostring(split(ClientIP,"]")[0
    ]))), ClientIP )
    | extend Keyword = iff(isnotempty(SubjectContainsWords), SubjectContainsWords, (
    iff(isnotempty(BodyContainsWords),BodyContainsWords,SubjectOrBodyContainsWords )
    ))
    | extend RuleDetail = case(OfficeObjectId contains '/' , tostring(split(OfficeOb
    jectId, '/')[-1]) , tostring(split(OfficeObjectId, '\\')[-1]))
    | summarize count(), StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated)
    by  Operation, UserId, ClientIPAddress, ResultStatus, Keyword, OriginatingServer,
    OfficeObjectId, RuleDetail
    | extend AccountName = tostring(split(UserId, "@")[0]), AccountUPNSuffix =
    tostring(split(UserId, "@")[1])
 
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
         columnName: 'AccountName' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'AccountUPNSuffix' 
    - 
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'FullName' 
         columnName: 'OriginatingServer' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'ClientIPAddress' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Persistence' 
    - 'DefenseEvasion' 
   techniques: 
    - 'T1098' 
    - 'T1078' 
   subTechniques: null 
   displayName: 'Malicious Inbox Rule' 
   enabled: true 
   description: >
    Often times after the initial compromise the attackers create inbox rules to delete
    emails that contain certain keywords.
    This is done so as to limit ability to warn compromised users that they've been
    compromised. Below is a sample query that tries to detect this.
    Reference: https://www.reddit.com/r/sysadmin/comments/7kyp0a/recent_phishing_att
    empts_my_experience_and_what/
 
   alertRuleTemplateName: '7b907bf7-77d4-41d0-a208-5643ff75bf9a' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
