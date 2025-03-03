# Daily Data Limit Reached [Custom]

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/5bcb540b-1135
  -4c48-a51e-b3d88318923d
 
 name: '5bcb540b-1135-4c48-a51e-b3d88318923d' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'PT2H' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
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
   severity: 'High' 
   query: >
    Operation
    | where OperationCategory == 'Data Collection Status'
    | where Detail contains "stopped" or Detail contains "OverQuota"

 
   suppressionDuration: 'PT12H' 
   suppressionEnabled: true 
   tactics: null 
   techniques: null 
   displayName: 'Daily Data Limit Reached [Custom]' 
   enabled: true 
   description: >
    When data collection stops, the OperationStatus is Warning. When data collection
    starts, the OperationStatus is Succeeded. The following table describes reasons
    that data collection stops and a suggested action to resume data collection:

    Daily limit of legacy Free pricing tier reached
    Wait until the following day for collection to automatically restart, or change
    to a paid pricing tier.

    Daily cap of your workspace was reached:
    Wait for collection to automatically restart, or increase the daily data volume
    limit described in manage the maximum daily data volume. The daily cap reset time
    is shows on the Data volume management page.

    Azure subscription is in a suspended state due to:
    Free trial ended
    Azure pass expired
    Monthly spending limit reached (for example on an MSDN or Visual Studio subscrip
    tion)
    Convert to a paid subscription
    Remove limit, or wait until limit resets.
 
   alertRuleTemplateName: null 
   lastModifiedUtc: 2024-10-30T13:02:29
```
