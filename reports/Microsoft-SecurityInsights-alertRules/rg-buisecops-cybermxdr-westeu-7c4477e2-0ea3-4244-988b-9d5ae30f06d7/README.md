# Rare subscription-level operations in Azure

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/7c4477e2-0ea3
  -4244-988b-9d5ae30f06d7
 
 name: '7c4477e2-0ea3-4244-988b-9d5ae30f06d7' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P14D' 
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
         columnName: 'Caller' 
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
         columnName: 'CallerIpAddress' 
   severity: 'Low' 
   query: >
    let starttime = 14d;
    let endtime = 1d;
    // The number of operations above which an IP address is considered an unusual
    source of role assignment operations
    let alertOperationThreshold = 5;
    // Add or remove operation names below as per your requirements. For operations
    lists, please refer to https://learn.microsoft.com/en-us/Azure/role-based-acces
    s-control/resource-provider-operations#all
    let SensitiveOperationList =  dynamic(["microsoft.compute/snapshots/write", "mic
    rosoft.network/networksecuritygroups/write", "microsoft.storage/storageaccounts/
    listkeys/action"]);
    let SensitiveActivity = AzureActivity
    | where OperationNameValue in~ (SensitiveOperationList) or OperationNameValue
    hassuffix "listkeys/action"
    | where ActivityStatusValue =~ "Success";
    SensitiveActivity
    | where TimeGenerated between (ago(starttime) .. ago(endtime))
    | summarize count() by CallerIpAddress, Caller, OperationNameValue, bin(TimeGene
    rated,1d)
    | where count_ >= alertOperationThreshold
    // Returns all the records from the right side that don't have matches from the
    left
    | join kind = rightanti (
    SensitiveActivity
    | where TimeGenerated >= ago(endtime)
    | summarize StartTimeUtc = min(TimeGenerated), EndTimeUtc = max(TimeGenerated),
    ActivityTimeStamp = make_list(TimeGenerated), ActivityStatusValue = make_list(A
    ctivityStatusValue), CorrelationIds = make_list(CorrelationId), ResourceGroups =
    make_list(ResourceGroup), ResourceIds = make_list(_ResourceId), ActivityCountBy
    CallerIPAddress = count()
    by CallerIpAddress, Caller, OperationNameValue
    | where ActivityCountByCallerIPAddress >= alertOperationThreshold
    ) on CallerIpAddress, Caller, OperationNameValue
    | extend Name = tostring(split(Caller,'@',0)[0]), UPNSuffix = tostring(split(Cal
    ler,'@',1)[0])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'CredentialAccess' 
    - 'Persistence' 
   techniques: 
    - 'T1003' 
    - 'T1098' 
   displayName: 'Rare subscription-level operations in Azure' 
   enabled: true 
   description: >
    This query looks for a few sensitive subscription-level events based on Azure
    Activity Logs. For example, this monitors for the operation name 'Create or Update
    Snapshot', which is used for creating backups but could be misused by attackers
    to dump hashes or extract sensitive information from the disk.
 
   alertRuleTemplateName: '23de46ea-c425-4a77-b456-511ae4855d69' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
