# Scheduled Task Hide

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/013cb0fb-629c
  -4dc0-ac3d-358c67186211
 
 name: '013cb0fb-629c-4dc0-ac3d-358c67186211' 
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
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'FullName' 
         columnName: 'AccountCustomEntity' 
    - 
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'FullName' 
         columnName: 'HostCustomEntity' 
   severity: 'High' 
   query: >
    SecurityEvent
    | where EventID == 4657
    | extend EventData = parse_xml(EventData).EventData.Data
    | mv-expand bagexpansion=array EventData
    | evaluate bag_unpack(EventData)
    | extend Key = tostring(column_ifexists('@Name', "")), Value = column_ifexists('#text',
    "")
    | evaluate pivot(Key, any(Value), TimeGenerated, TargetAccount, Computer,
    EventSourceName, Channel, Task, Level, EventID, Activity, TargetLogonId,
    SourceComputerId, EventOriginId, Type, _ResourceId, TenantId, SourceSystem,
    ManagementGroupName, IpAddress, Account)
    | extend ObjectName = column_ifexists('ObjectName', ""), OperationType = column_
    ifexists('OperationType', ""), ObjectValueName = column_ifexists('ObjectValueNam
    e', "")
    | where ObjectName has 'Schedule\\TaskCache\\Tree' and ObjectValueName == "SD" and
    OperationType == "%%1906"  // %%1906 - Registry value deleted
    | extend timestamp = TimeGenerated, HostCustomEntity = Computer, AccountCustomEntity
    = Account
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'DefenseEvasion' 
   techniques: 
    - 'T1562' 
   displayName: 'Scheduled Task Hide' 
   enabled: true 
   description: >
    This query detects attempts by malware to hide the scheduled task by deleting the
    SD (Security Descriptor) value. Removal of SD value results in the scheduled task
    disappearing from schtasks /query and Task Scheduler.
    The query requires auditing to be turned on for HKEY_LOCAL_MACHINE\SOFTWARE\Mic
    rosoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree registry hive as well as
    audit policy for registry auditing to be turned on.
    Reference: https://www.microsoft.com/security/blog/2022/04/12/tarrask-malware-u
    ses-scheduled-tasks-for-defense-evasion/
    Reference: https://4sysops.com/archives/audit-changes-in-the-windows-registry/
 
   alertRuleTemplateName: '6dd2629c-534b-4275-8201-d7968b4fa77e' 
   lastModifiedUtc: 2024-10-30T13:02:29
```
