# Security vulnerability to CVE-2022-22963/65 [Custom]

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/6e029b98-a5b0
  -4bd5-9437-54687df91595
 
 name: '6e029b98-a5b0-4bd5-9437-54687df91595' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'PT1H' 
   queryPeriod: 'PT1H' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'High' 
   query: >
    // Query focus on zeroday exploit for springshell
    let regx_value_1 = @'(http\:\/\/[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\:
    \d{1,4})shell\.jsp?cmd\=w{1,}';
    let regx_value_2 = @'(http\:\/\/[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\:
    \d{1,4})\/\w{1,}\.\w{1,3}\?\w{1,3}\=w{1,}';
    let regx_value_3 = @'\/w+\.\w{1,}\?[a-zA-Z]{1,}\=w{1,}\&\w{1,}\={1,}';
    let regx_value_4= @'(http\:\/\/[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4}\.[0-9]{1,4})';
    
    // you can add regex_value_4 if you would like to see malicious requestin
    union
    (CommonSecurityLog
    | extend ComLogs = Type
    | extend ComLogs_TimeGenerated = TimeGenerated
    | where RequestURL matches regex regx_value_1
    or RequestURL matches regex regx_value_2
    or RequestURL matches regex regx_value_3
    // uncomment this line if you are interested in request with IPs
    // or RequestURL matches regex regx_value_4
    ),
    (DeviceNetworkEvents
    | extend DeviceNetworkLog_TimeGenerated = TimeGenerated
    | extend DeviceNetworkLog= Type
    | extend DeviceNet = DeviceName
    | where RemoteUrl matches regex regx_value_1
    or RemoteUrl matches regex regx_value_2
    or RemoteUrl matches regex regx_value_3),
    (DnsEvents
    | extend DnsLog = Type
    | extend DnsLog_TimeGenerated = TimeGenerated
    | where Name matches regex regx_value_1
    or Name matches regex regx_value_2
    or Name matches regex regx_value_3)
    | project ComLogs_TimeGenerated,ComLogs,
    SourceIP,
    DestinationIP,
    DestinationPort,
    RequestURL,
    DeviceNetworkLog_TimeGenerated,
    DeviceNetworkLog,
    DeviceNet,
    LocalIP,
    RemoteIP,
    RemoteUrl,
    DnsLog_TimeGenerated,
    DnsLog,
    ClientIP,
    IPAddresses,
    Name
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
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
   entityMappings: 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'SourceIP' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Execution' 
   techniques: 
    - 'T0853' 
   subTechniques: null 
   displayName: 'Security vulnerability to CVE-2022-22963/65 [Custom]' 
   enabled: true 
   description: >
    The new vulnerability CVE-2022-22963 found on Spring Cloud Function would permit
    attackers to execute arbitrary code on the machine and compromise the entire host.
    Using routing functionality, it is possible for a user to provide a specially
    crafted Spring Expression Language (SpEL) as a routing-expression to access local
    resources and execute commands in the host. Since Spring Cloud Function can be
    used in Cloud serverless functions like AWS lambda or Google Cloud Functions,
    those functions might be impacted as well.
 
   alertRuleTemplateName: null 
   lastModifiedUtc: 2024-10-30T13:02:03
```
