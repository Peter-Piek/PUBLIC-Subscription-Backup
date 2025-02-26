# Potential Build Process Compromise - MDE

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/5d446d2b-84e9
  -40d4-a98e-11ca88eaa59d
 
 name: '5d446d2b-84e9-40d4-a98e-11ca88eaa59d' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: null 
   severity: 'Medium' 
   query: >
    // How far back to look for events from
    let timeframe = 1d;
    // How close together build events and file modifications should occur to alert
    (make this smaller to reduce FPs)
    let time_window = 5m;
    // Edit this to include build processes used
    let build_processes = dynamic(["MSBuild.exe", "dotnet.exe", "VBCSCompiler.exe"])
    ;
    // Include any processes that you want to allow to edit files during/around the
    build process
    let allow_list = dynamic([]);
    DeviceProcessEvents
    | where TimeGenerated > ago(timeframe)
    // Look for build process starts
    | where FileName has_any (build_processes)
    | summarize by BuildParentProcess=InitiatingProcessFileName, BuildProcess=FileName,
    BuildAccount = AccountName, DeviceName, BuildCommand=ProcessCommandLine, timekey=
    bin(TimeGenerated, time_window), BuildProcessTime=TimeGenerated
    | join kind=inner(
    DeviceFileEvents
    | where TimeGenerated > ago(timeframe)
    | where InitiatingProcessFileName !in (allow_list)
    | where ActionType == "FileCreated"  or ActionType == "FileModified"
    // Look for code files, edit this to include file extensions used in build.
    | where FileName endswith ".cs" or FileName endswith ".cpp"
    | summarize by FileEditParentProcess=InitiatingProcessParentFileName, FileEditAccount
    = InitiatingProcessAccountName, DeviceName, FileEdited=FileName, FileEditProces
    s=InitiatingProcessFileName, timekey= bin(TimeGenerated, time_window), FileEditT
    ime=TimeGenerated)
    // join where build processes and file modifications seen at same time on same h
    ost
    on timekey, DeviceName
    // Limit to only where the file edit happens after the build process starts
    | where BuildProcessTime <= FileEditTime
    | summarize make_set(FileEdited), make_set(FileEditProcess), make_set(FileEditAccount)
    by timekey, DeviceName, BuildParentProcess, BuildProcess
    | extend HostName = iff(DeviceName has '.', substring(DeviceName,0,indexof(Devic
    eName,'.')),DeviceName)
    | extend DnsDomain = iff(DeviceName has '.', substring(DeviceName,indexof(Device
    Name,'.')+1),"")
 
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
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'HostName' 
         columnName: 'HostName' 
       - 
         identifier: 'DnsDomain' 
         columnName: 'DnsDomain' 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
   tactics: 
    - 'Persistence' 
   techniques: 
    - 'T1554' 
   subTechniques: null 
   displayName: 'Potential Build Process Compromise - MDE' 
   enabled: true 
   description: >
    The query looks for source code files being modified immediately after a build
    process is started. The purpose of this is to look for malicious code injection
    during the build process. This query uses Microsoft Defender for Endpoint telem
    etry.
    More details: https://techcommunity.microsoft.com/t5/azure-sentinel/monitoring-t
    he-software-supply-chain-with-azure-sentinel/ba-p/2176463
 
   alertRuleTemplateName: '1bf6e165-5e32-420e-ab4f-0da8558a8be2' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
