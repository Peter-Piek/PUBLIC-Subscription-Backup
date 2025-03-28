# SQLEvent

```
--- 
 properties: 
   category: 'SQLEvent' 
   displayName: 'SQLEvent' 
   version: 2 
   functionAlias: 'SQLEvent' 
   query: >
    // KQL SQL Audit Event Parser
    // Last Updated Date: Jun 21,  2020
    // SQL Server 2016
    //
    //
    // Parser Notes:
    // This parser works against the SQL Audit events being written to Application Log
    of Windows Events.
    //
    // Usage Instruction:
    // Paste below query in log analytics, click on Save button and select as Function
    from drop down by specifying function name and alias (e.g. SQLEvent).
    // Function usually takes 10-15 minutes to activate. You can then use function
    alias from any other queries (e.g. SQLEvent | take 10).
    // References:
    // Using functions in Azure monitor log queries : https://docs.microsoft.com/azu
    re/azure-monitor/log-query/functions
    // Tech Community Blog on KQL Functions : https://techcommunity.microsoft.com/t5
    /Azure-Sentinel/Using-KQL-functions-to-speed-up-analysis-in-Azure-Sentinel/ba-p/
    712381
    // Detailed Blog on Monitoring SQL Server with Azure Sentinel : https://techcomm
    unity.microsoft.com/t5/azure-sentinel/monitoring-sql-server-with-azure-sentinel/
    ba-p/1502960
    //
    let SQlData = Event
    | where Source contains "MSSQL"
    ;
    let Sqlactivity = SQlData
    | where RenderedDescription !has "LGIS" and RenderedDescription !has "LGIF"
    | parse RenderedDescription with * "action_id:" Action:string
    " " *
    | parse RenderedDescription with * "client_ip:" ClientIP:string
    " permission" *
    | parse RenderedDescription with * "session_server_principal_name:" CurrentUser:
    string
    " " *
    | parse RenderedDescription with * "database_name:" DatabaseName:string
    "schema_name:" Temp:string
    "object_name:" ObjectName:string
    "statement:" Statement:string
    "additional_information:" AdditionalInfo:string
    "." *
    ;
    let FailedLogon = SQlData
    | where EventLevelName has "error"
    | where RenderedDescription startswith "Login"
    | parse kind=regex RenderedDescription with "Login" LogonResult:string
    "for user '" CurrentUser:string
    "'. Reason:" Reason:string " \\[" *
    | parse kind=regex RenderedDescription with * "CLIENT" * ":" ClientIP:string
    "]" *
    ;
    let dbfailedLogon = SQlData
    | where RenderedDescription has " Failed to open the explicitly specified database"
    
    | parse kind=regex RenderedDescription with "Login" LogonResult:string
    "for user '" CurrentUser:string
    "'. Reason:" Reason:string
    " '" DatabaseName:string
    "'" *
    | parse kind=regex RenderedDescription with * "CLIENT" * ":" ClientIP:string
    "]" *
    ;
    let successLogon = SQlData
    | where RenderedDescription has "LGIS"
    | parse RenderedDescription with * "action_id:" Action:string
    " " LogonResult:string
    ":" Temp2:string
    "session_server_principal_name:" CurrentUser
    :string
    " " *
    | parse RenderedDescription with * "client_ip:" ClientIP:string
    " " *
    ;
    (union isfuzzy=true
    Sqlactivity, FailedLogon, dbfailedLogon, successLogon )
    | project TimeGenerated, Computer, EventID, Action, ClientIP, LogonResult,
    CurrentUser, Reason, DatabaseName, ObjectName, Statement
 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/savedSearches/4b262a03-1aa1-490a-9356-23f84df25722_sqlevent
 
 name: '4b262a03-1aa1-490a-9356-23f84df25722_sqlevent' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
