# SymantecProxySG

```
--- 
 properties: 
   category: 'Microsoft Sentinel Parser' 
   displayName: 'SymantecProxySG' 
   version: 2 
   functionAlias: 'SymantecProxySG' 
   query: >
    let forwarder_host_names = dynamic(["datasource"]);
    let datasource = union isfuzzy=true  (datatable(Source: string)[]), (_GetWatchli
    st('ASimSourceType') | where SearchKey == 'SymantecProxySG' | project Source);
    Syslog
    | where CollectorHostName in (forwarder_host_names) or Computer in (forwarder_host_names)
    or CollectorHostName in (datasource) or Computer in (datasource)
    | where Facility == "local0"
    | parse SyslogMessage with logTime:datetime " " time_taken:long " " c_ip:string "
    " cs_userdn:string " " cs_auth_groups:string " " exception_id " " sc_filter_result:string
    ' "' cs_categories:string '" "' cs_referrer:string '" ' sc_status:string " "
    s_action:string " " cs_method:string ' "' content_type:string '" ' cs_uri_scheme:string
    " " cs_host:string " " cs_uri_port:string " " cs_uri_path:string " " cs_uri_query:string
    " " cs_uri_extension:string ' '  Part2:string
    | extend cs_categories = split(cs_categories,";")
    | extend content_type = split(replace(@"%20",@'',tostring(content_type)),";")
    | parse Part2 with '"' UserAgent '" ' Part3
    | extend cs_user_agent = iff(Part2 startswith "-", "-", UserAgent),
    Part3 = iff(Part2 startswith "-", substring(Part2,2), Part3)
    | parse Part3 with s_ip:string " " sent_bytes:long " " received_bytes:long " "
    virus_id:string  ' "' app_name:string  '" "' app_operation:string '" ' src_port:string
    ' "' country:string '" ' cs_threat_risk:string "#015"
    | project-away Part2, Part3, UserAgent

 
   tags: 
    - 
      name: 'description' 
      value: null 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/savedSearches/symantecproxysg
 
 name: 'symantecproxysg' 
 type: 'Microsoft.OperationalInsights/savedSearches'
```
