# 

```
---

 properties: 
   state: 'Enabled' 
   accessEndpoint: >
    https://prod-23.eastus.logic.azure.com:443/workflows/358b27b8148d41d8b86acf31cfa
    e7975

 
   definition: 
     $schema: >
      https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01
      /workflowdefinition.json#

 
     contentVersion: '1.0.0.0' 
     parameters: 
       $connections: 
         type: 'Object' 
     triggers: 
       Microsoft_Sentinel_incident: 
         type: 'ApiConnectionWebhook' 
         inputs: 
           body: 
             callback_url: '@{listCallbackUrl()}' 
           host: 
             connection: 
               name: '@parameters(''$connections'')[''azuresentinel''][''connectionId'']' 
           path: '/incident-creation' 
     actions: 
       Entities_-_Get_Accounts: 
         type: 'ApiConnection' 
         inputs: 
           body: '@triggerBody()?[''object'']?[''properties'']?[''relatedEntities'']' 
           host: 
             connection: 
               name: '@parameters(''$connections'')[''azuresentinel''][''connectionId'']' 
           method: 'post' 
           path: '/entities/account' 
       For_each: 
         foreach: '@body(''Entities_-_Get_Accounts'')?[''Accounts'']' 
         actions: 
           Condition_2: 
             actions: 
               Add_comment_to_incident_(V3): 
                 type: 'string type=ApiConnection' 
                 inputs: 'System.Management.Automation.PSCustomObject inputs=@{body=; host=; method=post; path=/Incidents/Comment}' 
               Update_incident: 
                 runAfter: 'System.Management.Automation.PSCustomObject runAfter=@{Add_comment_to_incident_(V3)=System.Object[]}' 
                 type: 'string type=ApiConnection' 
                 inputs: 'System.Management.Automation.PSCustomObject inputs=@{body=; host=; method=put; path=/Incidents}' 
             runAfter: 
               Send_approval_email: 
                - 'Succeeded' 
             else: 
               actions: 
                 Add_comment_to_incident_(V3)_2: 'System.Management.Automation.PSCustomObject Add_comment_to_incident_(V3)_2=@{type=ApiConnection; inputs=}' 
                 Post_message_in_a_chat_or_channel: 'System.Management.Automation.PSCustomObject Post_message_in_a_chat_or_channel=@{runAfter=; type=ApiConnection; inputs=}' 
             expression: 
               and: 
                - '@{equals=System.Object[]}' 
             type: 'If' 
           Get_user: 
             type: 'ApiConnection' 
             inputs: 
               host: 
                 connection: 'System.Management.Automation.PSCustomObject connection=@{name=@parameters('$connections')['azuread']['connectionId']}' 
               method: 'get' 
               path: >
                /v1.0/users/@{encodeURIComponent(concat(items('For_each')?['Name'], '@' ,items('
                For_each')?['UPNSuffix']))}

 
           Send_approval_email: 
             runAfter: 
               Get_user: 
                - 'Succeeded' 
             type: 'ApiConnectionWebhook' 
             inputs: 
               body: 
                 Message: 'System.Management.Automation.PSCustomObject Message=@{Body=New Alert from Microsoft Sentinel.
Please respond ASAP.
Severity: @{triggerBody()?['object']?['properties']?['severity']}
Name: @{triggerBody()?['object']?['properties']?['title']}
Description: @{triggerBody()?['object']?['properties']?['description']}; HideHTMLMessage=False; Importance=High; Options=This was me, This was not me; ShowHTMLConfirmationDialog=False; Subject=Security Alert: @{triggerBody()?['object']?['properties']?['title']}; To=@body('Get_user')?['mail']}' 
                 NotificationUrl: 'string NotificationUrl=@{listCallbackUrl()}' 
               host: 
                 connection: 'System.Management.Automation.PSCustomObject connection=@{name=@parameters('$connections')['office365']['connectionId']}' 
               path: '/approvalmail/$subscriptions' 
         runAfter: 
           Entities_-_Get_Accounts: 
            - 'Succeeded' 
         type: 'Foreach' 
   parameters: 
     $connections: 
       value: 
         azuread: 
           connectionId: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
            cybermxdr-westeu/providers/Microsoft.Web/connections/azuread-Prompt-User-Inciden
            t

 
           connectionName: 'azuread-Prompt-User-Incident' 
           id: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/providers/Microsoft.Web/loca
            tions/eastus/managedApis/azuread

 
         azuresentinel: 
           connectionId: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
            cybermxdr-westeu/providers/Microsoft.Web/connections/azuresentinel-Prompt-User-I
            ncident

 
           connectionName: 'azuresentinel-Prompt-User-Incident' 
           id: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/providers/Microsoft.Web/loca
            tions/eastus/managedApis/azuresentinel

 
           connectionProperties: 
             authentication: 
               type: 'ManagedServiceIdentity' 
         office365: 
           connectionId: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
            cybermxdr-westeu/providers/Microsoft.Web/connections/office365-Prompt-User-Incid
            ent

 
           connectionName: 'office365-Prompt-User-Incident' 
           id: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/providers/Microsoft.Web/loca
            tions/eastus/managedApis/office365

 
         teams: 
           connectionId: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
            cybermxdr-westeu/providers/Microsoft.Web/connections/teams-Prompt-User-Incident

 
           connectionName: 'teams-Prompt-User-Incident' 
           id: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/providers/Microsoft.Web/loca
            tions/eastus/managedApis/teams

 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.Logic/workflows/Prompt-User-Incident

 
 name: 'Prompt-User-Incident' 
 type: 'Microsoft.Logic/workflows' 
 location: 'eastus' 
 tags: 
   LogicAppsCategory: 'security' 
   hidden-SentinelTemplateName: 'Prompt-User' 
   hidden-SentinelTemplateVersion: '1.1' 
   hidden-SentinelWorkspaceId: >
    /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
    cybermxdr-westeu/providers/microsoft.OperationalInsights/Workspaces/log-buisecop
    s-cybermxdr-westeu

 
 identity: 
   type: 'SystemAssigned' 
   principalId: '61bfaf0a-72a5-4ac5-8940-e7dd0de2c974' 
   tenantId: '27909b42-a095-40f2-be50-76c52e13b8f3'
```
