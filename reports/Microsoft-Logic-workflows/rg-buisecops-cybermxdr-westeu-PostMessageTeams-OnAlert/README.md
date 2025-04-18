# 

```
---

 properties: 
   state: 'Enabled' 
   accessEndpoint: >
    https://prod-09.eastus.logic.azure.com:443/workflows/616acc7feeea4d6ba9c6f5a94c8
    77ecc

 
   definition: 
     $schema: >
      https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01
      /workflowdefinition.json#

 
     contentVersion: '1.0.0.0' 
     parameters: 
       $connections: 
         defaultValue:  
         type: 'Object' 
     triggers: 
       Microsoft_Sentinel_alert: 
         type: 'ApiConnectionWebhook' 
         inputs: 
           host: 
             connection: 
               name: '@parameters(''$connections'')[''azuresentinel-2''][''connectionId'']' 
           body: 
             callback_url: '@{listCallbackUrl()}' 
           path: '/subscribe' 
     actions: 
       Post_message_in_a_chat_or_channel: 
         runAfter: 
           Get_incident: 
            - 'Succeeded' 
         type: 'ApiConnection' 
         inputs: 
           host: 
             connection: 
               name: '@parameters(''$connections'')[''teams-1''][''connectionId'']' 
           method: 'post' 
           body: 
             recipient: 
               groupId: 'c68cb720-6f90-4914-b2ca-eaca01472151' 
               channelId: '19:lw-6PBOyhVdNAloLXheL124I_5YJWpix44JB6klvMRs1@thread.tacv2' 
             messageBody: >
              <p class="editor-paragraph"></p><p class="editor-paragraph">@{triggerBody()?['Se
              verity']}</p><p class="editor-paragraph"></p><br>

 
           path: >
            /beta/teams/conversation/message/poster/Flow bot/location/@{encodeURIComponent('
            Channel')}

 
       Get_incident: 
         runAfter:  
         type: 'ApiConnection' 
         inputs: 
           host: 
             connection: 
               name: '@parameters(''$connections'')[''azuresentinel-2''][''connectionId'']' 
           method: 'post' 
           body: 
             incidentArmId: >
              @{triggerBody()?['AlertDisplayName']}

              @{triggerBody()?['Severity']}

              @{triggerBody()?['Entities']}

 
           path: '/Incidents' 
   parameters: 
     $connections: 
       value: 
         azuresentinel-2: 
           id: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/providers/Microsoft.Web/loca
            tions/eastus/managedApis/azuresentinel

 
           connectionId: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
            cybermxdr-westeu/providers/Microsoft.Web/connections/azuresentinel-2

 
           connectionName: 'azuresentinel-2' 
         teams-1: 
           id: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/providers/Microsoft.Web/loca
            tions/eastus/managedApis/teams

 
           connectionId: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
            cybermxdr-westeu/providers/Microsoft.Web/connections/teams-1

 
           connectionName: 'teams-1' 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.Logic/workflows/PostMessageTeams-OnAlert

 
 name: 'PostMessageTeams-OnAlert' 
 type: 'Microsoft.Logic/workflows' 
 location: 'eastus' 
 tags: 
   hidden-SentinelTemplateName: 'PostMessageTeams' 
   hidden-SentinelTemplateVersion: '1.0' 
   hidden-SentinelWorkspaceId: >
    /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
    cybermxdr-westeu/providers/microsoft.OperationalInsights/Workspaces/log-buisecop
    s-cybermxdr-westeu

 
 identity: 
   type: 'SystemAssigned' 
   principalId: '197e5d9f-2fdb-4b5c-bd86-2d4b396acbe7' 
   tenantId: '27909b42-a095-40f2-be50-76c52e13b8f3'
```
