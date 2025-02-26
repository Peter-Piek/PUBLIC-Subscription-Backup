# 

```
---

 properties: 
   state: 'Enabled' 
   accessEndpoint: >
    https://prod-75.eastus.logic.azure.com:443/workflows/29976798136a4d559de2f0cf8ef
    82786

 
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
           body: 
             callback_url: '@{listCallbackUrl()}' 
           host: 
             connection: 
               name: '@parameters(''$connections'')[''azuresentinel''][''connectionId'']' 
           path: '/subscribe' 
     actions:  
     outputs:  
   parameters: 
     $connections: 
       value: 
         azuresentinel: 
           connectionId: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
            cybermxdr-westeu/providers/Microsoft.Web/connections/azuresentinel-kobustest1

 
           connectionName: 'azuresentinel-kobustest1' 
           id: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/providers/Microsoft.Web/loca
            tions/eastus/managedApis/azuresentinel

 
           connectionProperties: 
             authentication: 
               type: 'ManagedServiceIdentity' 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.Logic/workflows/kobustest1

 
 name: 'kobustest1' 
 type: 'Microsoft.Logic/workflows' 
 location: 'eastus' 
 identity: 
   type: 'SystemAssigned' 
   principalId: '5514684d-c35e-44c4-8d06-cf07db0044b3' 
   tenantId: '27909b42-a095-40f2-be50-76c52e13b8f3'
```
