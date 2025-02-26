# 

```
---

 properties: 
   state: 'Enabled' 
   accessEndpoint: >
    https://prod-04.eastus.logic.azure.com:443/workflows/d5ebad709ebe4d799785910bf78
    ae164

 
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
       Entities_-_Get_FileHashes: 
         type: 'ApiConnection' 
         inputs: 
           body: '@triggerBody()?[''object'']?[''properties'']?[''relatedEntities'']' 
           host: 
             connection: 
               name: '@parameters(''$connections'')[''azuresentinel''][''connectionId'']' 
           method: 'post' 
           path: '/entities/filehash' 
       For_each: 
         foreach: '@body(''Entities_-_Get_FileHashes'')?[''Filehashes'']' 
         actions: 
           Add_comment_to_incident_(V3): 
             runAfter: 
               Switch: 
                - 'Succeeded' 
             type: 'ApiConnection' 
             inputs: 
               body: 
                 incidentArmId: 'string incidentArmId=@triggerBody()?['object']?['id']' 
                 message: 'string message=<p>@{items('For_each')?['Value']} was added to MDE Indicators with action: AlertandBlock via playbook.</p>' 
               host: 
                 connection: 'System.Management.Automation.PSCustomObject connection=@{name=@parameters('$connections')['azuresentinel']['connectionId']}' 
               method: 'post' 
               path: '/Incidents/Comment' 
           Switch: 
             cases: 
               Case: 
                 case: 'string case=SHA1' 
                 actions: 'System.Management.Automation.PSCustomObject actions=@{HTTP=}' 
               Case_2: 
                 case: 'string case=SHA256' 
                 actions: 'System.Management.Automation.PSCustomObject actions=@{HTTP_2=}' 
             expression: '@items(''For_each'')?[''Algorithm'']' 
             type: 'Switch' 
         runAfter: 
           Entities_-_Get_FileHashes: 
            - 'Succeeded' 
         type: 'Foreach' 
   parameters: 
     $connections: 
       value: 
         azuresentinel: 
           connectionId: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
            cybermxdr-westeu/providers/Microsoft.Web/connections/azuresentinel-Restrict-MDEF
            ileHash

 
           connectionName: 'azuresentinel-Restrict-MDEFileHash' 
           id: >
            /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/providers/Microsoft.Web/loca
            tions/eastus/managedApis/azuresentinel

 
           connectionProperties: 
             authentication: 
               type: 'ManagedServiceIdentity' 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.Logic/workflows/Restrict-MDEFileHash

 
 name: 'Restrict-MDEFileHash' 
 type: 'Microsoft.Logic/workflows' 
 location: 'eastus' 
 tags: 
   LogicAppsCategory: 'security' 
   hidden-SentinelTemplateName: 'Restrict-MDEFileHash' 
   hidden-SentinelTemplateVersion: '1.0' 
   hidden-SentinelWorkspaceId: >
    /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
    cybermxdr-westeu/providers/microsoft.OperationalInsights/Workspaces/log-buisecop
    s-cybermxdr-westeu

 
 identity: 
   type: 'SystemAssigned' 
   principalId: '0338ed77-21c6-4842-a19e-bcfa151f3d2e' 
   tenantId: '27909b42-a095-40f2-be50-76c52e13b8f3'
```
