# teams-Prompt-User-Incident

```
---

 kind: 'V1' 
 properties: 
   displayName: 'teams-Prompt-User-Incident' 
   authenticatedUser:  
   overallStatus: 'Error' 
   statuses: 
    - 
      status: 'Error' 
      target: 'token' 
      error: 
        code: 'Unauthenticated' 
        message: 'This connection is not authenticated.' 
   connectionState: 'Enabled' 
   parameterValues:  
   customParameterValues:  
   api: 
     name: 'teams' 
     displayName: 'Microsoft Teams' 
     description: >
      Microsoft Teams enables you to get all your content, tools and conversations in
      the Team workspace with Microsoft 365.

 
     iconUri: >
      https://conn-afd-prod-endpoint-bmc9bqahasf3grgk.b01.azurefd.net/releases/v1.0.17
      19/1.0.1719.3955/teams/icon.png

 
     brandColor: '#4B53BC' 
     category: 'Standard' 
     id: >
      /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/providers/Microsoft.Web/loca
      tions/eastus/managedApis/teams

 
     type: 'Microsoft.Web/locations/managedApis' 
   testLinks: 
    - 
      requestUri: >
       https://management.azure.com:443/subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8
       a85/resourceGroups/rg-buisecops-cybermxdr-westeu/providers/Microsoft.Web/connect
       ions/teams-Prompt-User-Incident/extensions/proxy/beta/me/teamwork?api-version=20
       18-07-01-preview

 
      method: 'get' 
   testRequests: 
    - 
      body: 
        request: 
          method: 'get' 
          path: 'beta/me/teamwork' 
      requestUri: >
       https://management.azure.com:443/subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8
       a85/resourceGroups/rg-buisecops-cybermxdr-westeu/providers/Microsoft.Web/connect
       ions/teams-Prompt-User-Incident/dynamicInvoke?api-version=2018-07-01-preview

 
      method: 'POST' 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.Web/connections/teams-Prompt-User-Incident

 
 name: 'teams-Prompt-User-Incident' 
 type: 'Microsoft.Web/connections' 
 location: 'eastus'
```
