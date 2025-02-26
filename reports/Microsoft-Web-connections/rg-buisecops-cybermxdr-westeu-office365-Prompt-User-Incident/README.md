# office365-Prompt-User-Incident

```
---

 kind: 'V1' 
 properties: 
   displayName: 'office365-Prompt-User-Incident' 
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
     name: 'office365' 
     displayName: 'Office 365 Outlook' 
     description: >
      Microsoft Office 365 is a cloud-based service that is designed to help meet your
      organization's needs for robust security, reliability, and user productivity.

 
     iconUri: >
      https://conn-afd-prod-endpoint-bmc9bqahasf3grgk.b01.azurefd.net/releases/v1.0.17
      22/1.0.1722.3975/office365/icon.png

 
     brandColor: '#0078D4' 
     category: 'Standard' 
     id: >
      /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/providers/Microsoft.Web/loca
      tions/eastus/managedApis/office365

 
     type: 'Microsoft.Web/locations/managedApis' 
   testLinks: 
    - 
      requestUri: >
       https://management.azure.com:443/subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8
       a85/resourceGroups/rg-buisecops-cybermxdr-westeu/providers/Microsoft.Web/connect
       ions/office365-Prompt-User-Incident/extensions/proxy/testconnection?api-version=
       2018-07-01-preview

 
      method: 'get' 
   testRequests: 
    - 
      body: 
        request: 
          method: 'get' 
          path: 'testconnection' 
      requestUri: >
       https://management.azure.com:443/subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8
       a85/resourceGroups/rg-buisecops-cybermxdr-westeu/providers/Microsoft.Web/connect
       ions/office365-Prompt-User-Incident/dynamicInvoke?api-version=2018-07-01-preview

 
      method: 'POST' 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.Web/connections/office365-Prompt-User-Incid
  ent

 
 name: 'office365-Prompt-User-Incident' 
 type: 'Microsoft.Web/connections' 
 location: 'eastus'
```
