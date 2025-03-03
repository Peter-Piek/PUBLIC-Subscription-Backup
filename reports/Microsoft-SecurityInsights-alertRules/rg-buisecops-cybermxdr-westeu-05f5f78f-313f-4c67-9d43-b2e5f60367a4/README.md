# Creation of expensive computes in Azure

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/05f5f78f-313f
  -4c67-9d43-b2e5f60367a4
 
 name: '05f5f78f-313f-4c67-9d43-b2e5f60367a4' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Scheduled' 
 properties: 
   queryFrequency: 'P1D' 
   queryPeriod: 'P1D' 
   triggerOperator: 'GreaterThan' 
   triggerThreshold: 1 
   eventGroupingSettings: 
     aggregationKind: 'SingleAlert' 
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
      entityType: 'Account' 
      fieldMappings: 
       - 
         identifier: 'Name' 
         columnName: 'Name' 
       - 
         identifier: 'UPNSuffix' 
         columnName: 'UPNSuffix' 
    - 
      entityType: 'Host' 
      fieldMappings: 
       - 
         identifier: 'HostName' 
         columnName: 'ComputerName' 
    - 
      entityType: 'IP' 
      fieldMappings: 
       - 
         identifier: 'Address' 
         columnName: 'CallerIpAddress' 
   severity: 'Low' 
   query: >
    let tokens = dynamic(["416","208","192","128","120","96","80","72","64","48","44
    ","40","nc12","nc24","nv24"]);
    let operationList = dynamic(["microsoft.compute/virtualmachines/write", "microso
    ft.resources/deployments/write"]);
    AzureActivity
    | where OperationNameValue in~ (operationList)
    | where ActivityStatusValue startswith "Accept"
    | where Properties has 'vmSize'
    | extend parsed_property= parse_json(tostring((parse_json(Properties).responseBo
    dy))).properties
    | extend vmSize = tostring((parsed_property.hardwareProfile).vmSize)
    | mv-apply token=tokens to typeof(string) on (where vmSize contains token)
    | extend ComputerName = tostring((parsed_property.osProfile).computerName)
    | project TimeGenerated, OperationNameValue, ActivityStatusValue, Caller,
    CallerIpAddress, ComputerName, vmSize
    | extend Name = tostring(split(Caller,'@',0)[0]), UPNSuffix = tostring(split(Cal
    ler,'@',1)[0])
 
   suppressionDuration: 'PT5H' 
   suppressionEnabled: null 
   tactics: 
    - 'DefenseEvasion' 
   techniques: 
    - 'T1578' 
   displayName: 'Creation of expensive computes in Azure' 
   enabled: true 
   description: >
    Identifies the creation of large size or expensive VMs (with GPUs or with a large
    number of virtual CPUs) in Azure.
    An adversary may create new or update existing virtual machines to evade defenses
    or use them for cryptomining purposes.
    For Windows/Linux Vm Sizes, see https://docs.microsoft.com/azure/virtual-machine
    s/windows/sizes
    Azure VM Naming Conventions, see https://docs.microsoft.com/azure/virtual-machin
    es/vm-naming-conventions
 
   alertRuleTemplateName: '9736e5f1-7b6e-4bfb-a708-e53ff1d182c3' 
   lastModifiedUtc: 2024-10-30T13:03:57
```
