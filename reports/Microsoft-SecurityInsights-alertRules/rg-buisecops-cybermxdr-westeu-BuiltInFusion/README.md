# Advanced Multistage Attack Detection

```
--- 
 id: >
  /subscriptions/d7425a42-e8c6-4a20-8d02-c2d534dc8a85/resourceGroups/rg-buisecops-
  cybermxdr-westeu/providers/Microsoft.OperationalInsights/workspaces/log-buisecop
  s-cybermxdr-westeu/providers/Microsoft.SecurityInsights/alertRules/BuiltInFusion
 
 name: 'BuiltInFusion' 
 type: 'Microsoft.SecurityInsights/alertRules' 
 kind: 'Fusion' 
 properties: 
   displayName: 'Advanced Multistage Attack Detection' 
   description: >
    Microsoft Sentinel uses Fusion, a correlation engine based on scalable machine
    learning algorithms, to automatically detect multistage attacks by identifying
    combinations of anomalous behaviors and suspicious activities that are observed
    at various stages of the kill chain. On the basis of these discoveries, Azure
    Sentinel generates incidents that would otherwise be very difficult to catch. By
    design, these incidents are low-volume, high-fidelity, and high-severity, which
    is why this detection is turned ON by default.

    Since Fusion correlates multiple signals from various products to detect advanced
    multistage attacks, successful Fusion detections are presented as Fusion incidents
    on the Microsoft Sentinel Incidents page. This rule covers the following detect
    ions:
    - Fusion for emerging threats
    - Fusion for ransomware
    - Scenario-based Fusion detections (122 scenarios)

    To enable these detections, we recommend you configure the following data connectors
    for best results:
    - Out-of-the-box anomaly detections
    - Microsoft Entra ID Protection
    - Azure Defender
    - Azure Defender for IoT
    - Microsoft 365 Defender
    - Microsoft Cloud App Security
    - Microsoft Defender for Endpoint
    - Microsoft Defender for Identity
    - Microsoft Defender for Office 365
    - Scheduled analytics rules, both built-in and those created by your security
    analysts. Analytics rules must contain kill-chain (tactics) and entity mapping
    information in order to be used by Fusion.

    For the full description of each detection that is supported by Fusion, go to ht
    tps://aka.ms/SentinelFusion.
 
   alertRuleTemplateName: 'f71aba3d-28fb-450b-b192-4e76a83015c8' 
   tactics: 
    - 'Collection' 
    - 'CommandAndControl' 
    - 'CredentialAccess' 
    - 'DefenseEvasion' 
    - 'Discovery' 
    - 'Execution' 
    - 'Exfiltration' 
    - 'Impact' 
    - 'InitialAccess' 
    - 'LateralMovement' 
    - 'Persistence' 
    - 'PrivilegeEscalation' 
   severity: 'High' 
   sourceSettings: 
    - 
      enabled: true 
      sourceName: 'Anomalies' 
      sourceSubTypes: null 
    - 
      enabled: true 
      sourceName: 'Alert providers' 
      sourceSubTypes: 
       - 
         sourceSubTypeDisplayName: 'Microsoft Entra ID Protection' 
         sourceSubTypeName: 'Azure Active Directory Identity Protection' 
         enabled: true 
         severityFilters: 
           isSupported: true 
           filters: 
            - 
              severity: 'High' 
              enabled: true 
            - 
              severity: 'Medium' 
              enabled: true 
            - 
              severity: 'Low' 
              enabled: true 
            - 
              severity: 'Informational' 
              enabled: true 
       - 
         sourceSubTypeDisplayName: 'Microsoft 365 Defender' 
         sourceSubTypeName: 'Microsoft 365 Defender' 
         enabled: true 
         severityFilters: 
           isSupported: true 
           filters: 
            - 
              severity: 'High' 
              enabled: true 
            - 
              severity: 'Medium' 
              enabled: true 
            - 
              severity: 'Low' 
              enabled: true 
            - 
              severity: 'Informational' 
              enabled: true 
       - 
         sourceSubTypeDisplayName: 'Microsoft Cloud App Security' 
         sourceSubTypeName: 'Microsoft Cloud App Security' 
         enabled: true 
         severityFilters: 
           isSupported: true 
           filters: 
            - 
              severity: 'High' 
              enabled: true 
            - 
              severity: 'Medium' 
              enabled: true 
            - 
              severity: 'Low' 
              enabled: true 
            - 
              severity: 'Informational' 
              enabled: true 
       - 
         sourceSubTypeDisplayName: 'Microsoft Defender for Cloud' 
         sourceSubTypeName: 'Azure Defender' 
         enabled: true 
         severityFilters: 
           isSupported: true 
           filters: 
            - 
              severity: 'High' 
              enabled: true 
            - 
              severity: 'Medium' 
              enabled: true 
            - 
              severity: 'Low' 
              enabled: true 
            - 
              severity: 'Informational' 
              enabled: true 
       - 
         sourceSubTypeDisplayName: 'Microsoft Defender for Endpoint' 
         sourceSubTypeName: 'Microsoft Defender for Endpoint' 
         enabled: true 
         severityFilters: 
           isSupported: true 
           filters: 
            - 
              severity: 'High' 
              enabled: true 
            - 
              severity: 'Medium' 
              enabled: true 
            - 
              severity: 'Low' 
              enabled: true 
            - 
              severity: 'Informational' 
              enabled: true 
       - 
         sourceSubTypeDisplayName: 'Microsoft Defender for Identity' 
         sourceSubTypeName: 'Microsoft Defender for Identity' 
         enabled: true 
         severityFilters: 
           isSupported: true 
           filters: 
            - 
              severity: 'High' 
              enabled: true 
            - 
              severity: 'Medium' 
              enabled: true 
            - 
              severity: 'Low' 
              enabled: true 
            - 
              severity: 'Informational' 
              enabled: true 
       - 
         sourceSubTypeDisplayName: 'Microsoft Defender for IoT' 
         sourceSubTypeName: 'Azure Defender for IoT' 
         enabled: true 
         severityFilters: 
           isSupported: true 
           filters: 
            - 
              severity: 'High' 
              enabled: true 
            - 
              severity: 'Medium' 
              enabled: true 
            - 
              severity: 'Low' 
              enabled: true 
            - 
              severity: 'Informational' 
              enabled: true 
       - 
         sourceSubTypeDisplayName: 'Microsoft Defender for Office 365' 
         sourceSubTypeName: 'Microsoft Defender for Office 365' 
         enabled: true 
         severityFilters: 
           isSupported: true 
           filters: 
            - 
              severity: 'High' 
              enabled: true 
            - 
              severity: 'Medium' 
              enabled: true 
            - 
              severity: 'Low' 
              enabled: true 
            - 
              severity: 'Informational' 
              enabled: true 
       - 
         sourceSubTypeDisplayName: 'Azure Sentinel scheduled analytics rules' 
         sourceSubTypeName: 'Azure Sentinel scheduled analytics rules' 
         enabled: true 
         severityFilters: 
           isSupported: true 
           filters: 
            - 
              severity: 'High' 
              enabled: true 
            - 
              severity: 'Medium' 
              enabled: true 
            - 
              severity: 'Low' 
              enabled: true 
            - 
              severity: 'Informational' 
              enabled: true 
       - 
         sourceSubTypeDisplayName: 'Azure Sentinel NRT analytic rules' 
         sourceSubTypeName: 'Azure Sentinel NRT analytic rules' 
         enabled: true 
         severityFilters: 
           isSupported: true 
           filters: 
            - 
              severity: 'High' 
              enabled: true 
            - 
              severity: 'Medium' 
              enabled: true 
            - 
              severity: 'Low' 
              enabled: true 
            - 
              severity: 'Informational' 
              enabled: true 
   scenarioExclusionPatterns: null 
   techniques: null 
   subTechniques: null 
   enabled: true 
   lastModifiedUtc: 2024-07-22T09:06:48
```
