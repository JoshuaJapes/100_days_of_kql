# Name
- Auditing_Outbound_Connections_to_BPH

# Description
- Threat actors are drawn to Bulletproof Hosting (BPH) providers for their permissive policies regarding hosted content and their hands-off approach to abuse complaints and takedown requests. These providers allow malicious infrastructure like phishing kits, Command-and-Control (C2) servers, or data exfiltration points to remain online longer with fewer disruptions.

# References
- https://info.silentpush.com/hubfs/SP-WP-bulletproof-hosting.pdf?utm_campaign=31865988-asset-bph-whitepaper-q4fy25&utm_source=website&utm_medium=post

# Author
- Joshua Penny
  
# Socials
- twitter: josh_penny
- LinkedIn: linkedin.com/in/joshua-penny-50578b105/

# Threats
- Bulletproofhosting

# MITRE Techniques
- 

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceNetworkEvents

# Query
```
/*
AS152194 (CTGSERVERLIMITED-AS-AP)
AS214351 (FEMOIT GB)
AS213194 (NECHAEVDS-AS RU)
AS215789 (Karina Rashkovska)
AS214943 (RAILNET)
AS34985 (NETINNOVATIONLLC-AS-AP)
AS48589 (SOW-A-AS UA)
AS49217 (HOSTYPE US)
AS214940 (KPROHOST LLC)
AS140224 (SGPL-AS-AP STARCLOUD GLOBAL PTE. LTD. SG)
*/
let BPH_Subnets = externaldata(Network:string)
    [@"https://raw.githubusercontent.com/JoshuaJapes/100_days_of_kql/bph_subnets.csv"]
    with (format="csv", ignoreFirstRecord=true)
| summarize make_list(Network);
DeviceNetworkEvents
| where ActionType == "ConnectionSuccess"
| where ipv4_is_in_any_range(RemoteIP, toscalar(BPH_Subnets))
| join kind=inner (
    DeviceProcessEvents
    | project DeviceId, ProcessId, CreationTime, ProcessCommandLine, FolderPath, AccountName, SHA256
) on DeviceId, $left.InitiatingProcessId == $right.ProcessId, $left.InitiatingProcessCreationTime == $right.CreationTime
| where not(ProcessCommandLine has_any ("Microsoft Intune Management")) // include FPs are you investigate the data
| project 
    TimeGenerated, 
    DeviceName, 
    RemoteIP, 
    RemotePort, 
    Protocol, 
    InitiatingProcessFileName, 
    ProcessCommandLine, 
    AccountName, 
    SHA256
| sort by TimeGenerated desc
```