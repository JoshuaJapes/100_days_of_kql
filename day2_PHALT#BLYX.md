# Name
- PHALT#BLYX_InjectedFiles_Non_Standard_Outbound_Connections

# Description
- Detects possible injected binaries making outbound connections to non-standard port.
- Also detects possible injected binaries connections to known Loader Panel DC RAT C2 IP Addresses.  

# References
- https://www.securonix.com/blog/analyzing-phaltblyx-how-fake-bsods-and-trusted-build-tools-are-used-to-construct-a-malware-infection/

# Author
- Joshua Penny
  
# Socials
- twitter: josh_penny
- LinkedIn: linkedin.com/in/joshua-penny-50578b105/

# Threats
- PHALT#BLYX
- AsyncRAT

# MITRE Techniques
- TBC

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
let loader_panel_C2s = dynamic([
"194.169.163.140",
"5.23.52.131",
"45.141.87.243",
"185.211.170.173",
"45.132.50.107",
"185.217.199.146",
"193.233.204.176",
"193.124.24.105",
"45.91.8.136",
"194.87.238.216",
"213.171.5.199",
"195.66.114.70",
"94.156.181.191",
"178.250.186.16",
"185.221.214.197",
"62.60.187.17",
"46.173.214.64",
"46.173.214.8",
"92.118.113.110",
"62.60.187.101",
"46.173.214.176",
"80.64.18.173",
"85.192.63.194"
]);
let injectedFiles = dynamic([
"aspnet_compiler.exe", 
"RegSvcs.exe",
"RegAsm.exe"
]);
union DeviceProcessEvents, DeviceNetworkEvents
| where FileName in (injectedFiles)
| where RemotePort == "3535" or where RemoteIP in (loader_panel_C2s)
| project Timestamp, FileName, RemoteIp, RemotePort
```