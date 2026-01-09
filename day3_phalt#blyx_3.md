# Name
- PHALT#BLYX_BSOD_ClickFix

# Description
- Detects possible ClickFix used by PHALT#BLYX to execute PowerShell and retrieve .proj payloads.

# References
- https://www.securonix.com/blog/analyzing-phaltblyx-how-fake-bsods-and-trusted-build-tools-are-used-to-construct-a-malware-infection/

# Author
- Joshua Penny
  
# Socials
- twitter: josh_penny
- LinkedIn: linkedin.com/in/joshua-penny-50578b105/

# Threats
- PHALT#BLYX

# MITRE Techniques
- TBC

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceProcessEvents

# Query
```
DeviceProcessEvents
  | where InitiatingProcessFileName =~ "explorer.exe"
  | where FileName =~ "powershell.exe" or FileName =~ "pwsh.exe"
  | where ProcessCommandLine has_all (
    "booking.com",
    "gci",    
    "msbuild.exe",
    "iwr",
    "-r",
    "-o",
    "-ea",    
    "ProgramData",
    ".proj"
  )
  ```