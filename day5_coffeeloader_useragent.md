# Name
- CoffeeLoader_UserAgent

# Description
- Coffee Loader is a malware loader, seen dropped by Smokeloader and dropping Rhadamanthys Shellcode. Detects user agent string used by the loader.

# References
- https://www.zscaler.com/blogs/security-research/coffeeloader-brew-stealthy-techniques

# Author
- Joshua Penny
  
# Socials
- twitter: josh_penny
- LinkedIn: linkedin.com/in/joshua-penny-50578b105/

# Threats
- Coffee Loader

# MITRE Techniques
- 

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceNetworkEvents

# Query
```
// Coffee Loader has a hard coded user-agent that mimics the Apple iPhone. This detection looks to identify the specific iPhone user agent in outbound device network events, to Remote URLs ending with ".com", then validating that the Device is not an iPhone or running iOS from the DeviceInfo table.
    DeviceNetworkEvents
    | extend AdditionalFieldsParsed = parse_json(AdditionalFields)
    | where isnotnull(AdditionalFieldsParsed) 
    | where isnotnull(AdditionalFieldsParsed.user_agent)
    | where AdditionalFieldsParsed.user_agent has "Mozilla/5.0 (iPhone; CPU iPhone OS 11_2_8; like Mac OS X) AppleWebKit/533.7 (KHTML, like Gecko) Chrome/47.0.1880.340 Mobile Safari/536.9"
    | where AdditionalFieldsParsed.direction has "Out"
    | where RemoteUrl endswith ".com"
    | join kind=inner (
      DeviceInfo
      | where not (OSPlatform has "iOS") and not (Model has "iPhone")
    ) on DeviceId
```