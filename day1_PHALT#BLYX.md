# Name
- PHALT#BLYX_Process_Rename_Move_and_Url_File_in_StartUp

# Description
- Detects an executable moving from ProgramData to Temp and being renamed, then a .url file being created within user startup directory, within 10 minute window.

# References
- https://www.securonix.com/blog/analyzing-phaltblyx-how-fake-bsods-and-trusted-build-tools-are-used-to-construct-a-malware-infection/

# Author
- Joshua Penny
  
# Socials
- X: @josh_penny
- LinkedIn: linkedin.com/in/joshua-penny-50578b105/

# Threats
- PHALT#BLYX

# MITRE Techniques
- TBC

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceFileEvents

# Query
```
// Set 10 minute time window
let TimeWindow = 10m;
// Look for an InitiatingProcessName move a .exe from ProgramData to Temp and Rename it
let SuspiciousExeMove = 
    DeviceFileEvents
    | where ActionType in ("FileCreated", "FileRenamed")
    | where FolderPath has @"\Windows\Temp"
    | where FileName endswith ".exe"
    | where InitiatingProcessFolderPath has "ProgramData" or PreviousFolderPath has "ProgramData"
    // Allocate a MoveTime for the timestamp event, create unique DroppedExe name and Target Path.
    | project MoveTime = Timestamp, DeviceId, DeviceName, DroppedExe = FileName, TargetPath = FolderPath, InitiatingProcessFileName, InitiatingProcessId;
// Look for a .url file being created within the StartUp directory
let PersistenceShortcut = 
    DeviceFileEvents
    | where ActionType == "FileCreated"
    | where FolderPath has "Startup"
    | where FileName endswith ".url"
    // Assign ShortcutFile name and path
    | project PersistenceTime = Timestamp, DeviceId, ShortcutFile = FileName, ShortcutPath = FolderPath, InitiatingProcessFileName, InitiatingProcessId;
// Match first variable on InitiatingProcessFileName and check that both events occur within 10 minutes
SuspiciousExeMove
| join kind=inner (PersistenceShortcut) on InitiatingProcessFileName
| where PersistenceTime between (MoveTime .. (MoveTime + TimeWindow))
// Project relevant fields from join
| project MoveTime, PersistenceTime, DeviceName, DroppedExe, ShortcutFile, TargetPath
```