# Name
- CoffeeLoader_Scheduled_Tasks

# Description
- Coffee Loader is a new malware loader, seen dropped by Smokeloader and dropping Rhadamanthys Shellcode. Detects hard coded start boundary for scheduled task. 

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
- attack.T1053.005

# Data Sources
- Microsoft Defender for Endpoint (MDE)
  - DeviceEvents

# Query
```
// Coffee Loader creates scheduled tasks and has a hardcoded Start Boundary date when doing so: 2005-01-01T12:05:00. This detection looks for scheduled tasks that are created within the DeviceEvents table that have a matching StartBoundary.
    DeviceEvents
    | where ActionType == "ScheduledTaskCreated"
    | extend AdditionalFieldsParsed = parse_json(AdditionalFields)
    | extend TaskContentRaw = tostring(AdditionalFieldsParsed.TaskContent)
    | extend TaskContentParsed = parse_json(TaskContentRaw)
    | extend Triggers = TaskContentParsed.Triggers
    | extend CalendarTrigger = Triggers.CalendarTrigger
    | extend StartBoundary = CalendarTrigger.StartBoundary,
      Enabled = CalendarTrigger.Enabled,
      DaysOfMonth = tostring(CalendarTrigger.ScheduleByMonth.DaysOfMonth.Day)
    | where StartBoundary == "2005-01-01T12:05:00"
```