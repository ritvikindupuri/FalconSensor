//This LogScale query was used to hunt for the adversary's final actions on the Domain Controller. It specifically looks for tool transfers and the ntdsutil command for credential dumping.

// LogScale Query to find "Action on Objective" on the Domain Controller
// This query hunts for known tool transfer, execution, and credential dumping
// TTPs on the high-value 'FUTURE-DC' asset.

#repo=base_sensor UserName = * ComputerName = "FUTURE-DC"
| /net1|/Q /c/ OR "cmd.exe /C" OR "powershell.exe /C"| AND NOT rmdir
| groupBy([@timestamp, CommandLine], function=[limit = 20000])
| sort(@timestamp)
