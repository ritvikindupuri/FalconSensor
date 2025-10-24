// This LogScale query was used to isolate the adversary's initial reconnaissance, persistence, and privilege escalation commands on the compromised workstation.


// LogScale Query to find adversary TTPs on the initial workstation
// This query hones in on the specific user, host, and command-line tools
// used for persistence and privilege escalation.

UserName = srogers ComputerName = "*-DT"
| /"net1"|/Q /c/ "net1" CommandLine=*
| sort(@timestamp, order=desc)
| table([@timestamp, CommandLine])
