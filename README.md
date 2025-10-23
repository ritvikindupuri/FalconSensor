# End-to-End Incident Response: Tracing a Full-Kill-Chain Attack

This project simulates a high-fidelity, end-to-end incident response investigation on an enterprise environment. As the lead analyst, I traced a multi-stage adversary kill chain that began with a workstation compromise and culminated in a full domain controller credential dump.

The investigation involved triaging alerts from the **Falcon EDR** platform, performing deep-dive process analysis, and correlating EDR telemetry with raw log data by authoring advanced **LogScale** queries to build an evidence-backed timeline of the attack.

---
## The Investigation: From Triage to Root Cause

The investigation began with multiple critical and high-severity alerts in the Falcon incident workbench, indicating a coordinated attack spanning multiple hosts.

<img src=".assets/incident-workbench.png" width="800" alt="Falcon incident workbench showing multiple critical alerts">
*<p align="center">Figure 1: The incident queue, showing Critical 10/10 alerts for Lateral Movement.</p>*

### Step 1: Initial Compromise & EDR Analysis (Workstation: `TOT-TAPIR-DT`)
The investigation first focused on the initial point of entry. The Falcon EDR's process graph for the workstation `TOT-TAPIR-DT` provided clear visual evidence of the adversary's execution. The process tree shows `svchost.exe` spawning `WmiPrvSE.exe`, which in turn launched multiple `cmd.exe` and `net1.exe` processes. This is a classic signature of `wmiexec.py` (T1047), a common tool used for remote execution.

<img src=".assets/edr-process-tree.png" width="800" alt="EDR Process Tree showing WmiPrvSE.exe spawning cmd.exe and net1.exe">
*<p align="center">Figure 2: The EDR's process graph, visualizing the initial execution TTPs on the workstation.</p>*

### Step 2: Log-Level Validation (Workstation TTPs)
To validate the EDR's findings and uncover the adversary's specific actions, I pivoted to LogScale. By authoring a query to filter for the compromised user and host, I isolated the exact commands executed by the attacker. The logs definitively confirm the adversary's TTPs:
* `ipconfig /all`: Reconnaissance (T1082)
* `ping 172.16.1.6`: Network Reconnaissance (T1046)
* `net localgroup Administrators audit /add`: Privilege Escalation (T1078.001)
* `net user audit REDACTED /add`: Persistence (T1136.001)

<img src=".assets/logscale-workstation-query.png" width="800" alt="LogScale query showing net user and net localgroup commands">
*<p align="center">Figure 3: My LogScale query and its results, providing raw log evidence of persistence and privilege escalation.</p>*

### Step 3: Action on Objective (Domain Controller: `FUTURE-DC`)
The Critical 10/10 alert indicated the adversary had moved laterally to the Domain Controller (`FUTURE-DC`). I again pivoted to LogScale to hunt for the attacker's final objectives. This query revealed the "smoking gun" of the entire attack:
* `Invoke-WebRequest ... okira_win.exe`: Ingress Tool Transfer (T1105)
* `ntdsutil ... create full C:\Windows\Temp\CrashpadXX`: **Credential Dumping (T1003.003)**

This query confirms the adversary successfully compromised the DC and exfiltrated the `ntds.dit` file, containing all domain user password hashes.

<img src=".assets/logscale-dc-query.png" width="800" alt="LogScale query showing ntdsutil and Invoke-WebRequest commands on the Domain Controller">
*<p align="center">Figure 4: The successful hunt for the attacker's final actions, confirming a full domain compromise.</p>*

---
##  Skills & Technologies Demonstrated

* **Incident Response (IR):** Executing a full-cycle IR process, from triage to evidence correlation and reporting.
* **Endpoint Detection & Response (EDR):** Using the **Falcon EDR** platform for process graph analysis and alert triage.
* **Log Analysis:** Authoring advanced **LogScale (KQL-style)** queries to hunt for and validate adversary activity.
* **Threat Hunting:** Proactively searching for TTPs in raw log data to build a complete attack timeline.
* **MITRE ATT&CK Framework:** Identifying and mapping adversary techniques (T1047, T1136, T1078, T1105, T1003).
* **Adversary Emulation:** Analyzing the TTPs of common tools like `wmiexec.py` and `ntdsutil`.
