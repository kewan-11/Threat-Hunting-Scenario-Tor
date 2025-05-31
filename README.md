<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/kewan-11/Threat-Hunting-Scenario-Tor/blob/main/threat-hunting-scenario-tor-event-creation.md)

## Platforms and Languages Leveraged
- Windows 10 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched the DeviceFileEvents table for ANY file that had the string “tor” in it and discovered what looks like the user “employee” downloaded a tor installer did something that resulted in many tor-related files being copied to the desktop and the creation of a file called “tor- shopping-list.txt” on the desktop. These events begin at: 2025-05-29T22:55:48.1675948Z.

**Query used to locate events:**

```kql
DeviceFileEvents
| where DeviceName == "threathuntlab"
| where InitiatingProcessAccountName == "labuser"
| where FileName contains "tor"
| order by Timestamp desc
| where Timestamp >= datetime(2025-05-29T22:55:48.1675948Z)
| order by Timestamp desc
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1444" alt="image" src="https://github.com/user-attachments/assets/bdce998f-9973-4027-83d0-22a30faa67cd" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched the DeviceProcessEvents table for any ProcessCommandLine that contained the string “tor-browser-windows-x86_64-portable-14.5.3.exe.” Based on the logs returned at 2025-05-29T22:55:48.1675948Z, an employee on the "threathuntlab" device ran the file tor-browser-windows-x86_64-portable-14.5.3.exe from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql

DeviceProcessEvents
| where DeviceName == "threathuntlab"
| where ProcessCommandLine contains "tor-browser-windows-x86_64-portable-14.5.3.exe”
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1458" alt="image" src="https://github.com/user-attachments/assets/7c3323d3-a678-4226-9bd0-757492ebd807" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched the DeviceProcessEvents table for identification the user “employee” actually opened the tor browser. There was evidence that they did open it at 2025-05-29T22:55:48.1675948Z. There several other instances of firefox.exe (Tor) as well as tor.exe spawned.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "threathuntlab"
| where FileName has_any ("tor.exe", "firefox.exe", "tor-browser.exe")
| project Timestamp, DeviceName, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| order by Timestamp desc
```
<img width="1452" alt="image" src="https://github.com/user-attachments/assets/87189742-d371-4974-8d84-592665950bbd" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

Searched the DeviceNetworkEvents table for any indication the tor browser was used to establish a connection using any of the known tor ports. at 2025-05-29T22:55:48.1675948Z, an employee on the "threat-hunt-lab" device successfully established a connection to the remote IP address 176.198.159.33 on port 9001. The connection was initiated by the process tor.exe. located in the folder c: users\emplovee\desktop\tor\browser\browser\tor\browser\tor\tor.exe. There were a couple other connections to sites over port 443 as well. 

**Query used to locate events:**

```kql
DeviceNetworkEvents
| where DeviceName == "threathuntlab"
| where InitiatingProcessAccountName != "system"
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")
| where RemotePort in ("9001", "9030", "9048", "9050", "9051", "9150", "80", "443")
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemoteUrl, InitiatingProcessFileName
| order by Timestamp desc
```
<img width="1453" alt="image" src="https://github.com/user-attachments/assets/27179e12-7fb9-4ae3-a8ee-e2a75c8f3aca" />

---

## Chronological Event Timeline 

1. File Download - Tor Installer
○ Timestamp: 2025-05-29T22:55:48.1675948Z
○ Event: The user “employee” downloaded a file named tor-browser-windows-x86_64-portable-14.0.1.exe to the Downloads folder.
○ Action: File download detected.
○ File Path: C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe

2. Process Execution - Tor Browser Installation
○ Timestamp: 2025-05-29T22:55:48.1675948Z
○ Event: The user “employee” executed the file tor-browser-windows-x86_64-portable-14.0.1.exe in silent mode, initiating a background installation of the Tor Browser.
○ Action: Process creation detected.
○ Command: tor-browser-windows-x86_64-portable-14.0.1.exe /S
○ File Path: C:\Users\employee\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe

3. Process Execution - Tor Browser Launch
○ Timestamp: 2025-05-29T22:55:48.1675948Z
○ Event: User “employee” opened the Tor browser. Subsequent processes associated with Tor browser, such as firefox.exe and tor.exe, were also created, indicating that the browser launched successfully.
○ Action: Process creation of Tor browser-related executables detected.
○ File Path: C:\Users\employee\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe

4. Network Connection - Tor Network
○ Timestamp: 2025-05-29T22:55:48.1675948Z
○ Event: A network connection to IP 176.198.159.33 on port 9001 by user “employee” was established using tor.exe, confirming Tor browser network activity.
○ Action: Connection success.
○ Process: tor.exe
○ File Path: C:\Users\employee\desktop\tor browser\browser\torbrowser\tor\tor.exe

5. Additional Network Connections - Tor Browser Activity
○ Timestamps:
▪ 2025-05-29T22:55:48.1675948Z – Connected to 194.164.169.85 on port 443.
▪ 2025-05-29T22:55:48.1675948Z – Local connection to 127.0.0.1 on port 9150.
○ Event: Additional Tor network connections were established, indicating ongoing activity through the Tor browser.
○ Action: Multiple successful connections detected.

6. File Creation - Tor Shopping List
○ Timestamp: 2025-05-29T22:55:48.1675948Z
○ Event: The user “employee” created a file named tor-shopping-list.txt on the desktop, potentially indicating a list or notes related to their Tor browser activities.
○ Action: File creation detected.
○ File Path: C:\Users\employee\Desktop\tor-shopping-list.txt

---

## Summary

The user "employee" on the "threat-hunt-lab" device initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `threat-hunt-lab` by the user `employee`. The device was isolated, and the user's direct manager was notified.

---
