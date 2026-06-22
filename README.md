# LetsDefend — Brute Force Attacks Challenge Walkthrough

## 📝 Executive Summary
This report documents the digital forensics and investigation of a brute-force attack campaign directed against a corporate web server and system infrastructure. By analyzing network packet captures (`BruteForce.pcap`) and system authentication records (`auth.log`), the investigation traces the attacker's footprints across different layers, uncovering the target server, web-based brute-force metrics, RDP reconnaissance, and the compromised credentials.

---

## 🛠️ Lab Setup & Data Extraction
Before beginning the investigation, the challenge files were provided in a compressed `.7z` archive. I utilized the Linux CLI to extract the dataset:

```bash
# Extracting the lab files using 7z
7z x ChallengeFile.7z -o./BruteForce_Lab
🔍 Investigation Tasks

Task 1: Identifying the Target Server IP
Question: What is the IP address of the server targeted by the attacker's brute-force attack?

Analysis & Methodology
To locate the target server, I analyzed the network traffic statistics within Wireshark by navigating to Statistics -> Conversations -> TCP.

By examining the connection frequencies and data volumes, a significant pattern emerged involving two primary hosts: 192.168.190.137 (Attacker) and 51.116.96.181 (Target). The host 192.168.190.137 initiated an anomalous number of parallel TCP connections across multiple source ports targeted at a single destination IP address. This behavior is indicative of automated scanning and brute-force traffic.

![the answer](./Screenshots/wireshark_conversations.png)
Answer: 51.116.96.181

Task 2: Investigating Web-Based Brute-Force Activity
Question: Which directory/file was targeted by the attacker's brute-force attempt?

Analysis & Methodology
To investigate potential web application attacks, I analyzed the HTTP traffic inside Wireshark by applying the protocol filter: http.

The packet capture revealed a dense stream of repetitive HTTP POST requests originating from the attacker's machine and directed toward the target web server. Looking closely at the Info column and the Hypertext Transfer Protocol breakdown (specifically frame 20947), the attacker was targeting the local directory file /index.php.

Further inspection of the HTML Form URL Encoded data within the packet details showed that these POST requests were automated login attempts transmitting credential payloads (e.g., username=t3m0&password=TestTest). This confirms that the web application's main index page was subjected to an aggressive credential-stuffing or brute-force campaign.

Answer: index.php

Task 3: Identifying Compromised Credentials
Question: Identify the correct username and password combination used for a successful login.

Solution Steps

Step 1: Identifying the Success Indicator
Instead of manually shifting through thousands of failed HTTP POST requests, the analysis was streamlined by searching for the server's success response within the HTML body.
Using Wireshark's Find Packet feature (Ctrl + F):

Search Type: String

Search In: Packet details

Search Term: >Correct</p> (The specific green HTML success message rendered by the application upon successful authentication).

Step 2: Locating the Successful HTTP Response
The search led directly to Frame 22249:

Protocol: HTTP

Status: HTTP/1.1 200 OK

Payload Contains: <p style='color: green;'>Correct</p> inside the response body.

Step 3: Extracting the Credentials
By tracing the associated HTTP POST request in Frame 22247 (linked via [Response in frame: 22249]), the raw URL-encoded form data was exposed:

Target URL: http://51.116.96.181/index.php

Form Data Found:

Form item: "username" = "web-hacker"

Form item: "password" = "admin12345"

Answer: web-hacker:admin12345

Task 4: Evaluating RDP Target Scope
Question: Determine how many unique user accounts the attacker attempted to compromise via RDP brute-force.

Solution Steps

Step 1: Tracking RDP Connection Attempts
By applying a network filter on the RDP protocol (tcp.port == 3389), we can intercept the RDP connection cookies (mstshash) initiated by the attacker. This initial sweep revealed a broad list of potential target names transmitted inside the packet capture (.pcap).

Step 2: Cross-Referencing Logs and Cross-Matching Names
To isolate the exact number of accounts targeted exclusively via RDP, a cross-match analysis was performed against the Linux host logs (auth.log):

Accounts such as mmox and web-hacker were heavily logged inside auth.log due to persistent, successful SSH/local logins, meaning they were active system accounts or part of a separate SSH/Web attack vector.

On the other hand, names unique to the RDP traffic (like Mohamed, Mohsen, and Ali) never showed up in the Linux authentication logs because their attempts were strictly bounded to the RDP network layer.

By filtering out the non-RDP related accounts and cross-matching the unique target sessions active over port 3389, the final count of unique user accounts targeted by the RDP brute-force attack is exactly 7.

Answer: 7

Task 5: Identifying the Attacker's Machine (clientName)
Question: Find the explicit "clientName" of the attacker's machine used during the RDP connection attempts.

Solution Steps

Step 1: Filtering for RDP Client Data
During an RDP connection handshake, the client machine transmits its local system metadata (such as hostname, keyboard layout, and display resolution) to the target server inside a specific data structure called clientCoreData.
To locate this information efficiently within Wireshark, the main RDP port traffic was isolated, and a specific string search was conducted:

Display Filter: tcp.port == 3389

Search Feature (Ctrl + F):

Search Type: String

Search In: Packet details

Search Term: clientname

Step 2: Extracting the Hostname Metadata
The search feature pointed directly to Frame 23 (Protocol: RDP / Info: ClientData):
Expanding the packet details tree reveals the underlying layers: Remote Desktop Protocol -> clientCoreData.
Inside the parsed core attributes, the server successfully decoded the attacker's local workstation name parameter:

Parameter: clientName

Value: t3m0-virtual-ma

Answer: t3m0-virtual-ma

Task 6: SSH Last Successful Login Analysis
Question: Identify the user who last successfully logged in via SSH and the exact timestamp of the event.

Solution Steps

Step 1: Filtering the Linux Authentication Logs
The Linux authentication log file (auth.log) natively records all system login activities. To track down successful interactive sessions over SSH, we look for the system keyword Accepted.
Using the Linux terminal, a targeted string isolation was performed on the log file:

Bash
cat auth.log | grep -i "Accepted"
Step 2: Parsing the Timestamps and User Sessions
The command output produced a historical log list of successful logins. Since the log entries are appended sequentially over time (chronological order), the very last line of the output represents the latest chronological event.
Navigating to the bottom-most log entry reveals the final recorded session:

Plaintext
Feb 25 11:43:54 chall sshd[981]: Accepted password for mmox from 41.38.160.33 port 54464 ssh2
Extracting the required parameters from this specific line:

Username: mmox

Timestamp: 11:43:54 (HH:MM:SS)

Answer: mmox:11:43:54

Task 7: Counting Unsuccessful SSH Connection Attempts
Question: Determine the total number of unsuccessful SSH connection attempts made by the attacker against the system.

Solution Steps

Step 1: Crafting the Log Query
Linux systems log every failed SSH authentication milestone into /var/log/auth.log under distinct patterns generated by the SSH daemon (sshd). When an attacker performs a password brute-force attack, each incorrect guess generates an explicit entry stating Failed password for.
To accurately count these events, we combine text filtering tools (grep) with a word/line counting utility (wc) via the Linux terminal:

Bash
cat auth.log | grep -i "sshd" | grep -i "failed password for" | wc -l
Step 2: Analyzing the Command Breakdown

cat auth.log: Reads and streams the entire authentication log file.

grep -i "sshd": Isolates traffic specifically belonging to the Secure Shell Daemon process.

grep -i "failed password for": Filters out noise and matches only the explicit rows where a password attempt was rejected.

wc -l: Counts the total number of lines returned after passing through the filters.

Step 3: Extracting the Metric
Executing the piped command instantly parses the records and returns the total line count:

Output Result: 7480

Answer: 7480

Task 8: Mapping to MITRE ATT&CK Framework
Question: Identify the specific MITRE ATT&CK technique ID used by the attacker to gain initial access to the system.

Solution Steps

Step 1: Analyzing Attack Patterns
Throughout the forensic investigation of both the packet capture (BruteForce.pcap) and system logs (auth.log), a consistent and automated pattern was observed:

Over 7,480 failed password attempts directed at the SSH service.

Multiple parallel connection sweeps targeted at the web interface and RDP services using extensive lists of usernames and potential passwords.
This systematic guessing of credentials to force entry into legitimate accounts is classified universally under credential stuffing or brute-forcing.

Step 2: Mapping to MITRE ATT&CK Matrix
According to the MITRE ATT&CK Framework, tactics that involve an adversarial attempt to access accounts by systematically cycling through passwords fall under the Initial Access or Credential Access tactics:

Main Technique: Brute Force

MITRE ID: T1110

Answer: T1110