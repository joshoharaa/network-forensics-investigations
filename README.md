# Network-Forensics-Investigations

## Scenario

A user reported abnormal system behaviour shortly after clicking a link contained within an email. The original email was unavailable; however, the link click reportedly occurred on 2023-12-15 shortly after 16:00 UTC.

Packet capture (PCAP) data was available for analysis, and the objective of this investigation is to determine what occurred following the reported interaction. 

### Investigation Constraints 

- No access to SIEM or centralised log sources
- Analysis limited strictly to the provided PCAP

--- 

## Investigation Summary

Between **2023-12-15 16:01:57 UTC and 17:09:20 UTC**, host 10.12.15.101 exhibited a rapid sequence of DNS resolution and encrypted outbound communication following the reported link click.

At **16:05:18 UTC**, the host resolved multiple domains: 

- ionister[.]com
- keebling[.]com
- baumbachers[.]com

Threat intelligence sources classify these domains as associated with phishing infrastructure. Within one second of resolution, encrypted outbound **TLS** connections were initiated to the corresponding IP addresses. 

The rapid sequence of DNS resolution followed by immediate encrypted communication indicates automated execution rather than user-driven browsing and is consistent with malware staging or command-and-control behaviour. 

Based on the available network evidence, host **10.12.15.101** should be treated as compromised pending full endpoint investigation. 

--- 

## Key Timeline of Events
- **~16:00 UTC** - User reports clicking email link
- **16:01:57 UTC** - Packet capture begins
- **16:02:02 UTC** - File downloaded from 'jinjadiocese[.]com' via HTTP
- **16:05:17 UTC** - DNS query for 'ionister[.]com'
- **16:05:17 UTC** - DNS query for 'keebling[.]com'
- **16:05:17 UTC** - DNS query for 'baumbachers[.]com'
- **16:05:18 UTC** - TLS Client Hello to 66.42.96.18 ('ionister[.]com')
- **16:05:18 UTC** - TLS Client Hello to 45.77.85.150 ('keebling[.]com')
- **16:05:18 UTC** - TLS Client Hello to 207.246.75.243 ('baumbachers[.]com')
- **Post-16:05 UTC** - Sustained outbound encrypted communication observed
- **17:09:20 UTC** - Packet capture ends

---

## Incident Overview 

### WHO
**Users / Accounts Involved:** 
No user account information was available within the PCAP. 

--- 

### WHAT 
Suspected malware execution following a clicked link within a phishing email. 

An exported file recovered from network traffic was flagged as malicious by 28 security vendors. The file download aligns temporally with the reported email interaction. 

### WHERE  
**Host / System Affected:** 
10.12.15.101 

--- 

### WHY 
Based on: 

- Automated DNS resolution patterns
- Immediate TLS-encrypted outbound connections
- Timing correlation with suspected user interaction
- Communication with domains identified as malicious

The observed behaviour is consistent with initial command-and-control or staging communication. 

--- 

### HOW
As shown in the timeline, the host resolved multiple phishing-associated domains and immediately initiated encrypted outbound connections. 

The rapid DNS → TLS transition is characteristic of non-interactive execution behaviour commonly observed during malware staging. Network evidence demonstrates a clear progression from HTTP payload delivery to automated outbound encrypted communication with malicious infrastructure.

--- 

### MITRE ATT&CK Mapping 

- **T1566 - Phishing**

--- 

## Verdict

Host **10.12.15.101** demonstrated automated DNS resolution followed by immediate encrypted communication with domains identified as phishing infrastructure shortly after a user-reported link click. 

The timing correlation, automated connection pattern, and malicious domain reputation strongly indicate execution of malicious code and probable initiation of command-and-control (C2) or staging communication. 

Based on the available network evidence, the host should be considered **compromised** pending full endpoint investigation. 

**Confidence Level:** Moderate to High
*(Limited by encrypted traffic visibility.)*

--- 
## Recommendations 

1. **Identify and isolate additional affected hosts**
   - Determine whether other internal systems have communicated with the identified indicators
   - Contain any additional compromised hosts.

2. **Investigate email distribution**
   - Identify the originating email and message ID.
   - Determine whether the phishing email was delivered to other users.
   - Remove the message and block sender/infrastructure as appropriate. 
3. **Perform controlled detonation**
   - Conduct behavioural analysis of the identified file in a sandboxed environment.
   - Document observed capabilities and persistence mechanisms.
4. **Conduct full endpoint remediation**
   - Remove malware and validate system integrity.
   - Reset credentials associated with the affected user.
   - Review for persistence mechanisms and lateral movement indicators.
  
---
  
  ## Indicators of Compromise (IOCs) 

  | Type      | Indicator |
|-----------|----------|
| Domain    | `ionister[.]com` |
| Domain    | `keebling[.]com` |
| Domain    | `baumbachers[.]com` |
| IP        | 66.42.96.18 |
| IP        | 45.77.85.150 |
| IP        | `07.246.75.243 |
| SHA256    | `F24888DA47BAE0149AB5C0D887D32FC155CB42AC8138D22699AE12CE1DCA6BD1` |

---
## File Evidence

During analysis, a file was directly recovered from network traffic using **Wireshark -> Export Objects -> HTTP**. 

**Recovered File Details:** 
- **Filename:** `%3fzKGIWQwzp=1702656118`
- **SHA256:** `F24888DA47BAE0149AB5C0D887D32FC155CB42AC8138D22699AE12CE1DCA6BD1`

The SHA256 hash is classified as malicious by multiple security vendors and linked to phishing-delivered malware campaigns.

The download occurred shortly before: 

- The DNS resolution bursts
- Immediate outbound TLS connections
- Continued encrypted communication

The tight temporal correlation supports the conclusion that the recovered file initiated the observed automated execution and outbound communication.

---

## Investigation Methodology

### 1. Establish Investigation Scope and Timeline 

The packet capture was reviewed to determine the observation window of network activity. 

- **First Packet Observed:** 2023-12-15 16:01:57 UTC
- **Last Packet Observed:** 2023-12-15 17:09:20 UTC
- **Total Duration:** ~1 hour 7 minutes

This timeframe aligns with the user-reported suspicious activity occurring shortly after 16:00 UTC. 

<img width="512" height="480" alt="wireshark ref 1" src="https://github.com/user-attachments/assets/fa9ca4ba-8556-43d5-afa9-80fa2a820fe4" />

**Figure 1:** Capture file properties showing investigation time frame (16:01:57-17:09:20 UTC)

---

### 2. Identify Dominant Network Behaviour

Protocol hierarchy analysis was conducted to determine the distribution of network protocols within the capture. The analysis showed that **TLS traffic accounted for approximately 92% of total bytes**, indicating that the majority of communications were encrypted. This significantly limited deep packet inspection and required behavioural and metadata-based analysis (e.g., DNS timing correlation and TLS SNI extraction). 

<img width="512" height="123" alt="wireshark ref 2" src="https://github.com/user-attachments/assets/98406629-8e5d-4b39-881d-0b7102a231e8" />

*Figure 2 - Protocol Hierarchy statistics showing TLS as the dominant protocol (~92% of total bytes), indicating primarily encrypted communication.*

---

### 3. Identify Suspicious Hosts and External Infrastructure

Conversations analysis was performed to identify the most active communication pairs within the capture. 

The internal host **10.12.15.101** demonstrated significant encrypted communication with the following external IP addresses: 

- 66.42.96.18
- 207.246.75.243
- 45.77.85.150

All observed communications occurred over **TCP 443 (TLS)**. 

The concentration of outbound encrypted traffic to a small set of external IP addresses, particularly following the reported user interaction, warranted further investigation into potential command-and-control or staging activity. 

<img width="512" height="319" alt="wireshark ref 3" src="https://github.com/user-attachments/assets/2bbd3959-2d6c-4c94-9f09-7137212243a6" />

*Figure 3 - Wireshark TCP conversation analysis highlighting significant outbound encrypted communication from internal host 10.12.15.101 to multiple external IP addresses over TCP 443 (TLS). The volume and repetition of traffic to a limited set of external hosts indicates potential command-and-control or staging activity.* 

--- 

### 4. Extract Domain Indicators from TLS Traffic 

Network evidence demonstrates a clear progression from HTTP payload delivery to automated outbound encrypted communication with malicious infrastructure.

The timing correlation, malicious domain reputation, and threat intelligence validation of the recovered file collectively support the conclusion that host 10.12.15.101 was compromised during the observed timeframe.

The host should be treated as compromised and isolated immediately pending full forensic examination.

**Confidence Level:** Moderate to High  
(Limited by encrypted traffic visibility.)
<img width="512" height="44" alt="wireshark 4" src="https://github.com/user-attachments/assets/c24f665e-8c69-4104-af29-f3a5f56ce0b8" />

*Figure 4 - TLS Client Hello packets from 10.12.15.101 at 16:05:18 UTC showing SNI values for ionister[.]com, keebling[.]com, and baumbachers[.]com. These connections immediately followed DNS resolution and indicate automated outbound staging or command-and-control communication.*

### 5. Correlate DNS Activity with TLS Connections

DNS traffic was analysed to determine when the suspicious domains were resolved and how resolution timing aligned with subsequent encrypted communication. 

The following domains were resolved at **16:05:18 UTC**: 

- ionister[.]com
- keebling[.]com
- baumbachers[.]com

Within **one second** of resolution, TLS Client Hello packets were initiated to the corresponding IP addresses. 

This rapid DNS -> TLS execution sequence strongly indicates automated behaviour consistent with malware execution rather than manual user browsing. 

Additionally, several randomly generated '.dat' domains returned **NXDOMAIN** responses. This behaviour suggests possible fallback mechanisms or automated domain generation attempts, further supporting malicious execution activity. 

<img width="512" height="216" alt="wireshark ref 5" src="https://github.com/user-attachments/assets/0e8e7406-83c7-4674-a2fa-a5826a6c1e9c" />

*Figure 5 - DNS responses resolving ionister[.]com, keebling[.]com, and baumbachers[.]com at 16:05:18 UTC, immediately preceding outbound TLS connections. The tight timing correlation is characteristic of staging activity.* 

--- 

### 6. Identify Initial File Download 

HTTP traffic preceding the DNS resolution burst was examined using **Wireshark -> Export Objects -> HTTP** to determine whether an initial payload delivery occurred. 

Analysis revealed that host **10.12.15.101** downloaded a file from: 

- 'jinjadiocese[.]com'

This activity occured prior to the suspicious DNS resolution burst and subsequent encrypted TLS communication, indicating likely initial payload delivery. 

The timing sequence suggests: 

HTTP payload download -> execution -> automated outbound staging communication

<img width="512" height="284" alt="wireshark 6" src="https://github.com/user-attachments/assets/aefbb135-f863-46f9-afbc-0678148b08ad" />

*Figure 6 - HTTP GET request from 10.12.15.101 to jinjadiocese[.]com requesting the malicious payload prior to DNS and TLS activity. The tight temporal correlation supports execution of the downloaded payload.* 

---

### 7. Correlate Download → Execution → Encrypted Communication

Following payload retrieval, host 10.12.15.101 exhibited a distinct burst of automated network activity:

- DNS resolution of multiple phishing-associated domains  
- Immediate TLS Client Hello initiation to corresponding IP addresses  
- Sustained outbound encrypted communication over TCP 443  

The tight temporal correlation between these events strongly supports execution of the downloaded payload and initiation of staging or command-and-control communication.

<img width="512" height="53" alt="wireshark screenshot 2802" src="https://github.com/user-attachments/assets/de3788f1-8480-421a-bf2e-f89a39058f39" />

*Figure 7A – HTTP GET request from 10.12.15.101 retrieving payload from jinjadiocese[.]com, preceding automated DNS and TLS activity.*

<img width="512" height="274" alt="wireshark 2802 1" src="https://github.com/user-attachments/assets/edcadbf4-ac0c-4b1b-b18b-db59339220ac" />

*Figure 7B - Subsequent DNS resolution burst followed immediately by TLS Client Hello packets to phishing-associated domains. The tight correlation suggests non-interactive execution behaviour.*

---

### 8. File Validation and Threat Intelligence Correlation

The recovered file was analysed locally to confirm its integrity and assess its reputation. 

A **SHA256 hash** was generated from the extracted file and submitted to multiple threat intelligence sources for validation. 

- **Filename:** `%3fzKGIWQwzp=1702656118`
- **SHA256:** `F24888DA47BAE0149AB5C0D887D32FC155CB42AC8138D22699AE12CE1DCA6BD1`

Threat intelligence results indicated that the file is flagged as malicious by multiple security vendors and is associated with phishing-delivered malware campaigns. 

This validation confirms that the downloaded file represents the initial payload. 

Its execution directly preceded the automated DNS resolution and encrypted outbound communication observed during the investigation.

<img width="512" height="118" alt="wireshark 7 " src="https://github.com/user-attachments/assets/13ec4cef-fb88-49f2-8d1e-194c3bce2f2d" />

*Figure 8A - Malicious file recovered from network traffic using **Wireshark -> Export Objects -> HTTP**, confirming successful payload retrieval from the identified infrastructure.*

<img width="512" height="108" alt="wireshark 8 " src="https://github.com/user-attachments/assets/a2650c92-3689-42b8-9788-b8d551f68f31" />

*Figure 8B - SHA256 hash calculated locally from the recovered file to verify integrity and enable submission to threat intelligence platforms for reputation analysis.* 

<img width="512" height="291" alt="wireshark osint" src="https://github.com/user-attachments/assets/3b58a8a3-60d5-4727-8ae8-d3efded420fc" />

*Figure 8C - Threat intelligence analysis results showing the recovered file flagged as malicious by multiple security vendors, confirming its association with phishing-delivered malware campaigns.* 
