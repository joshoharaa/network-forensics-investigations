# Network-Forensics-Investigations

## Scenario

A client reported that their computer began behaving abnormally after clicking on a link in an email. The exact email is unavailable; however, the client stated that the client stated that the link was clicked on ** December 15th, 2023**, shortly after **16:00 UTC**.

Packet capture (PCAP) data was available for analysis, and the objective of this investigation is to determine what occured following the reported interaction. 

### Investigation Constraints 

- No access to SIEM to centralised log sources
- Analysis limited strictly to the provided PCAP

--- 

## Investigation Summary

Between **2023-12-15 16:01:57 UTC** and **17:09:20 UTC**, host **10.12.15.101** exhbiited abnormal network behaviour shortly after a user-reported link click. 

At **16:05:18 UTC**, the host resolved multiple domains: 

- ionister[.]com
- keebling[.]com
- baumbachers[.]com

These domains are flagged by multiple security vendors for phishing activity. Within one second of resolution, encrypted outbound **TLS** connections were initiated to the corresponding IP addresses. 

The rapid sequence of DNS resolution followed by immediate encrypted communication indicates automated execution rather than user-driven browsing and is consistent with malware staging or command-and-conrol behaviour. 

Based on the available network evidence, host **10.12.15.101** is likely compromised pending further endpoint investigation. 

--- 

## Key Timeline of Events
- **~16:00 UTC** - User reports clicking link in email (external context)
- **16:01:57 UTC** - Packet cpature begins
- **16:02:02 UTC** - File downloaded from 'jinjadiocse[.]com' via HTTP
- **16:05:17 UTC** - DNS query for 'ionister[.]com'
- **16:05:17 UTC** - DNS query for 'keebling[.]com'
- **16:05:17 UTC** - DNS query for 'baumbachers[.]com'
- **16:05:18 UTC** - TLS Client Hello to '66.42.96.18' ('ionister[.]com')
- **16:05:18 UTC** - TLS Client Hello to '45.77.85.150' ('keebling[.]com')
- **16:05:18 UTC** - TLS Client Hello to '207.246.75.243'('baumbachers[.]com')
- **Post-16:05 UTC** - Continued encrypted outbound traffic observed
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
19.12.15.101 

--- 

### WHY 
Based on: 

- Automated DNS resolution patterns
- Immediate TLS-encrypted outbounf connections
- Timing correlation with suspected user interaction
- Communication with domains identified as malicious

The observed behaviour is consistent with initial with command-and-control or staging communication. 

--- 

### HOW
As shown in the timeline, the host resolved multiple phishing-associated domains and immediately initiated encrypted outbound connections. 

This rapid DNS -> TLS sequence strongly indicates automated execution consistent with malware staging or command-and-control behaviour. 

--- 

### MITRE ATT&CK Mapping 

- **T1566 - Phishing**

--- 

## Verdict

Host **10.12.15.101** demonstrated automated DNS resolution followed by immediate encrypted communication with domains identified as phishing infrastructure shortly after a user-reported link click. 

The timing correlation, automated connection pattern, and maliicous domain reputation strongly indicate execution of malicious code and probable of initial command-and-control or staging communication. 

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
   - Condut behavioural analysis of the identified file has in a sandboxed environments.
   - Document observed capabilities and persistence mechanisms.
4. **Conduct full endpoint remediation**
   - Remove malware and validate system integrity.
   - Reset credentials associated with the affected user.
   - Review for persistence mechanisms and lateral movement indicators.
  
  ## Indicators of Compromise (IOCs) 

  | Type      | Indicator |
|-----------|----------|
| Domain    | `ionister[.]com` |
| Domain    | `keebling[.]com` |
| Domain    | `baumbachers[.]com` |
| IP        | `66.42.96.18` |
| IP        | `45.77.85.150` |
| IP        | `207.246.75.243` |
| SHA256    | `F24888DA47BAE0149AB5C0D887D32FC155CB42AC8138D22699AE12CE1DCA6BD1` |

## File Evidence

During analysis, a file was directly recovered ffrom network traffic using **Wiresh






