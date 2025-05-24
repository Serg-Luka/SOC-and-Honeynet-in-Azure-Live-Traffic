# ☁️🍯 Honeypot Deployment and Real-Time Attack Analysis in Azure SOC Environment

## Lab Overview

In this lab, I deployed a virtual machine in Microsoft Azure and deliberately exposed it to the public internet to act as a honeypot. The aim was to attract real-world cyber-attacks and monitor them in real time. I configured the virtual machine to send security logs, including failed sign-in attempts and other suspicious activity, to a Log Analytics Workspace. This workspace was connected to Microsoft Sentinel, Azure’s cloud-native SIEM (Security Information and Event Management) solution, where I queried and investigated the collected data. To visualise the activity, I created an attack map within Microsoft Sentinel, showing the geographical locations of the IP addresses targeting the honeypot. This lab provided valuable insight into how quickly exposed systems are discovered and attacked on the internet, as well as hands-on experience with Azure security tools and threat detection.

# 🌟 Table of Contents 🌟

- [Part 1️⃣. Azure Subscription Setup](#part-1-azure-subscription-setup)
  - [Part 1.1: Signing up](#part-11-signing-up)
  - [Part 1.2: Accessing Azure Portal](#part-12-accessing-azure-portal)
  - [Part 1.3: Configured Cost Management alerts to monitor usage](#13-configured-cost-management-alerts-to-monitor-usage)
- [Part 2️⃣. Azure Honeypot Infrastructure Configuration](#part-2-azure-honeypot-infrastructure-configuration)
  - [Part 2.1: Creating a Resource Group](#part-21-creating-a-resource-group)
  - [Part 2.2: Creating a Virtual Network](#part-22-creating-a-virtual-network)
  - [Part 2.3: Creating a Honeypot Virtual Machine](#part-23-creating-a-honeypot-virtual-machine)
  - [Part 2.4: Configuring NSG](#part-24-configuring-nsg)
  - [Part 2.5: Weakening VM’s Security](#part-25-weakening-vms-security)
  - [Part 2.6: Checking Connectivity](#part-26-checking-connectivity)
- [Part 3️⃣. Logging into the VM and inspecting logs](#part-3-logging-into-the-vm-and-inspecting-logs)
- [Part 4️⃣. Log Forwarding and Log Analytics](#part-4-log-forwarding-and-log-analytics)
  - [Part 4.1: Created Log Analytics Workspace in Azure](#part-41-created-log-analytics-workspace-in-azure)
  - [Part 4.2: Created a Sentinel Instance & Connected Log Analytics](#part-42-created-a-sentinel-instance--connected-log-analytics)
  - [Part 4.3: Configuring Windows Security Events via AMA](#part-43-configuring-windows-security-events-via-ama)
  - [Part 4.4: Observing Logs in Log Analytics](#part-44-observing-logs-in-log-analytics)
- [Part 5️⃣. Log Enrichment and Finding Location Data](#part-5-log-enrichment-and-finding-location-data)
  - [Part 5.1: Observing Logs with Geographic Information](#part-51-observing-logs-with-geographic-information)
  - [Part 5.2: Validating Geolocation Accuracy](#part-52-validating-geolocation-accuracy)
- [Part 6️⃣. Attack Map Creation](#part-6-attack-map-creation)
  - [Part 6.1: Attack Map Visualised](#part-61-attack-map-visualised)
  - [Part 6.2: Analysis of Observed Activity](#part-62-analysis-of-observed-activity)
  - [Part 6.3: Threat Intelligence Correlation and MITRE ATT&CK Mapping](#part-63-threat-intelligence-correlation-and-mitre-attck-mapping)
- [Part 7️⃣. Ethical Considerations and Cleanup](#part-7-ethical-considerations-and-cleanup)
  - [Part 7.1: Ethical Considerations](#part-71-ethical-considerations)
  - [Part 7.2: Deleted All Resources to Avoid Charges](#part-72-deleted-all-resources-to-avoid-charges)
- [Part 8️⃣. Lab Conclusion](#part-8-lab-conclusion)

## Part 1. Azure Subscription Setup

### Part 1.1: Signing up

<img src="https://i.imgur.com/acJlbm1.png">

<img src="https://i.imgur.com/fweFXz3.png">

I created a free Azure subscription using the free credits: https://azure.microsoft.com/en-us/pricing/purchase-options/azure-account

---

### Part 1.2: Accessing Azure Portal

<img src="https://i.imgur.com/Qfck8QQ.png">

After my subscription was created, I was able to log in at: https://portal.azure.com

---

### 1.3: Configured Cost Management alerts to monitor usage.

<img src="https://i.imgur.com/oCYpOFr.png">
<img src="https://i.imgur.com/VC9QSDy.png">

I navigated to Cost Management in Azure and set up a budget to monitor my spending. I named it "pot Lab Budget," with a monthly reset, starting on 14 May 2025 and expiring on 30 April 2027. I allocated £50 as the budget amount. Then, I configured alerts based on actual costs, setting thresholds at 50%, 75%, and 100%, and added my email for notifications. This ensured I was promptly informed of my usage, helping me manage my free Azure credits effectively during the lab.

---

## Part 2. Azure pot Infrastructure Configuration

### Part 2.1: Creating a Resource Group

<img src="https://i.imgur.com/2utLlTe.png">

I went to https://portal.azure.com and created a resource group.

---

<a id="part-2-azure-honeypot-infrastructure-configuration"></a>
### Part 2.2: Creating a Virtual Network

<img src="https://i.imgur.com/pmVOOY6.png">

Created a new VNet for my resource group and used the same region.

---

<a id="part-23-creating-a-honeypot-virtual-machine"></a>
### Part 2.3: Creating a pot Virtual Machine

<img src="https://i.imgur.com/VuibYQk.png">

I deployed a new virtual machine to act as a pot for this lab and added it to the existing resource group. To avoid raising suspicion, I assigned it a generic name **"CORP-NET-SOUTH-1"** to mimic a typical corporate endpoint. I selected **Windows 10 Pro** as the operating system, configured the appropriate storage, and set up login credentials. During the final stages of deployment, I connected the VM to the virtual network (VNet) that I had previously configured.

**Note:** I selected Windows 10 Pro as the operating system due to its widespread use in corporate environments, making it a realistic target for attackers seeking to exploit common endpoints.

---

### Part 2.4: Configuring NSG 

<img src="https://i.imgur.com/eBpFl3l.png">

I deliberately configured the Network Security Group (NSG) rules to weaken the virtual machine’s security posture, making it more enticing for potential attackers to target. As shown in the screenshot, I created a custom inbound rule named "DANGER_AllowAnyCustomAnyInbound" with the source set to ‘Any’, destination set to ‘Any’, and port range left open, effectively allowing all inbound traffic on any protocol and any port. This level of exposure removes nearly all network-level protections and simulates a misconfigured or poorly secured VM—conditions that often attract malicious scans and intrusion attempts in real-world environments.

---

### Part 2.5: Weakening VM’s Security

<img src="https://i.imgur.com/lBC18Gt.png">

I turned off the virtual machine’s firewall. 

---

### Part 2.6: Checking Connectivity

<img src="https://i.imgur.com/5BI4IIu.png">

I pinged the virtual machine’s public IP from my home PC to make sure that the virtual machine can be connected over the internet. This is to make sure that an attacker can also access the machine. 

---

## Part 3. Logging into the VM and inspecting logs

<img src="https://i.imgur.com/BWtx9EF.png">

I intentionally failed three login attempts using the “employee” account (which doesn’t exist) to generate security event logs on the virtual machine for analysis and to make sure that everything was being logged correctly. 

<img src="https://i.imgur.com/29OLatn.png">

I filtered the Event Viewer for Event **ID 4625** and confirmed that the failed login attempt was successfully logged within the virtual machine.

---

## Part 4. Log Forwarding and Log Analytics 

### Part 4.1. Created Log Analytics Workspace in Azure

<img src="https://i.imgur.com/eSnWiZi.png">

I created a **Log Analytics Workspace** and added it to the existing resource group for centralised log management and analysis.

---

### Part 4.2. Created a Sentinel Instance & Connected Log Analytics

<img src="https://i.imgur.com/LjJ4otB.png">

Within the **Microsoft Sentinel Content Hub**, I searched for **“Windows Security Events”** and installed the corresponding solution. This content pack includes prebuilt analytics rules, workbooks, and data connectors specifically designed to monitor and analyse Windows security logs.
Installing this solution helps streamline the detection of suspicious activity such as failed logins, privilege escalation, and other potential threats. It enhances visibility into Windows-based systems and supports effective threat detection and incident response within Microsoft Sentinel.

---

### Part 4.3. Configuring Windows Security Events via AMA

<img src="https://i.imgur.com/nGa2Hv8.png">

Created a data collection rule within Windows Security Events via AMA so that my virtual machine can forward logs towards the Azure Log Analytics which can then be accessed through our SIEM (Sentinel). 

<img src="https://i.imgur.com/1EWlIOx.png">

I confirmed that the Azure Monitoring Agent was installed.

---

### Part 4.4. Observing Logs in Log Analytics 

<img src="https://i.imgur.com/ihVBkNw.png">

Within just 15 minutes of enabling log monitoring in Azure, my virtual machine recorded nearly 2,000 access attempts from the public internet—highlighting how quickly exposed systems can become targets.

**KQL Query Used:**

```
SecurityEvent
| where EventID == 4625
| summarize FailedLoginAttempts = count() by IpAddress
```

This KQL command filters the SecurityEvent log for failed login attempts (Event ID 4625). It then counts how many times each unique IP address triggered a failed login and displays the total per IP.

--- 

## Part 5. Log Enrichment and Finding Location Data

<img src="https://i.imgur.com/nppHhb6.png">

I uploaded a CSV file named ```geoip-summarized.csv``` into Microsoft Sentinel’s Watchlist wizard to create a custom geolocation watchlist. The file maps IP ranges to locations—such as countries, cities, and coordinates—with a preview shown in the screenshot above. I chose "Local file" as the source and set the network column as the SearchKey, enabling Sentinel to match IPs from security logs with their geographic data. This enrichment adds real-world context to suspicious activity, helping pinpoint where threats are coming from and strengthening investigation efforts.

--- 

### Part 5.1. Observing Logs with Geographic Information

<img src="https://i.imgur.com/GUc1pMh.png">

First, I identified all the IP addresses that tried accessing my pot virtual machine. 

**KQL Query Used:**

```
SecurityEvent
| where EventID == 4625
| where isnotempty(IpAddress)
| summarize FailedLogonCount = count(), AccountNames = makeset(TargetUserName, 100) by IpAddress
| sort by FailedLogonCount desc
```

<img src="https://i.imgur.com/uRHdT3V.png">

After identifying one of the IP addresses, in this case, **41.143.19.219**, I ran the following KQL query to retrieve the associated city and country information. This was made possible by a prior step, where I uploaded a watchlist to Microsoft Sentinel that maps IP addresses to their corresponding geographic locations. This now allows me to see where the attacks are coming from.

**KQL Query Used:**

```
let GeoIPDB_FULL = _GetWatchlist("geoip");
let WindowsEvents = SecurityEvent
    | where IpAddress == "41.143.19.219"
    | where EventID == 4625
    | order by TimeGenerated desc
    | evaluate ipv4_lookup(GeoIPDB_FULL, IpAddress, network);
WindowsEvents
```

---

### Part 5.2. Validating Geolocation Accuracy

<img src="https://i.imgur.com/X3iFgh3.png">

To validate the geolocation accuracy of the CSV uploaded to the watchlist, I cross-checked the IP address **41.143.19.219** using an external IP lookup website. The location returned matched the geolocation identified by the watchlist, confirming the accuracy of the data.

---

## Part 6. Attack Map Creation

<img src="https://i.imgur.com/Nd9CCne.png">

I navigated to Microsoft Sentinel > Workbooks and created a new workbook titled “Windows Attack Map.” I added a query element using the geolocation data from my watchlist to map IP addresses to their geographical origins, visualising the data with a map template in Sentinel.

---

### Part 6.1. Attack Map Visualised

<img src="https://i.imgur.com/p3tVu85.png">

I now have a visual map that displays the origin of incoming attacks. High levels of activity are represented by larger red circles, while lower activity levels appear as smaller green circles. The map updates automatically as the machine continues to receive attacker activity.

<img src="https://i.imgur.com/w3Z9PHp.png">

This is the same map after about 24 hours.

---

### Part 6.2: Analysis of Observed Activity

-	Attackers attempted multiple failed logins using the same username from a single IP address within a short timeframe, indicating typical brute-force attack behaviour.<br>

-	Commonly used account names such as 'Admin' and 'Administrator' were the primary targets, highlighting the importance of avoiding generic names for high-privilege accounts to reduce vulnerability.<br>

-	The honeypot attracted opportunistic bots and scanners but lacked engagement from advanced persistent threats, likely due to the absence of deception layers such as tokens, fake file shares, or misleading login banners.<br>

<img src="https://i.imgur.com/0Ww2hSA.png">

The screenshot above clearly shows that attackers often target generic usernames, such as **'Administrator'**.

---

<a name="part-63-threat-intelligence-correlation-and-mitre-attck-mapping"></a>
### 6.3: Threat Intelligence Correlation and MITRE ATT&CK Mapping

<img src="https://i.imgur.com/2YhhIc0.png">
<img src="https://i.imgur.com/0qdyW5G.png">

One of the most active IP addresses targeting my pot was **193.37.69.105**, responsible for generating thousands of failed login attempts. To determine whether this behaviour had been observed elsewhere, I looked up the IP on **AbuseIPDB**. The search revealed that it had been reported over **700** times, with a clear history of malicious and abusive activity. Given the rapid and repetitive nature of the login attempts, it's likely that this was part of an automated bot-driven brute-force attack targeting publicly accessible systems.

<img src="https://i.imgur.com/wfwatIh.png">

Interestingly, the IP was associated with the domain **hxxp://tutamail[.]com** — an encrypted email provider. While **TutaMail** is a legitimate service, threat actors frequently abuse it to facilitate command-and-control (C2) communication or to receive credentials and malware logs.

A search of this domain on VirusTotal revealed community reports linking it to prior **ransomware-related IOCs.** While this doesn’t confirm that ransomware was the intent in this case, the pattern of brute-force behaviour combined with its infrastructure associations suggests the IP may have been part of a larger campaign seeking unauthorised access to deploy malware — potentially including ransomware.

This technique aligns with **MITRE ATT&CK T1110.001 – Brute Force: Password Guessing.**

**Recommended mitigations:**

•	Block the IP and domain at the network edge.<br>
•	Use unique usernames for privileged accounts.<br>
•	Enforce MFA and account lockout policies.<br>
•	Monitor for repeated failed login attempts and enable alerting.<br>

---

## Part 7: Ethical Considerations and Cleanup

### Part 7.1: Ethical Considerations

Throughout the lab, I monitored the pot to ensure it was not used for malicious purposes, such as sending spam or attacking other systems, adhering to Azure’s terms of service and ethical research practices. 

I monitored the VM’s outbound traffic using Azure Network Watcher to confirm it was not being used for malicious purposes, such as sending spam or participating in attacks, in compliance with Azure’s terms of service.

---

### Part 7.2: Deleted All Resources to Avoid Charges

I accessed the Azure Portal and navigated to the resource group containing my honeypot lab resources. I selected the resource group and chose the option to delete it, confirming the deletion to remove the virtual machine, virtual network, Log Analytics Workspace, and Microsoft Sentinel instance. This ensured no further charges were incurred on my free Azure subscription after completing the lab.

---

<a name="part-8-lab-conclusion"></a>
## 8. Lab Conclusion 

This lab provided a realistic and insightful look into how vulnerable public-facing systems are rapidly targeted by opportunistic attackers and automated bots. By deploying a deliberately weakened virtual machine as a pot in Microsoft Azure, I was able to observe brute-force login attempts in real time and leverage Microsoft Sentinel to analyse and visualise the attack data. The exercise not only demonstrated the practical value of cloud-native SIEM tools like Microsoft Sentinel and Kusto Query Language (KQL), but also reinforced the importance of implementing layered security controls such as strong authentication policies, log monitoring, and threat intelligence correlation. The ability to trace attacks geographically and map behaviours to MITRE ATT&CK techniques deepened my understanding of adversary tactics, techniques, and procedures (TTPs). Overall, this hands-on experience highlighted both the technical and ethical aspects of threat detection and cloud security monitoring
