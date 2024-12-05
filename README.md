<h1>TryHackMe SOC Level 1</h1>


<h2>Description</h2>
Gained practical experience in critical SOC functions through hands-on labs, focusing on the implementation and analysis of security frameworks, threat intelligence, network traffic, and endpoint monitoring.
<br />


<h2>Languages and Utilities Used</h2>

- <b>Wireshark</b> 
- <b>Snort</b>
- <b>Zeek</b>
- <b>TShark</b>
- <b>Sysmon</b>
- <b>Windows Event Logs</b>
- <b>Osquery</b>
- <b>Wazuh</b>
- <b>Splunk</b>
- <b>ELK Stack (Elasticsearch, Logstash, Kibana)</b>
- <b>Autopsy</b>
- <b>Redline</b>
- <b>KAPE</b>
- <b>Volatility</b>
- <b>OpenCTI</b>
- <b>MISP</b>
- <b>Yara</b>

<h2>Environments Used </h2>

- <b>Virtualized Labs</b>
- <b>Windows Systems (for endpoint security and forensic analysis)</b>
- <b>Linux Systems (for forensic analysis and network traffic monitoring)</b>
- <b>Cloud-based Threat Intelligence Platforms (MISP, OpenCTI)</b>
- <b>Simulated SOC Environments for incident response and SIEM tasks</b>
- <b>Network Traffic Analysis Environments (Snort, Zeek, Wireshark, TShark)</b>
- <b>Digital Forensics Labs (Autopsy, Redline, KAPE, Velociraptor)</b>

<h2>Frameworks:</h2>

<p align="center">
Pyramid Of Pain: <br/>
<img src="https://i.imgur.com/HsvyzIw.jpeg" height="50%" width="50%" />
<br/>          
<br/> 
<p>Learned to apply key cyber defense frameworks such as the Pyramid of Pain, MITRE ATT&CK, Cyber Kill Chain, and Unified Kill Chain to enhance threat detection, incident response, and threat hunting capabilities. Gained insights into the significance of different Indicators of Compromise (IOCs), such as hashes, IP addresses, domain names, and artifacts, in hindering adversaries' attack strategies. Also explored how advanced techniques like Fast Flux and User-Agent strings are used by attackers to evade detection.</p>  
<br />
<br />
Cyber Kill Chain:  <br/>
<img src="https://i.imgur.com/7w6Ib1z.jpeg" height="70%" width="70%" />
<p>Learned the phases of the Cyber Kill Chain, a framework used to understand and defend against cyber attacks such as ransomware, breaches, and APTs. Explored each stage of an attack, from reconnaissance and weaponization to delivery, exploitation, and command and control (C2). Gained insights into techniques like phishing, USB drops, and zero-day exploits, as well as how attackers maintain persistence and move laterally through networks. Learned how defenders can recognize and disrupt attacks at various stages to prevent adversaries from achieving their objectives.</p>
<br />
<br />
<br />
MITRE ATT&CK: <br/>
<img src="https://i.imgur.com/U12b95Q.jpeg" height="80%" width="80%" />

<p>Gained an understanding of the MITRE Corporation’s cybersecurity contributions, including the ATT&CK® framework, which maps adversary TTPs (Tactics, Techniques, and Procedures) to real-world attacks. Explored additional MITRE resources such as the Cyber Analytics Repository (CAR), ENGAGE for adversary deception, and D3FEND for mapping countermeasures. Learned how these tools help defenders detect and respond to threats, simulate adversary behavior, and improve security postures through threat-informed defense strategies.</p>

<h2>Threat Intelligence:</h2>


Cyber Threat Intel Process: <br/>
<img src="https://i.imgur.com/0fHt5Xc.jpeg" height="50%" width="50%" />
<p>Learned the fundamentals of Cyber Threat Intelligence (CTI), including the collection, processing, and analysis of data to identify adversaries, their tactics, and indicators of compromise. Explored the four main types of threat intelligence—strategic, technical, tactical, and operational—used to inform security teams and enhance decision-making. Gained insights into the CTI lifecycle, from defining objectives and collecting data to processing, analyzing, and disseminating actionable intelligence to stakeholders. Also reviewed industry standards and frameworks such as MITRE ATT&CK, STIX, and the Cyber Kill Chain for organizing and sharing threat intelligence.</p>
<br />
<br />
CTI Tools:  <br/>
<img src="https://i.imgur.com/J4blpIn.jpeg" height="25%" width="25%" />
<img src="https://i.imgur.com/auY89pd.jpeg" height="25%" width="25%" />
<img src="https://i.imgur.com/xqD9z7R.jpeg" height="25%" width="25%" />
<img src="https://i.imgur.com/q3diFsB.jpeg" height="25%" width="25%" />
<p>Gained proficiency in cyber threat analysis tools like Urlscan.io and Abuse.ch for scanning and tracking malicious websites, malware, and botnets. Explored PhishTool for email phishing detection and Cisco Talos Intelligence for analyzing threat indicators and vulnerabilities.

Developed skills in YARA, creating rules for malware detection through pattern matching and integrating it with tools like Cuckoo Sandbox. Additionally, explored key CTI platforms such as OpenCTI and MISP for managing, analyzing, and sharing threat intelligence. These platforms integrate with tools like TheHive and leverage frameworks like MITRE ATT&CK to support malware analysis and threat investigations across trusted communities.</p>

<h2>Network Security and Traffic Analysis:</h2>


Wireshark:  <br/>
<img src="https://i.imgur.com/pRK5xrn.jpeg" height="50%" width="50%" />
<img src="https://i.imgur.com/6FlrcPE.jpeg" height="80%" width="80%" />
<p>In Wireshark, I used the Statistics menu to analyze traffic patterns and key details like resolved addresses, protocol hierarchy, conversations, and endpoints to identify significant network events. By applying capture and display filters, I filtered traffic based on IP, TCP, UDP, HTTP, and DNS to isolate relevant packets. Advanced filters such as contains, matches, and in were used to refine searches for specific strings, ports, and packet types. I also utilized features like bookmarks, filter buttons, and profiles for efficient reuse of complex filters during network traffic investigations.</p>
<br />
<br />
Snort:  <br/>
<img src="https://i.imgur.com/2G7j9vD.jpeg" height="50%" width="50%" />
<img src="https://i.imgur.com/H7T92bu.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/CZXJ78Z.jpeg" height="80%" width="80%" />
<p>I used Snort to analyze network traffic, detect ICMP packets, and apply custom rules for threat detection. By running Snort in Sniffer, Logger, and IDS/IPS modes, I monitored live traffic, generated alerts, and logged packets for deeper analysis, demonstrating its key functionality in identifying and preventing malicious activity in a network environment.</p>
<br />
<br />
Zeek:  <br/>
<img src="https://i.imgur.com/TPvb4Md.jpeg" height="50%" width="50%" />
<img src="https://i.imgur.com/VnCltZ3.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/g710ZHf.jpeg" height="80%" width="80%" />
<p>I utilized Zeek as a powerful network monitoring tool to analyze network traffic and generate detailed logs for security investigations. By processing pcap files and using Zeek's logging capabilities, I was able to gain deep visibility into network activity, focusing on identifying anomalies, protocol usage, and traffic patterns. I leveraged Zeek's extensive logging, such as connection and protocol-specific logs, to investigate potential security incidents. Additionally, I utilized command-line tools like zeek-cut to extract relevant data from logs and applied custom scripts to automate event correlation and streamline my analysis process.</p>
<br />
<br />
Tshark:  <br/>
<img src="https://i.imgur.com/SfFiTYH.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/mGw0SUS.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/NJ6USna.jpeg" height="80%" width="80%" />
<p>I used TShark, the command-line version of Wireshark, to analyze network traffic by filtering, capturing, and processing packets. TShark's flexibility allowed me to perform in-depth analysis and automate tasks via command-line tools like capinfos, grep, and cut. I leveraged capture and display filters for live and post-capture analysis, using the -f parameter for capture filters and -Y for display filters to narrow down traffic efficiently. Additionally, I utilized options such as -r to read pcap files, -w to write output, and -x for detailed hex and ASCII views of packets. TShark provided a streamlined, efficient way to analyze packets and automate repetitive tasks in network investigations.</p>

<h2>Endpoint Security Monitoring:</h2>


Sysinternals:  <br/>
<img src="https://i.imgur.com/ZsJEkqV.jpeg" height="80%" width="80%" />
<p>I used Sysinternals tools like TCPView for monitoring network connections, Process Explorer for analyzing running processes, and Autoruns to check for suspicious startup entries. These tools helped streamline system analysis and enhance threat detection.</p>
<br />
<br />
Sysmon:  <br/>
<img src="https://i.imgur.com/JwzeLPk.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/vbHJklz.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/5nrebYL.jpeg" height="80%" width="80%" />
<p>I used Sysmon to monitor key events like Process Creation (Event ID 1), Network Connection (Event ID 3), Image Load (Event ID 7), and others to detect anomalies such as suspicious processes, DLL injection, and unauthorized access attempts. By leveraging Sysmon with well-configured rulesets, I filtered out noise and focused on actionable alerts, forwarding them to SIEM for further analysis and investigation.</p>
<br />
<br />
osquery:  <br/>
<img src="https://i.imgur.com/OxQIAkk.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/RWqfQHF.jpeg" height="80%" width="80%" />
<p> I used Osquery's interactive mode to query the system, exploring tables and schemas, filtering results with SQL queries, and joining tables to gather specific insights on processes, users, and other system behaviors. This flexible querying aids in incident response and threat hunting tasks.</p>
<br />
<br />
Wazuh: <br/>
<img src="https://i.imgur.com/m9XdoeT.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/fCGPwkc.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/U0cPhuY.jpeg" height="80%" width="80%" />
<p>I used Wazuh, an open-source EDR solution, to monitor endpoint activity and detect security threats across Windows and Linux systems. By deploying agents, I collected logs on processes like authentication, file access, and vulnerabilities, using Wazuh's rule-based alerts to identify suspicious events. I integrated Sysmon to track key system processes and enhanced detection. Additionally, I leveraged Wazuh’s API for retrieving data and generating reports, enabling detailed analysis of security events.</p>

<h2>Security Information and Event Management:</h2>


ELK Stack: <br/>
<img src="https://i.imgur.com/tF6nIEA.jpeg" height="60%" width="60%" />
<img src="https://i.imgur.com/oQ9nMhp.jpeg" height="70%" width="70%" />
<p>I used the ELK stack (Elasticsearch, Logstash, Kibana) to analyze VPN logs, identifying anomalies like failed login attempts and unauthorized access. Using Kibana’s Discover tab and KQL, I filtered and searched logs by user, IP, and time. I also created visualizations to highlight patterns, such as failed connections from specific countries, improving my ability to investigate and monitor network security events efficiently.</p>
<br />
<br />
Splunk: <br/>
<img src="https://i.imgur.com/JeCduHz.jpeg" height="70%" width="70%" />
<img src="https://i.imgur.com/OZqwQ34.jpeg" height="70%" width="70%" />
<img src="https://i.imgur.com/q8RDVy0.jpeg" height="70%" width="70%" />
<p>I used Splunk to investigate a cyber attack, tracing the attacker’s activities through the Cyber Kill Chain. By analyzing logs from IIS, Suricata, and Sysmon, I identified reconnaissance, brute-force attacks, exploitation, and installation of malicious files. Leveraging OSINT tools like VirusTotal and Robtex, I uncovered attacker infrastructure and linked it to malicious files, mapping the attack’s progression and identifying key indicators of compromise.</p>

<h2>Digital Forensics and Incident Response:</h2>


Autopsy: <br/>
<img src="https://i.imgur.com/8qALBAt.jpeg" height="30%" width="30%" />
<img src="https://i.imgur.com/aTLBOf5.jpeg" height="50%" width="50%" />
<img src="https://i.imgur.com/2y6E0p0.jpeg" height="50%" width="50%" />
<img src="https://i.imgur.com/TjtpQTB.jpeg" height="50%" width="50%" />
<p>Autopsy is an open-source digital forensics tool used to analyze digital media and mobile devices. I utilized it to open case files, configure ingest modules, extract artifacts, and generate reports, allowing for efficient forensic analysis and data retrieval from disk images.</p>
<br />
<br />
RedLine: <br/>
<img src="https://i.imgur.com/fW4V8Yc.jpeg" height="50%" width="50%" />
<img src="https://i.imgur.com/gwVqjfc.jpeg" height="50%" width="50%" />
<img src="https://i.imgur.com/QSTDHpS.jpeg" height="50%" width="50%" />
<p>Redline is a memory and disk analysis tool for quickly assessing compromised systems. It provides a high-level view of processes, registry data, network info, and browser history. I used the Standard Collector method to gather key forensic data and analyze potential threats, leveraging its interface to quickly identify indicators of compromise during incident response.</p>
<br />
<br />
Kape: <br/>
<img src="https://i.imgur.com/Dg3OaLo.jpeg" height="25%" width="25%" />
<img src="https://i.imgur.com/a1XMtlp.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/KSR9Nd1.jpeg" height="80%" width="80%" />
<p>KAPE streamlines forensic artifact collection and processing, allowing for rapid analysis during incident response. It efficiently gathers and processes key data like registry hives and Prefetch files from live systems and storage devices. By configuring custom Targets and Modules, I quickly extracted evidence to understand system activity, using both the command-line and GUI versions for comprehensive triage and analysis.</p>
<br />
<br />
Volatility: <br/>
<img src="https://i.imgur.com/P3cpTmE.jpeg" height="50%" width="50%" />
<p>Volatility is a powerful, open-source memory forensics tool commonly used by malware analysts and SOC teams to analyze memory dumps. It supports multiple operating systems, including Windows, Linux, and macOS, and allows analysts to extract critical system artifacts from memory, offering deep visibility into the runtime state of a system. I used Volatility to investigate various processes, network connections, and DLLs, utilizing plugins like pslist, malfind, and yarascan to detect suspicious activity and potential malware. The tool is essential for identifying advanced evasion techniques, such as SSDT hooks and malicious drivers, during memory forensics investigations.</p>
<br />
<br />
Velociraptor: <br/>
<img src="https://i.imgur.com/zCot4EL.jpeg" height="25%" width="25%" />
<img src="https://i.imgur.com/T3qZfjO.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/7BuuE6X.jpeg" height="80%" width="80%" />
<p>Velociraptor is an open-source endpoint monitoring and forensics tool used for efficient incident response and artifact collection. I deployed it to manage server-client setups, interact with endpoints, and run VQL queries for system analysis and vulnerability detection. Its powerful VFS and query capabilities made it essential for real-time forensic investigations and monitoring.</p>

<h2>Phishing:</h2>


MessageHeader: <br/>
<img src="https://i.imgur.com/72R6QsN.jpeg" height="80%" width="80%" />
<p>I used Messageheader to analyze the phishing email's headers. By pasting the raw header into the tool, I quickly obtained details about the sender's IP, email origin, and any suspicious elements, helping me verify if the email was legitimate or part of a phishing attack.</p>
<br />
<br />
URL Extractor & CyberChef: <br/>
<img src="https://i.imgur.com/7epUJfP.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/itpDv6p.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/vMCZiCT.jpeg" height="50%" width="50%" />
<p>I used URL Extractor to pull URLs from a phishing email by copying the raw header into the tool, which extracted the embedded links. Afterward, I used CyberChef’s "Extract URLs" recipe to cross-check and further analyze the links, ensuring I captured all possible malicious URLs. This combination allowed me to verify and investigate the URLs efficiently, providing a more thorough analysis.</p>
<br />
<br />
CMD(For hash) & VirusTotal: <br/>
<img src="https://i.imgur.com/ZM19tNv.png" height="60%" width="60%" />
<img src="https://i.imgur.com/zvpghaS.jpeg" height="60%" width="60%" />
<p>After obtaining the email attachment, I generated it's hash value using the command line and checked the file's reputation using tools like VirusTotal, which analyzes suspicious files and URLs for malware and shares findings with the security community.</p>
<br />
<br />
Any.Run & Hybrid Analysis: <br/>
<img src="https://i.imgur.com/M2F3LPa.jpeg" height="60%" width="60%" />
<img src="https://i.imgur.com/EA53fcm.jpeg" height="60%" width="60%" />
<p>Online malware sandboxes like Any.Run and Hybrid Analysis were used to upload and analyze a suspicious email attachment. These tools provided insights into the attachment’s behavior, such as its communication with URLs, downloaded payloads, and persistence mechanisms, helping to identify Indicators of Compromise (IOCs) without requiring advanced malware analysis skills.</p>
<br />
<br />
PhishTool: <br/>
<img src="https://i.imgur.com/fqYLcGW.jpeg" height="60%" width="60%" />
<p>PhishTool was used to automate the analysis of a phishing email. By uploading the email, the tool provided detailed insights such as email metadata, sender information, and attachments. It can also be connected to VirusTotal for additional analysis, streamlining the phishing response process.</p>




<br/>
<br/>
Badges Earned: <br/>
<img src="https://i.imgur.com/b4wtrSH.jpeg" height="80%" width="80%" />
<img src="https://i.imgur.com/VirfkFK.jpeg" height="80%" width="80%" />
<br/>
<br/>
<b>Conclusion<b> <br />
<p>The TryHackMe SOC Level 1 Labs allowed me to develop a deep understanding of various cybersecurity frameworks, threat intelligence techniques, network security, endpoint monitoring, and digital forensics. I learned how to analyze and respond to security events through hands-on experience with traffic analysis, endpoint security, SIEM platforms, and phishing detection. Additionally, I gained experience in threat hunting and malware analysis, applying this knowledge to real-world scenarios in incident response and phishing prevention. This journey has significantly enhanced my skills as a SOC analyst, preparing me for future challenges in cybersecurity.</p>
