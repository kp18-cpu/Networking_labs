# Network Security Lab Portfolio: Mastering Infrastructure Defense and Offense

This repository documents a series of hands-on laboratory exercises in network security. These labs, conducted using Cisco Packet Tracer and Kali Linux, demonstrate my practical skills and theoretical understanding across critical network security domains, including foundational network services, infrastructure hardening, and advanced attack mitigation techniques.

## Labs Overview:

Each lab focuses on a specific aspect of network security, providing a comprehensive exploration of vulnerabilities and their countermeasures.

### 1. Physical Security & Initial Device Configuration (Lab: 1)
* **Initial Device Setup:** Configuring basic network devices like switches and routers in Cisco Packet Tracer.
* **Interface Configuration:** Assigning IP addresses and enabling interfaces on routers.
* **Device Identification:** Locating MAC addresses of connected devices and understanding their role.
* **Command Line Interface (CLI) Access:** Practicing different methods of accessing network devices, including console, Telnet, and SSH.
* **Password Management:** Setting and managing various password types (enable secret, console, VTY lines) for secure access.
* **SSH Implementation:** Configuring and utilizing SSH for secure remote access to network devices.
* **Routing Fundamentals:** Implementing and verifying static routing to ensure network connectivity.

### 2. Switch Features: VLANs, SVIs, and SPAN (Lab: 3)
* **VLAN Configuration:** Creating and assigning VLANs to logically segment network traffic on a switch.
* **Inter-VLAN Routing:** Configuring a multilayer switch to perform routing between different VLANs using Switched Virtual Interfaces (SVIs).
* **Trunking:** Establishing trunk links between switches to allow multiple VLANs to traverse a single physical link.
* **Switch Port Analyzer (SPAN):** Implementing SPAN to monitor network traffic on specific switch ports.
* **Network Reset:** Understanding how to erase switch configurations and reload devices to a default state.

### 3. Infrastructure Security: Port Security & ACLs (Labs: 2 & 6)
* **Port Security:** Configuring port security on switches to prevent MAC address spoofing and control access based on MAC addresses (static, sticky, and violation modes).
* **Access Control Lists (ACLs):**
    * **Standard ACLs:** Implementing basic IP-based filtering rules.
    * **Extended ACLs:** Applying more granular filtering based on source IP, destination IP, protocol, and port numbers.
    * **ACL Placement:** Understanding the best practices for placing standard and extended ACLs (near source vs. near destination).

### 4. DHCP, ARP, and IP Attacks & Mitigation (Freestyle Lab)
* **Rogue DHCP Server Attack:** Demonstrating how an unauthorized DHCP server can distribute malicious network configurations to clients, becoming a man-in-the-middle.
* **DHCP Snooping Mitigation:** Implementing DHCP snooping on switches to secure DHCP operations by trusting legitimate DHCP servers and dropping rogue DHCP messages.
* **DHCP Starvation Attack:** Simulating a DHCP starvation attack where an attacker depletes the DHCP server's IP address pool, leading to a denial-of-service.
* **Port Security Mitigation for DHCP Starvation:** Using port security to limit the number of MAC addresses per port, preventing DHCP starvation.
* **IP Spoofing Attack:** Illustrating how an attacker can forge their source IP address to masquerade as a legitimate host.
* **IP Source Guard Mitigation:** Understanding and configuring IP Source Guard to prevent IP spoofing by binding IP addresses to specific ports.
* **ARP Cache Poisoning Attack:** Executing an ARP spoofing attack to redirect network traffic through the attacker's machine.
* **Dynamic ARP Inspection (DAI) Mitigation:** Implementing DAI to validate ARP packets and prevent ARP cache poisoning.
* **Private VLANs Mitigation:** Utilizing Private VLANs to isolate devices and prevent ARP requests from untrusted sources within a VLAN.

### 5. Intrusion Detection Systems (Lab: 7)
* **Snort Installation and Modes:** Installing Snort on Kali Linux and exploring its three primary modes: sniffer, packet logger, and Network Intrusion Detection System (NIDS).
* **Packet Logging:** Configuring Snort to log network packets to a specified directory.
* **NIDS Mode with Custom Rules:** Implementing Snort in NIDS mode, configuring `snort.conf`, and writing custom rules (e.g., for ICMP detection) to generate alerts based on network traffic.
* **Rule Categories and Analysis:** Examining different Snort rule categories (web attacks, malware, DDoS, ICMP) and identifying interesting individual rules.
* **Log Analysis:** Analyzing Snort output (alerts and logs) to identify and interpret detected intrusions.

### 6. OSPF Authentication (Lab: 9)
* **OSPF Fundamentals:** Understanding the basics of OSPF, a link-state routing protocol, including Link State Advertisements (LSAs).
* **Authentication Types:** Exploring and configuring different OSPF authentication mechanisms:
    * **Null Authentication:** The default, insecure method.
    * **Plaintext Authentication:** A basic, but vulnerable, form of authentication.
    * **MD5 Authentication:** A hashed authentication method.
    * **HMAC-SHA Authentication:** The most secure method, utilizing SHA-256 for cryptographic integrity.
* **Security Implications:** Analyzing the security strengths and weaknesses of each authentication type and their importance in preventing routing attacks.
* **Packet Sniffing OSPF Traffic:** Using a network sniffer to observe OSPF packets and verify their authentication types.

### 7. Authentication and Remote Access: Password Cracking (Lab: 8)
* **John the Ripper:**
    * **Tool Usage:** Utilizing `john` for password auditing and cracking.
    * **Hash Type Support:** Understanding `john`'s capabilities to crack various ciphertext formats (DES, MD5, Blowfish, NT hashes).
    * **Wordlist Attacks:** Performing dictionary attacks using `john` with provided wordlists (e.g., `rockyou.txt`, `password.lst`).
    * **Unshadow Utility:** Combining `/etc/passwd` and `/etc/shadow` files for `john` to use.
    * **Rule-Based Attacks:** Applying rules to generate password candidates.
* **Crunch:**
    * **Wordlist Generation:** Using `crunch` to generate custom wordlists based on specified character sets (alphanumeric, symbols, mixed case).
    * **Brute-Force Attack Preparation:** Understanding how `crunch` aids in preparing for brute-force attacks by creating exhaustive password lists.
* **Mimikatz:**
    * **Credential Dumping:** Using `mimikatz` to extract hashed credentials (NTLM hashes) from a Windows system's SAM database.
    * **Privilege Escalation:** Utilizing `privilege::debug` and `token::elevate` within `mimikatz` to gain higher privileges.
* **Ophcrack:**
    * **Rainbow Table Attacks:** Employing `ophcrack` for rainbow table-based password cracking.
    * **LM/NT Hash Cracking:** Loading and cracking Windows LM and NT hashes.
* **Password Security:** Understanding the importance of strong, unique, and hashed passwords, and the vulnerabilities of common passwords.

## Key Learnings & Skills Acquired:

* **Network Device Configuration:** Proficient in configuring Cisco switches and routers, including VLANs, trunking, routing protocols, and security features.
* **Network Service Security:** Deep understanding of DHCP, ARP, and IP protocols, their common attacks, and effective mitigation strategies.
* **Threat Detection:** Ability to deploy and configure IDSs like Snort, write custom rules, and analyze alerts to identify malicious network activity.
* **Offensive Security Techniques:** Practical experience with password cracking tools (John the Ripper, Crunch, Mimikatz, Ophcrack) and an understanding of different attack methodologies (dictionary, brute-force, rainbow table, credential dumping).
* **Infrastructure Hardening:** Implementing various security measures on network devices to protect against common attacks, such as port security, IP Source Guard, Dynamic ARP Inspection, and OSPF authentication.
* **Packet Analysis:** Utilizing sniffers to capture and analyze network traffic at various layers to understand protocol behavior and detect anomalies.
* **Command Line Proficiency:** Extensive experience working with command-line tools in both Kali Linux and Windows environments for network configuration, security tasks, and forensic analysis.
* **Security Best Practices:** Gained insights into best practices for secure network design, password policies, and incident prevention.

This portfolio represents my dedication to understanding and securing network infrastructures, combining theoretical knowledge with practical, hands-on experience.
