# Blain Framework v2.0



```
  ____  _       _                  
 | __ )| | __ _(_)_ __ 
 |  _ \| |/ _` | | '_ \ 
 | |_) | | (_| | | | | |
 |____/|_|\__,_|_|_| |_|

```
<div align="center">
 
**Blain: Bluetooth Anas Intelligence Network**

An Advanced Bluetooth Penetration & Zero-Day Discovery Platform

</div>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/Platform-Linux-lightgrey.svg" alt="Platform: Linux">
  <img src="https://img.shields.io/badge/License-MIT-green.svg" alt="License: MIT">
  <img src="https://img.shields.io/badge/Maintained%3F-Yes-green.svg" alt="Maintained">
</p>

---

## About The Project

**Blain** is a powerful open-source Bluetooth security framework designed for penetration testers, researchers, and advanced users. Built by Anas Erami, Blain aims to provide a professional-grade toolkit for discovering, assessing, and exploiting Bluetooth vulnerabilities — with an emphasis on ethical usage and zero-day research.

Version 2.0 introduces a full-featured **fuzzing engine**, making Blain a next-gen platform for discovering previously unknown vulnerabilities in BLE devices.

---

## Key Features

### Reconnaissance & Scanning
- **Dual-Mode Scanning:** Supports both Classic Bluetooth (BR/EDR) and BLE.
- **Deep Profiling:** Gathers detailed info: name, MAC, vendor, RSSI, services.
- **Service Enumeration:** Extracts SDP and GATT services for attack surface mapping.

### Vulnerability Assessment
- **Modular JSON Database:** Load, update, and manage known vulnerability definitions.
- **Active Rule-Based Testing:** Goes beyond version checks — executes commands and pairing attempts to confirm vulnerabilities like BlueBorne, KNOB, and BIAS.

### Exploitation Toolkit
- **Pairing Exploits:** Common-PIN, forced pairing, and bypass attacks.
- **BLE Data Access:** Read/write/subscribe to BLE characteristics.
- **AVRCP/OBEX Hijack:** Take control of media or access files from vulnerable targets.
- **DoS Attacks:** Launch GATT or L2CAP flood attacks.
- **A2DP Eavesdropping:** (Experimental, requires Ubertooth or SDR hardware).

### Zero-Day Fuzzing Engine
- **Mutation-Based Fuzzing:** Smart (bit-flip) and dumb fuzzing modes.
- **Live Target Health Check:** Auto-monitoring via l2ping.
- **Crash Logging:** Generates detailed JSON crash reports with test data.

### Monitoring & Post-Exploitation
- **Bluetooth Sniffing:** Integrated with Wireshark/dumpcap.
- **Logs & Reports:** Structured output for all scans, exploits, and fuzzing attempts.

---

## ⚙ Requirements

### System Requirements
- **OS:** Debian-based Linux (Ubuntu, Kali, Parrot, etc.)
- **Permissions:** Root (sudo) access required
- **Hardware:** Compatible Bluetooth adapter (Classic & BLE)

### Dependencies

Blain requires several tools and libraries. Run the installer to handle them.

#### System Packages
- `bluez`, `bluez-tools`, `ubertooth`, `ffmpeg`, `gr-bluetooth`, `wireshark`

#### Python Modules
- `bleak`, `pexpect`, `pyobex`, `dbus-python`, `colorama`

---

## Getting Started

### 1. Clone the Repository
```bash
git clone https://github.com/anas-2003/Blain-ma.git
cd Blain-ma
```

### 2. Run the Installer
```bash
chmod +x setup.sh

sudo ./setup.sh
```

This script will:
- Install all system dependencies
- Create a virtual environment
- Install all Python modules
- Launch the framework

To specify an adapter:
```bash
pip install -r requirements.txt

sudo ./setup.sh --adapter hci1
```

---

## ⚠ Legal Disclaimer

> This framework is provided for **educational** and **authorized** testing only. You are fully responsible for how you use this tool. **Never scan, exploit, or interact with Bluetooth devices you do not own or have explicit permission to test.**

Anas Erami assumes **no liability** for misuse or damages.

---

## Contributing

Blain is open to contributions!

- Add new vulnerability definitions (JSON)
- Report bugs or suggest enhancements
- Fork and submit PRs

### Steps to contribute:
1. Fork the project
2. Create a branch (`git checkout -b feature/new-tool`)
3. Commit your changes
4. Push and open a PR

---

>  **Want to contribute to Blain?**  
> Check out our [CONTRIBUTING guide](CONTRIBUTING.md) for how to get involved!

---

---
> **Code of Conduct**   
> Please read our [Code of Conduct](code_of_conduct.md) to know how we maintain a respectful community.
---

## License

This project is licensed under the **MIT License**. See the `LICENSE` file.

---

## Contact

**Developer:** Anas Erami  
📧 Email: [anaserami17@gmail.com](mailto:anaserami17@gmail.com)  
🔗 GitHub: [github.com/anas-2003/Blain-ma](https://github.com/anas-2003/Blain-ma)

> Framework Name: **Blain** — Bluetooth Anas Intelligence Network

---

Thanks for using Blain. Stay safe. Hack ethically.
