# Bluetooth Vulnerability Scanner 🔍

![Banner](https://via.placeholder.com/800x200/2c3e50/ffffff?text=Bluetooth+Vulnerability+Scanner)  
**Advanced Bluetooth security assessment toolkit**

## Developed by Anas Erami 💻🔒

## Key Features ✨

- 🛰️ Dual-mode scanning (Classic Bluetooth + BLE)
- 🔍 Comprehensive vulnerability detection (BlueBorne, KNOB, BIAS, SweynTooth)
- 📊 Professional terminal interface with color-coded results
- 🎯 Targeted device analysis
- ⚡ Auto-generated exploit scripts
- 📋 Vulnerability status indicators (OPEN/CLOSED/PARTIAL)
- 🛡️ Security severity ratings (CRITICAL/HIGH/MEDIUM)

## Requirements 📋

- Linux OS (Kali Linux recommended)
- Python 3.7+
- Bluetooth adapter (built-in or USB dongle)
- Root privileges

## Installation ⚙️

```bash
# Install dependencies
sudo apt update
sudo apt install python3 python3-pip bluez bluez-tools bluetooth

# Install Python requirements
pip3 install colorama

# Clone repository
git clone https://github.com/AnasErami/bluetooth-scanner.git
cd bluetooth-scanner

# Make script executable
chmod +x bluetooth_pentest.py
```

## Usage 🚀

```bash
sudo ./bluetooth_pentest.py
```

### Main Menu Options:
1. **Show discovered devices** - List all Bluetooth devices in range
2. **Scan vulnerabilities** - Comprehensive security assessment
3. **Target specific device** - Focus on a particular device
4. **Advanced exploitation toolkit** - Generate exploit scripts
5. **Exit** - Quit the application

## Screenshots 📸

### Main Interface
![Main Menu](https://via.placeholder.com/600x300/1a2b3c/ffffff?text=Professional+Terminal+Interface)

### Vulnerability Scan
![Vulnerability Scan](https://via.placeholder.com/600x300/2c3e50/ffffff?text=Vulnerability+Scan+Results)

### Advanced Tools
![Advanced Tools](https://via.placeholder.com/600x300/34495e/ffffff?text=Advanced+Exploitation+Tools)

## Detected Vulnerabilities 🚨

| Vulnerability  | Status Indicator | Severity | Test Included |
|----------------|------------------|----------|---------------|
| BlueBorne     | OPEN/CLOSED     | CRITICAL | ✅            |
| KNOB Attack   | OPEN/PATCHED    | HIGH     | ✅            |
| BIAS Attack   | PARTIAL         | MEDIUM   | ✅            |
| SweynTooth    | OPEN            | HIGH     | ✅            |
| OBEX Exploits | OPEN            | MEDIUM   | ✅            |

## Ethical Use Policy ⚖️

> **Warning**  
> This tool is for educational purposes only. Only test devices you own.  
> Unauthorized access to computer systems is illegal.  
> The developer assumes no liability for misuse of this software.

## License 📜

This project is licensed under the **MIT License** - see the [LICENSE](LICENSE) file for details.

## Contribution 🤝

Contributions are welcome! Please open an issue or submit a pull request for any:
- Bug fixes
- New vulnerability signatures
- Feature enhancements
- Documentation improvements

---
**Developed with ❤️ by Anas Erami - Security Researcher**  
[![Twitter](https://img.shields.io/badge/Twitter-1DA1F2?style=for-the-badge&logo=twitter&logoColor=white)](https://twitter.com/yourprofile)
[![GitHub](https://img.shields.io/badge/GitHub-100000?style=for-the-badge&logo=github&logoColor=white)](https://github.com/yourprofile)
