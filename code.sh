#!/bin/bash

# Elite Bluetooth Framework Installer & Runner
# Developed by Anas Erami
# This script prepares the environment and runs the main application.

# --- Configuration ---
VENV_DIR="venv"
PYTHON_SCRIPT="blain.py" # اسم ملف البايثون الرئيسي الخاص بك
REQUIREMENTS_FILE="requirements.txt"

# --- Colors for better output ---
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# --- Stop on any error ---
set -e

# --- 1. Check for Root Privileges ---
printf "${YELLOW}[*] Checking for root privileges...${NC}\n"
if [ "$EUID" -ne 0 ]; then
  printf "${RED}[!] Error: This script must be run as root. Please use 'sudo ./install_and_run.sh'${NC}\n"
  exit 1
fi
printf "${GREEN}[+] Root privileges confirmed.${NC}\n\n"


# --- 2. Install System-Level Dependencies ---
printf "${YELLOW}[*] Updating package list and installing system dependencies...${NC}\n"
printf "${YELLOW}    This may take a few minutes and will require your password for sudo.${NC}\n"

# A list of packages required by the framework
# This covers Debian/Ubuntu based systems.
apt-get update
apt-get install -y python3-pip python3-venv bluez bluez-tools libbluetooth-dev \
                   wireshark ffmpeg ubertooth gr-bluetooth obexftp

printf "${GREEN}[+] System dependencies installed successfully.${NC}\n\n"


# --- 3. Setup Python Virtual Environment ---
printf "${YELLOW}[*] Setting up Python virtual environment in './${VENV_DIR}'...${NC}\n"

if [ ! -d "$VENV_DIR" ]; then
    printf "    Creating virtual environment...\n"
    python3 -m venv $VENV_DIR
    printf "${GREEN}[+] Virtual environment created.${NC}\n"
else
    printf "${GREEN}[+] Virtual environment already exists.${NC}\n"
fi

# Activate the virtual environment for the current script session
source "${VENV_DIR}/bin/activate"
printf "${GREEN}[+] Virtual environment activated.${NC}\n\n"


# --- 4. Install Python Libraries ---
printf "${YELLOW}[*] Installing Python libraries from '${REQUIREMENTS_FILE}'...${NC}\n"

if [ ! -f "$REQUIREMENTS_FILE" ]; then
    printf "${RED}[!] Error: '${REQUIREMENTS_FILE}' not found. Cannot install Python libraries.${NC}\n"
    exit 1
fi

# Upgrade pip and install from requirements file
pip install --upgrade pip
pip install -r $REQUIREMENTS_FILE

printf "${GREEN}[+] Python libraries installed successfully.${NC}\n\n"


# --- 5. Final Setup & Run ---
printf "${GREEN}====================================================${NC}\n"
printf "${GREEN}       Installation and Setup Complete!             ${NC}\n"
printf "${GREEN}====================================================${NC}\n\n"

printf "${YELLOW}[*] Starting the Elite Bluetooth Framework...${NC}\n"
printf "${YELLOW}    Remember to run this script with 'sudo' in the future.${NC}\n\n"

# Run the main python script using the python from our virtual environment
# We use sudo because the script itself needs root to access hardware.
# "$@" passes any command-line arguments (like --adapter) to the python script.
sudo "${VENV_DIR}/bin/python" "$PYTHON_SCRIPT" "$@"

# Deactivate venv upon exiting the script (good practice)
deactivate