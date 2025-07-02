#!/bin/bash

# Elite Bluetooth Framework Installer & Runner
# Developed by Anas Erami


VENV_DIR="venv"
PYTHON_SCRIPT="blain.py" 
REQUIREMENTS_FILE="requirements.txt"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' 

set -e

printf "${YELLOW}[*] Checking for root privileges...${NC}\n"
if [ "$EUID" -ne 0 ]; then
  printf "${RED}[!] Error: This script must be run as root. Please use 'sudo ./install_and_run.sh'${NC}\n"
  exit 1
fi
printf "${GREEN}[+] Root privileges confirmed.${NC}\n\n"


printf "${YELLOW}[*] Updating package list and installing system dependencies...${NC}\n"
printf "${YELLOW}    This may take a few minutes and will require your password for sudo.${NC}\n"

apt-get update
apt-get install -y python3-pip python3-venv bluez bluez-tools libbluetooth-dev \
                   wireshark ffmpeg ubertooth gr-bluetooth obexftp

printf "${GREEN}[+] System dependencies installed successfully.${NC}\n\n"


printf "${YELLOW}[*] Setting up Python virtual environment in './${VENV_DIR}'...${NC}\n"

if [ ! -d "$VENV_DIR" ]; then
    printf "    Creating virtual environment...\n"
    python3 -m venv $VENV_DIR
    printf "${GREEN}[+] Virtual environment created.${NC}\n"
else
    printf "${GREEN}[+] Virtual environment already exists.${NC}\n"
fi

source "${VENV_DIR}/bin/activate"
printf "${GREEN}[+] Virtual environment activated.${NC}\n\n"

printf "${YELLOW}[*] Installing Python libraries from '${REQUIREMENTS_FILE}'...${NC}\n"

if [ ! -f "$REQUIREMENTS_FILE" ]; then
    printf "${RED}[!] Error: '${REQUIREMENTS_FILE}' not found. Cannot install Python libraries.${NC}\n"
    exit 1
fi

pip install --upgrade pip
pip install -r $REQUIREMENTS_FILE

printf "${GREEN}[+] Python libraries installed successfully.${NC}\n\n"


printf "${GREEN}====================================================${NC}\n"
printf "${GREEN}       Installation and Setup Complete!             ${NC}\n"
printf "${GREEN}====================================================${NC}\n\n"

printf "${YELLOW}[*] Starting the Elite Bluetooth Framework...${NC}\n"
printf "${YELLOW}    Remember to run this script with 'sudo' in the future.${NC}\n\n"
sudo "${VENV_DIR}/bin/python" "$PYTHON_SCRIPT" "$@"

# Deactivate venv 
deactivate
