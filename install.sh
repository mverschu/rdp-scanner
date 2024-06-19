#!/bin/bash

# Update package list and install required system packages
sudo apt update
sudo apt install nmap rdesktop xvfb python3-pip -y

# Install Python dependencies
pip3 install -r requirements.txt

echo "Installation complete. You can now run the rdp-scanner script."
