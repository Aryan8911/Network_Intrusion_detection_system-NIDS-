# Network Intrusion Detection System (NIDS)

This project contains a simple Network Intrusion Detection System using Python's `scapy` library. It captures network packets in real-time and logs details such as source IP, destination IP, protocol, and size to a CSV file. The NIDS is designed for both Windows and Mac/Linux environments.

## Requirements

- Python 3.x
- Scapy library
- Pandas library
- (For Windows) Npcap driver

## Setup Instructions

### Windows

1. **Install Python and Libraries**:
   Make sure Python is installed. Then, install required libraries:
   ```
   pip install scapy pandas
   ```

2. **Install Npcap Driver**:
   Download and install Npcap from [here](https://nmap.org/npcap/). During installation, check:
   - "Support raw 802.11 traffic (and monitor mode) for WiFi adapters"
   - "WinPcap API-compatible Mode"

3. **Run with Administrator Privileges**:
   - Open **Command Prompt** as Administrator:
     - Search for "cmd", right-click, and choose "Run as administrator".
   - Navigate to the script's folder:
     ```
     cd path	o\yourolder
     ```
   - Run the script:
     ```
     python nids_analyzer.py
     ```

### Mac/Linux

1. **Install Python and Libraries**:
   Use the following command:
   ```
   pip install scapy pandas
   ```

2. **Run the Script**:
   You need to run the script with root privileges:
   ```
   sudo python3 nids_analyzer.py
   ```

3. **Find Correct Network Interface**:
   If needed, modify the script to use the correct interface for your system (e.g., `wlan0` for Wi-Fi on Linux).

### Detecting Network Interface
The script automatically detects your network interface (Wi-Fi or LAN). If it doesn't capture packets, you may need to manually specify the correct interface:
- Use this code to list available interfaces:
  ```python
  from scapy.all import get_if_list
  print(get_if_list())
  ```
- Replace the interface in the script with the appropriate one.

### Output
- The captured packets will be saved in a CSV file in the current directory.

Enjoy using the NIDS!



## Model dataset can be dowmloaded from https://www.kaggle.com/datasets/dhoogla/cidds001
# Search for cidds001 on any web-browser and download the dataset from kaggle.