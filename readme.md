# Porter

**Porter** is a Python-powered network scanner and OS detection tool designed for security professionals . It offers host discovery, TCP/UDP port scanning, OS fingerprinting, and banner grabbing to help you analyze and audit networks.

## Features

- **Host Discovery:** ICMP ping and TCP ACK scanning to find live hosts.
- **OS Detection:** Identifies operating systems using TTL values and open port analysis.
- **Port Scanning:** Scans both TCP and UDP ports for open services.
- **Banner Grabbing:** Retrieves service banners for identification.
- **HTTP(S) Analysis:** Inspects HTTP/HTTPS headers for additional information.

## Requirements

- Python 3.x
- [scapy](https://scapy.net/) (`pip install scapy`)

> **Note:** Running Porter requires administrator/root privileges due to raw socket operations.

## Usage

1. Clone or download the repository.
2. Install dependencies:
    ```sh
    pip install scapy
    ```
3. Run the main script:
    ```sh
    python Porter.py
    ```
4. Follow the interactive prompts:
    - Enter a target host IP (single address or range)
    - Choose between OS detection or port scanning
    - Select TCP or UDP scan type

### Example 

```
Enter target host IP: 192.168.1.0
Enter host range (e.g., 1-254): 1-10
Do you want to perform a port scan to identify the OS? Enter 'yes' to do or press Enter to ignore: yes
```

## File Overview

- `Porter.py`: Main script for scanning and detection.
- `custom_ping.py`: Implements custom ICMP ping and TTL-based functions.

---

Created by Mohammed Aloli