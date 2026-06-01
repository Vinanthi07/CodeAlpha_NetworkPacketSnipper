# CodeAlpha_NetworkPacketSnipper
# Basic Network Sniffer

A simple Python-based network packet sniffer built using Scapy. This tool captures live network traffic, displays packet information in real time, and saves captured packets to a PCAP file for later analysis with Wireshark.

## Features

* Capture packets from a selected network interface
* Automatic or manual interface selection
* Live packet monitoring
* Protocol identification (ICMP, TCP, UDP, etc.)
* Packet statistics and protocol breakdown
* Save captured traffic to a `.pcap` file
* Compatible with Wireshark for further analysis

## Technologies Used

* Python 3
* Scapy

## Installation

### Clone the Repository

```bash
git clone https://github.com/your-username/basic-network-sniffer.git
cd basic-network-sniffer
```

### Install Dependencies

#### Kali Linux

```bash
sudo apt update
sudo apt install python3-scapy
```

or

```bash
pip3 install scapy --break-system-packages
```

## Usage

Run the sniffer with administrator privileges:

```bash
sudo python3 sniffer.py
```

You will be prompted to:

1. Select a network interface (e.g., `eth0`, `wlan0`)
2. Choose the number of packets to capture

   * Enter `0` for unlimited capture

Example:

```text
Enter interface (e.g. eth0 / wlan0) or ENTER for auto: eth0
How many packets? (0 = unlimited): 100
```

## Sample Output

```text
==================================================
       BASIC NETWORK SNIFFER
       Press CTRL+C to stop
==================================================

[*] Sniffing started...

[ICMP] 192.168.1.10 -> 8.8.8.8
[TCP ] 192.168.1.10 -> 142.251.x.x
[UDP ] 192.168.1.10 -> 8.8.8.8
```

## Capture Summary

```text
========== CAPTURE SUMMARY ==========
Total packets : 1502
PCAP saved to : captured.pcap

Protocol Breakdown:
ICMP   1490 packets
UDP      12 packets
=====================================
```

## Viewing Captured Traffic

Install Wireshark:

```bash
sudo apt install wireshark
```

Open the generated capture file:

```bash
wireshark captured.pcap
```

## Project Structure

```text
.
├── sniffer.py
├── captured.pcap
└── README.md
```

## Learning Objectives

This project helps demonstrate:

* Network packet capture
* TCP/IP fundamentals
* ICMP, TCP, and UDP protocols
* Packet analysis
* PCAP generation
* Network troubleshooting concepts

## Disclaimer

This project is intended for educational purposes and authorized network analysis only. Always ensure you have permission before capturing or analyzing network traffic on any network or device.

## License

This project is released under the MIT License.
