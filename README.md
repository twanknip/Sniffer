# Sniffer
# Python packet sniffer

A simple packet sniffer written in Python without external libraries. 
This tool shows TCP and UDP packets including IP information and TCP flags.

## Requirements
- Python 3.8+
- Windows (Admin rights required to open RAW sockets)

- ## Versions
v1.0.0 - 
✅ Support for parsing IP, TCP and UDP headers
✅ Print source and destination IP and ports
✅ Recognize TCP flags (SYN, ACK, FIN, etc.)
✅ Establishing a basic structure for further extension (OOP ready)
✅ Supports live sniffing via socket on Windows (with SIO_RCVALL)

## Usage
``` bash
python main.py
