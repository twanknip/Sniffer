# Sniffer
# Python packet sniffer

A simple packet sniffer written in Python without external libraries.  
This tool shows TCP and UDP packets including IP information and TCP flags.  
Additionally, it can parse encrypted TLS payloads when enabled.

## Requirements
- Python 3.8+
- Windows (Admin rights required to open RAW sockets)

## Usage

```bash
# Start sniffer with default settings (no TLS parsing)
python main.py

# Start sniffer with TLS encrypted payload parsing enabled
python main.py --tls
