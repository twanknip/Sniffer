# Sniffer
# Python packet sniffer

A simple packet sniffer written in Python without external libraries. 
This tool shows TCP and UDP packets including IP information and TCP flags.

## Requirements
- Python 3.8+
- Windows (Admin rights required to open RAW sockets)


## Usage

```bash
# Show all TCP and UDP packets
python main.py

# Filter packets by a specific port
python main.py --port PORT_NUMBER

