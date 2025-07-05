# Sniffer

A lightweight packet sniffer written in Python using only the standard library.  
Now includes a live web dashboard for real-time traffic monitoring.

---

## Features

- Capture **TCP** and **UDP** traffic with IP/port info and packet length
- Live **web dashboard** (built in React) via Flask + Socket.IO
- Filter packets by common ports (HTTP, HTTPS, DNS, etc.)
- Realtime packet feed with pause/resume toggle
- Simple, clean UI built with React and custom CSS

---

## Requirements

- Python **3.8+**
- **Windows only** (due to use of raw sockets and `SIO_RCVALL`)
- Admin rights required to capture packets

---

## Getting Started

```bash
# Clone repo
git clone https://github.com/twanknip/Sniffer.git
cd Sniffer

# Run sniffer
python main.py

# Run Dashboard
npm start
