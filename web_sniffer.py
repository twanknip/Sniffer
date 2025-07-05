import socket
import threading
from flask import Flask
from flask_socketio import SocketIO
from packet import Packet
from parser.packet_parser import parse_payload  
from protocols.http import parse_http            


app = Flask(__name__)
# Allow any origin to connect via websockets 
socketio = SocketIO(app, cors_allowed_origins="*")


#  Core packet‑sniffer loop (runs in background thread)


def start_sniffer() -> None:
    """Capture all inbound/outbound IPv4 packets on the local NIC and
    stream a subset (TCP/UDP) to the web front‑end via Socket.IO."""

    # Determine the local IP address to bind the raw socket
    local_ip = socket.gethostbyname(socket.gethostname())

    # Create a raw socket, AF_INET = IPv4, SOCK_RAW = raw frames
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind((local_ip, 0))                  # Bind to our IP on any port
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # Include IP headers
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)           # Enable promiscuous mode

    print(f"[✓] Live sniffer started on {local_ip}")

    try:
        while True:
            # Receive a single raw frame 
            raw_data, _ = sniffer.recvfrom(65565)
            packet = Packet(raw_data)  # Convert to our higher‑level Packet object

            # Send only TCP (6) and UDP (17) packets to the UI; skip others
            if packet.protocol in (6, 17):
                protocol = "TCP" if packet.protocol == 6 else "UDP"

                # Human‑readable payload — try a custom parser first, fallback to raw string
                try:
                    payload_str = parse_payload(packet) or packet.payload_to_str()
                except Exception:
                    payload_str = "[unreadable payload]"

                # Special case: if HTTP traffic, attempt to parse for extra insight
                if protocol == "TCP":
                    http_info = parse_http(packet.payload)
                    if http_info:
                        payload_str = http_info  # Replace with prettified HTTP summary

                # Build minimal data dict for the front‑end table
                data = {
                    "src_ip":   packet.src_ip,
                    "dest_ip":  packet.dest_ip,
                    "src_port": packet.src_port,
                    "dest_port": packet.dest_port,
                    "protocol": protocol,
                    "length":   packet.length,
                    "payload":  payload_str[:200]  # Truncate long payloads for perf
                }

                # Emit to all connected Socket clients
                socketio.emit("packet", data)

    except KeyboardInterrupt:
        print("\n[!] Sniffer stopped by user.")

    finally:
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass  # Ignore cleanup errors



@app.route("/")
def index() -> str:
    return "Packet sniffer backend is running…"



if __name__ == "__main__":
    # Daemon thread so the program can exit cleanly when Flask shuts down
    threading.Thread(target=start_sniffer, daemon=True).start()

    # Expose on 0.0.0.0 so front‑end can connect from anywhere in the LAN
    socketio.run(app, host="0.0.0.0", port=5000)
