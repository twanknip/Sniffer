import socket
import threading
from flask import Flask
from flask_socketio import SocketIO
from packet import Packet

# Initialize Flask application and configure secret key
app = Flask(__name__)
app.config['SECRET_KEY'] = 'secret!'  # Secret key used by Flask for session security

# Create a SocketIO instance with CORS allowed for all origins
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

def sniff_packets():
    # Determine local IP address to bind the sniffer socket
    local_ip = socket.gethostbyname(socket.gethostname())

    # Create a raw socket to capture all IPv4 traffic
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind((local_ip, 0))  # Bind to local IP on any port
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # Include IP headers in captured packets
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # Enable promiscuous mode (Windows‑specific)

    print(f"[✓] Sniffer started on {local_ip}")

    try:
        while True:
            # Receive a raw packet (up to 65,565 bytes)
            raw_data, _ = sniffer.recvfrom(65565)
            packet = Packet(raw_data)  # Parse raw bytes into Packet object

            # Map protocol numbers to human‑readable names
            protocol_map = {6: "TCP", 17: "UDP"}
            protocol = protocol_map.get(packet.protocol, "Other")

            # Convert payload bytes to string; fall back if decoding fails
            try:
                payload_str = packet.payload_to_str()
            except Exception:
                payload_str = "[unreadable payload]"

            # Prepare dictionary to send to front‑end
            data = {
                "protocol": protocol,
                "src_ip": packet.src_ip,
                "src_port": packet.src_port,
                "dest_ip": packet.dest_ip,
                "dest_port": packet.dest_port,
                "payload": payload_str[:200]  # Truncate long payloads for performance
            }

            socketio.emit('packet', data)  # Emit packet to all connected SocketIO clients

    except KeyboardInterrupt:
        print("\n[!] Sniffer stopped by user.")
    finally:
        # Always disable promiscuous mode when exiting
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass  # Ignore errors during cleanup

# Simple health‑check route
@app.route('/')
def index():
    return "Packet sniffer backend is running."

if __name__ == '__main__':
    # Run packet sniffer in a background thread
    threading.Thread(target=sniff_packets, daemon=True).start()
    # Start Flask + SocketIO server
    socketio.run(app, host='0.0.0.0', port=5000)
