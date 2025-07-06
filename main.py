import socket
import threading
import logging
import os
from queue import Queue, Empty
from flask import Flask
from flask_socketio import SocketIO
from packet import Packet

# Initialize Flask application and configure secret key
app = Flask(__name__)
app.config['SECRET_KEY'] = os.getenv('FLASK_SECRET', 'secret!')  # Secret key used by Flask for session security

# Create a SocketIO instance with CORS allowed for all origins
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# Create a thread-safe queue to decouple sniffing from emitting
packet_queue = Queue(maxsize=5000)

# Global event for clean shutdown
stop_event = threading.Event()

# Map protocol numbers to human-readable names
protocol_map = {6: "TCP", 17: "UDP"}

# Set up logging instead of print
logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s in %(threadName)s: %(message)s'
)

def sniff_packets(stop_evt: threading.Event):
    # Determine local IP address to bind the sniffer socket
    local_ip = socket.gethostbyname(socket.gethostname())

    try:
        # Create a raw socket to capture all IPv4 traffic
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        sniffer.bind((local_ip, 0))  # Bind to local IP on any port
        sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)  # Include IP headers in captured packets
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)  # Enable promiscuous mode (Windows‑specific)

        logging.info(f"Sniffer started on {local_ip}")
    except Exception as e:
        logging.error(f"Failed to initialize sniffer: {e}")
        return

    try:
        while not stop_evt.is_set():
            try:
                # Receive a raw packet (up to 65,565 bytes)
                raw_data, _ = sniffer.recvfrom(65565)
                packet = Packet(raw_data)  # Parse raw bytes into Packet object

                # Map protocol numbers to human‑readable names
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

                # Add parsed packet data to the queue
                packet_queue.put_nowait(data)

            except Exception as e:
                logging.warning(f"Error processing packet: {e}")

    finally:
        # Always disable promiscuous mode when exiting
        try:
            sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        except Exception:
            pass  # Ignore errors during cleanup
        logging.info("Sniffer stopped.")

# Background thread to emit packets to front-end
def emit_packets():
    while not stop_event.is_set():
        try:
            data = packet_queue.get(timeout=1)
            socketio.emit('packet', data)  # Emit packet to all connected SocketIO clients
        except Empty:
            continue
        except Exception as e:
            logging.error(f"Emit failed: {e}")

# Simple health‑check route
@app.route('/')
def index():
    return "Packet sniffer backend is running."

if __name__ == '__main__':
    try:
        # Run packet sniffer in a background thread
        threading.Thread(target=sniff_packets, args=(stop_event,), daemon=True, name="SnifferThread").start()
        # Run emitter in a background thread
        threading.Thread(target=emit_packets, daemon=True, name="EmitThread").start()
        # Start Flask + SocketIO server
        socketio.run(app, host='0.0.0.0', port=5000)
    except KeyboardInterrupt:
        logging.info("KeyboardInterrupt received. Shutting down...")
    finally:
        stop_event.set()
