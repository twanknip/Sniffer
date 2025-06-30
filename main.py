import socket
from packet import Packet
from protocols.http import parse_http
from parser.packet_parser import parse_payload
import argparse


def main():
    # Argument parser to handle command-line options
    parser = argparse.ArgumentParser(description="Simple packet sniffer")
    parser.add_argument('--port', type=int, help='Filter packets by specific port (e.g., 80, 53, 443)')
    parser.add_argument('--dns', action='store_true', help='Filter for DNS traffic only (UDP port 53 or 5353)')
    parser.add_argument('--http', action='store_true', help='Filter for HTTP traffic only (TCP port 80)')
    parser.add_argument('--https', action='store_true', help='Filter for HTTPS traffic only (TCP port 443)')
    args = parser.parse_args()

    # Creates a raw socket that captures all IP packets on the local IP.
    # Dynamic IP
    local_ip = socket.gethostbyname(socket.gethostname())

    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind((local_ip, 0))
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    # Enable promiscuous mode (RCVALL_ON) to receive all packets.
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"Sniffer started on: {local_ip}...")

    try:
        while True:
            raw_data, _ = sniffer.recvfrom(65565)
            packet = Packet(raw_data)

            # Filtering logic based on CLI flags
            if args.port and not (packet.src_port == args.port or packet.dest_port == args.port):
                continue
            if args.dns and not (packet.protocol == 17 and (packet.src_port in (53, 5353) or packet.dest_port in (53, 5353))):
                continue
            if args.http and not (packet.protocol == 6 and (packet.src_port == 80 or packet.dest_port == 80)):
                continue
            if args.https and not (packet.protocol == 6 and (packet.src_port == 443 or packet.dest_port == 443)):
                continue

            if packet.protocol == 6:  # TCP
                print(f"TCP {packet.src_ip}:{packet.src_port} -> {packet.dest_ip}:{packet.dest_port} | Flags={','.join(packet.flags)}")
                print(packet.payload_to_str())

                parsed = parse_payload(packet.payload, packet.src_port, packet.dest_port, "TCP")
                if parsed:
                    print("Parsed payload:")
                    print(parsed)

                # Extra: Show HTTP data for traffic on port 80 or 443
                if packet.src_port in (80, 443) or packet.dest_port in (80, 443):
                    http_info = parse_http(packet.payload)
                    if http_info:
                        print("HTTP:")
                        print(http_info)

            elif packet.protocol == 17:  # UDP
                print(f"UDP {packet.src_ip}:{packet.src_port} -> {packet.dest_ip}:{packet.dest_port} | Length={packet.length} bytes")
                print(packet.payload_to_str())

                parsed = parse_payload(packet.payload, packet.src_port, packet.dest_port, "UDP")
                if parsed:
                    print("Parsed payload:")
                    print(parsed)

            else:
                print(f"Other {packet.src_ip} -> {packet.dest_ip} | Protocol={packet.protocol}")

            print("-" * 80)

    except KeyboardInterrupt:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("\nSniffer stopped.")


if __name__ == "__main__":
    main()
