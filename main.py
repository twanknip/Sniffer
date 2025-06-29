import socket
from packet import Packet
from protocols.http import parse_http
from parser.packet_parser import parse_payload
import argparse


def main():
    # Argument parser to handle command-line options
    parser = argparse.ArgumentParser(description="Simple packet sniffer")
    parser.add_argument('--tls', action='store_true', help='Display encrypted TLS/HTTPS traffic (port 443)')
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

            if packet.protocol == 6:  # TCP
                # Optionally skip TLS (port 443) unless --tls is passed
                if not args.tls and (packet.src_port == 443 or packet.dest_port == 443):
                    continue

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

            # Check if the protocol is UDP (protocol number 17)
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
