import socket
import struct

def parse_ip_header(data):
    ip_header = struct.unpack('!BBHHHBBH4s4s', data[:20])
    version_ihl = ip_header[0]
    ihl = version_ihl & 0x0F
    ip_length = ihl * 4
    protocol = ip_header[6]
    src_ip = socket.inet_ntoa(ip_header[8])
    dest_ip = socket.inet_ntoa(ip_header[9])
    return protocol, ip_length, src_ip, dest_ip

def parse_tcp_header(data):
    tcp_header = struct.unpack('!HHLLBBHHH', data[:20])
    src_port = tcp_header[0]
    dest_port = tcp_header[1]
    flags = tcp_header[5]
    flag_list = []
    if flags & 0x01: flag_list.append("FIN")
    if flags & 0x02: flag_list.append("SYN")
    if flags & 0x04: flag_list.append("RST")
    if flags & 0x08: flag_list.append("PSH")
    if flags & 0x10: flag_list.append("ACK")
    if flags & 0x20: flag_list.append("URG")
    return src_port, dest_port, flag_list

def parse_udp_header(data):
    udp_header = struct.unpack('!HHHH', data[:8])
    src_port = udp_header[0]
    dest_port = udp_header[1]
    length = udp_header[2]
    return src_port, dest_port, length

def main():
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind((socket.gethostbyname(socket.gethostname()), 0))  
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    try:
        while True:
            raw_data, _ = sniffer.recvfrom(65565)
            protocol, ip_header_len, src_ip, dest_ip = parse_ip_header(raw_data)

            if protocol == 6:  # TCP
                tcp_start = ip_header_len
                tcp_data = raw_data[tcp_start:]
                src_port, dest_port, flags = parse_tcp_header(tcp_data)
                print(f"TCP {src_ip}:{src_port} -> {dest_ip}:{dest_port} | Flags={','.join(flags)}")

            elif protocol == 17:  # UDP
                udp_start = ip_header_len
                udp_data = raw_data[udp_start:]
                src_port, dest_port, length = parse_udp_header(udp_data)
                print(f"UDP {src_ip}:{src_port} -> {dest_ip}:{dest_port} | Length={length} bytes")

            else:
                print(f"Other {src_ip} -> {dest_ip} | Protocol={protocol}")

    except KeyboardInterrupt:
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
        print("\nSniffer stopped.")
        

if __name__ == "__main__":
    main()
