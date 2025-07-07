import socket, struct, time

# Class packet, When making the parsing i get IP-header, TCP/UDP header + payload.
class Packet:
    def __init__(self, raw_data):
        self.timestamp = time.time()
        self.raw_data = raw_data
        self.protocol, self.ip_header_len, self.src_ip, self.dest_ip = self.parse_ip_header()
        self.payload = None

        if self.protocol == 6:  # TCP
            self.src_port, self.dest_port, self.flags = self.parse_tcp_header()
            self.payload = self.get_payload_tcp()
        elif self.protocol == 17:  # UDP
            self.src_port, self.dest_port, self.length = self.parse_udp_header()
            self.payload = self.get_payload_udp()
        else:
            self.src_port = None
            self.dest_port = None
            self.flags = None
            self.length = None

    # Ip header parsing -> reading the first 20 bytes for getting the information.
    # When reading the headerlength we can decide it is TCP or UDP.
    def parse_ip_header(self):
        ip_header = struct.unpack('!BBHHHBBH4s4s', self.raw_data[:20])
        version_ihl = ip_header[0]
        ihl = version_ihl & 0x0F
        ip_length = ihl * 4
        protocol = ip_header[6]
        src_ip = socket.inet_ntoa(ip_header[8])
        dest_ip = socket.inet_ntoa(ip_header[9])
        return protocol, ip_length, src_ip, dest_ip

    # Reading the TCP header directly after the [seld.ip_header_len] -> TCP-flags (SYN, ACK, FIN, etc.).
    # This allows you to see which ports are involved and what type of TCP communication is being used.
    def parse_tcp_header(self):
        tcp_header = struct.unpack('!HHLLBBHHH', self.raw_data[self.ip_header_len:self.ip_header_len+20])
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

    # UDP-header parsing, reading the header out of the 8 bytes after the IP-header.
    # UDP has a shorter header than TCP, but you still want to know where the payload starts and which ports it uses.
    def parse_udp_header(self):
        udp_header = struct.unpack('!HHHH', self.raw_data[self.ip_header_len:self.ip_header_len+8])
        src_port = udp_header[0]
        dest_port = udp_header[1]
        length = udp_header[2]
        return src_port, dest_port, length

    # Payload is the “content” of the packet, everything after the headers.
    # Payload allows you to analyze what exactly is being sent (e.g. HTTP data, DNS queries).
    # You can now also print hex + ASCII to inspect the data.
    def get_payload_tcp(self):
        tcp_header_len = (self.raw_data[self.ip_header_len + 12] >> 4) * 4
        start = self.ip_header_len + tcp_header_len
        return self.raw_data[start:]

    def get_payload_udp(self):
        start = self.ip_header_len + 8
        return self.raw_data[start:]

    # Prints up to 64 bytes of the payload in hex and as human-readable ASCII (unreadable chars as .)
    # Provides immediate insight into what is in the payload without making it unreadable.
    # Useful for debugging and analysis.
    def payload_to_str(self, max_len=64):
        if not self.payload:
            return ""
        # Print max_len bytes in hex + ASCII (printable chars)
        payload = self.payload[:max_len]
        hex_str = ' '.join(f"{b:02x}" for b in payload)
        ascii_str = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload)
        return f"Hex: {hex_str}\nASCII: {ascii_str}"
