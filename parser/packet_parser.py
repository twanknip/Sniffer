from protocols.http import parse_http

def is_printable_ascii(byte):
    """Check if a byte is a printable ASCII character."""
    return 32 <= byte <= 126

def format_hex_ascii(data):
    """Return a tuple of hex string and ASCII representation for given bytes."""
    hex_part = ' '.join(f'{b:02x}' for b in data)
    ascii_part = ''.join(chr(b) if is_printable_ascii(b) else '.' for b in data)
    return hex_part.upper(), ascii_part

def parse_ssdp(data):
    """Parse SSDP packets if recognized."""
    try:
        text = data.decode(errors='ignore')
        if text.startswith('M-SEARCH') or text.startswith('HTTP/1.1'):
            lines = text.split('\r\n')
            return "SSDP Message:\n" + '\n'.join(f"  {line}" for line in lines if line)
    except:
        pass
    return None

def parse_dns(data):
    """Naive mDNS/DNS query detection and parse domain names."""
    try:
        # Simple mDNS query detection by checking fixed header fields
        if data[2:4] == b'\x00\x00' and data[4:6] == b'\x00\x01':
            idx = 12
            labels = []
            while data[idx] != 0:
                length = data[idx]
                labels.append(data[idx+1:idx+1+length].decode(errors='ignore'))
                idx += 1 + length
            domain = '.'.join(labels)
            return f"DNS Query: {domain}"
    except:
        pass
    return None

def parse_payload(data, src_port, dst_port, protocol):
    """
    Parse payload based on protocol and ports.
    For UDP: detect SSDP and DNS.
    For TCP: parse HTTP using http_parser.
    If no known protocol detected, return hex and ASCII dump.
    """
    parsed = None
    if protocol == 'UDP':
        if dst_port == 1900:
            parsed = parse_ssdp(data)
        elif dst_port in (5353, 53):
            parsed = parse_dns(data)
    elif protocol == 'TCP':
        parsed = parse_http(data)  # Use HTTP parser from protocols.http

    if parsed:
        return parsed
    else:
        hex_str, ascii_str = format_hex_ascii(data)
        return f"Hex: {hex_str}\nASCII: {ascii_str}"
