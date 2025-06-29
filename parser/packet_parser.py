import binascii

def is_printable_ascii(byte):
    return 32 <= byte <= 126

def format_hex_ascii(data):
    hex_part = ' '.join(f'{b:02x}' for b in data)
    ascii_part = ''.join(chr(b) if is_printable_ascii(b) else '.' for b in data)
    return hex_part.upper(), ascii_part

def parse_ssdp(data):
    try:
        text = data.decode(errors='ignore')
        if text.startswith('M-SEARCH') or text.startswith('HTTP/1.1'):
            lines = text.split('\r\n')
            return "SSDP Message:\n" + '\n'.join(f"  {line}" for line in lines if line)
    except:
        pass
    return None

def parse_dns(data):
    try:
        # Naive mDNS query detection based op qname parsable als ASCII domeinnaam
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

def parse_http(data):
    try:
        text = data.decode(errors='ignore')
        if text.startswith(('GET', 'POST', 'HTTP/')):
            lines = text.split('\r\n')
            return "HTTP Message:\n" + '\n'.join(f"  {line}" for line in lines if line)
    except:
        pass
    return None

def parse_tls(data):
    if len(data) > 5 and data[0] in (20, 21, 22, 23) and data[1] == 3 and data[2] in (0,1,2,3):
        return f"TLS Encrypted Data ({len(data)} bytes)"
    return None

def parse_payload(data, src_port, dst_port, protocol):
    # Check known protocol types
    parsed = None
    if protocol == 'UDP':
        if dst_port == 1900:
            parsed = parse_ssdp(data)
        elif dst_port == 5353 or dst_port == 53:
            parsed = parse_dns(data)
    elif protocol == 'TCP':
        parsed = parse_http(data)
        if not parsed:
            parsed = parse_tls(data)

    if parsed:
        return parsed
    else:
        hex_str, ascii_str = format_hex_ascii(data)
        return f"Hex: {hex_str}\nASCII: {ascii_str}"

# Voorbeeld gebruik:
# parsed = parse_payload(payload_bytes, 49992, 8009, 'TCP')
# print(parsed)
