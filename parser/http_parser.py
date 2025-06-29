def hex_ascii_dump(data: bytes, length=16):
    lines = []
    for i in range(0, len(data), length):
        chunk = data[i:i+length]
        hex_bytes = ' '.join(f"{b:02X}" for b in chunk)
        ascii_bytes = ''.join((chr(b) if 32 <= b <= 126 else '.') for b in chunk)
        lines.append(f"{hex_bytes:<{length*3}}  {ascii_bytes}")
    return '\n'.join(lines)

def parse_http(payload: bytes):
    try:
        # Attempt to decode the payload from bytes to string using UTF-8
        # Ignore any decoding errors to avoid crashes
        text = payload.decode('utf-8', errors='ignore')
        
        # Split the decoded HTTP message into individual lines
        lines = text.splitlines()

        # Basic validation: check if the first line starts with an HTTP method (GET or POST)
        # or is an HTTP response (starts with HTTP/)
        if lines and (lines[0].startswith("GET") or lines[0].startswith("POST") or lines[0].startswith("HTTP/")):
            header_lines = []

            # Loop through the lines until an empty line is found (marks end of HTTP headers)
            for line in lines:
                if line.strip() == "":
                    break  # End of HTTP headers
                header_lines.append(line)
            
            # Return the collected HTTP headers as a single string, and hex dump
            return '\n'.join(header_lines), hex_ascii_dump(payload)
        else:
            # If it’s not a valid HTTP GET, POST or response, return None and the hex dump
            return None, hex_ascii_dump(payload)
    except Exception:
        # If any unexpected error occurs (e.g., decoding issue), return None and hex dump
        return None, hex_ascii_dump(payload)
