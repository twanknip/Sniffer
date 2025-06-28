def parse_http(payload: bytes):
    try:
        # Attempt to decode the payload from bytes to string using UTF-8
        # Ignore any decoding errors to avoid crashes
        text = payload.decode('utf-8', errors='ignore')
        
        # Split the decoded HTTP message into individual lines
        lines = text.splitlines()

        # Basic validation: check if the first line starts with an HTTP method (GET or POST)
        if lines and (lines[0].startswith("GET") or lines[0].startswith("POST")):
            header_lines = []

            # Loop through the lines until an empty line is found (marks end of HTTP headers)
            for line in lines:
                if line.strip() == "":
                    break  # End of HTTP headers
                header_lines.append(line)
            
            # Return the collected HTTP headers as a single string
            return '\n'.join(header_lines)
        else:
            # If it’s not a valid HTTP GET or POST request, return None
            return None
    except Exception as e:
        # If any unexpected error occurs (e.g., decoding issue), return None
        return None
