from .split_buffer import *
from parser_protocol import *

# Request format:
# METHOD        path        version


# Response format:
# HTTP/1.1      status code         response

# If Content-Length header is present, we can expect a body after the empty line
# Also, current line might not be complete, because we sequentially receive data

# b"GET /index.html HTTP/1.1\r\nHost: localhost:5000\r\nUser-Agent: curl/7.69.1\r\nAccept: */*\r\n\r\n"

HTTP_METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT']


class HttpParser:
    def __init__(self, protocol: ParserProtocol):
        self.protocol: ParserProtocol = protocol
        self.buffer = SplitBuffer()
        self.done_parsing_start: bool = False
        self.done_parsing_headers: bool = False
        self.is_message_complete: bool = False
        self.expected_body_length: int = 0

    def feed_data(self, data: bytes):
        self.buffer.feed_data(data)
        self.parse()

    def parse(self):
        if not self.done_parsing_start:
            self.parse_line_start()
        elif not self.done_parsing_headers:
            self.parse_header()
        elif self.expected_body_length and not self.buffer.is_empty():
            data = self.buffer.flush()
            self.expected_body_length -= len(data)
            self.protocol.on_body(data)
            self.parse()
        elif self.expected_body_length == 0:
            self.is_message_complete = True

    def parse_header(self):
        line = self.buffer.pop(separator=b"\r\n")
        if line is not None:
            if line:
                name, value = line.strip().split(b": ", maxsplit=1)
                if name.lower() == b"content-length":
                    self.expected_body_length = int(value.decode("utf-8"))
                    print("INITIAL EXPECTED BODY LENGTH {}".format(self.expected_body_length))
                self.protocol.on_header(name, value)
            else:
                self.done_parsing_headers = True
            self.parse()

    def parse_line_start(self):
        line = self.buffer.pop(separator=b"\r\n")
        if line is not None:
            line_parts = line.strip().split()
            http_method = line_parts[0]
            print(f'METHOD IS {http_method.decode("utf-8")}')

            if http_method.decode("utf-8") in HTTP_METHODS:
                # HTTP REQUEST
                self.protocol.http_version = line_parts[2]
                self.protocol.on_request(url=line_parts[1], http_method=http_method)
            else:
                print(f"RESPONSE WITH METHOD {http_method}")
                # HTTP RESPONSE
                self.protocol.http_version = line_parts[0]
                self.protocol.on_response(status_code=line_parts[1], status_message=b' '.join(line_parts[2:]))

            self.done_parsing_start = True
            self.parse()


def is_http_data(data: bytes) -> bool:
    try:
        text = data.decode('ascii')
        if any(text.startswith(method) for method in HTTP_METHODS) or text.lower().startswith('http/'):
            return True
    except UnicodeDecodeError:
        # If data can't be decoded to ASCII, it's not HTTP
        pass
    return False
