from .split_buffer import SplitBuffer
from parsers.info_http import InfoHTTP

# Request format:
# METHOD        path        version


# Response format:
# HTTP/1.1      status code         response

# If Content-Length header is present, we can expect a body after the empty line
# Also, current line might not be complete, because we sequentially receive data

# b"GET /index.html HTTP/1.1\r\nHost: localhost:5000\r\nUser-Agent: curl/7.69.1\r\nAccept: */*\r\n\r\n"

HTTP_METHODS = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH', b'TRACE', b'CONNECT']


class HttpParser:
    def __init__(self, info_http: InfoHTTP):
        self.info_http: InfoHTTP = info_http
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
            self.info_http.on_body(data)
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
                self.info_http.on_header(name, value)
            else:
                self.done_parsing_headers = True
            self.parse()

    def parse_line_start(self):
        line = self.buffer.pop(separator=b"\r\n")
        if line is not None:
            line_parts = line.strip().split()
            http_method: bytes = line_parts[0]

            if http_method in HTTP_METHODS:
                # HTTP REQUEST
                self.info_http.http_version = line_parts[2]
                self.info_http.on_request(url=line_parts[1], http_method=http_method)
            else:
                # HTTP RESPONSE
                self.info_http.http_version = line_parts[0]
                self.info_http.on_response(status_code=line_parts[1], status_message=b' '.join(line_parts[2:]))

            self.done_parsing_start = True
            self.parse()


def is_http_data(data: bytes) -> bool:
    return (any(data.startswith(method) for method in HTTP_METHODS)
            or data.lower().startswith(b'http'))
