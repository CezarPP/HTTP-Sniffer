from .split_buffer import SplitBuffer
from parsers.info_http import InfoHTTP

# Request format:
# METHOD        path        version


# Response format:
# HTTP/1.1      status code         response

# If Content-Length header is present, we can expect a body after the empty line
# Also, current line might not be complete, because we sequentially receive data

# b"GET /index.html HTTP/1.1\r\n
# Host: localhost:5000\r\n
# User-Agent: curl/7.69.1\r\n
# Accept: */*\r\n\r\n"

HTTP_METHODS = [b'GET', b'POST', b'PUT', b'DELETE', b'HEAD', b'OPTIONS', b'PATCH', b'TRACE', b'CONNECT']


class HttpParser:
    """
    A parser for HTTP request and response messages.

    Attributes:
        info_http (InfoHTTP): An object to handle parsed information.
        buffer (SplitBuffer): Buffer to manage the incoming byte stream.
        done_parsing_start (bool): Indicates if the start line of HTTP message is parsed.
        done_parsing_headers (bool): Indicates if the headers of the HTTP message are parsed.
        is_message_complete (bool): Indicates if the entire HTTP message is parsed.
        expected_body_length (int): The expected length of the body content in bytes.

    Methods:
        feed_data(data: bytes): Feeds incoming data to the buffer and triggers parsing.
        parse(): Main parsing function, orchestrates the parsing of different parts of the HTTP message.
        parse_header(): Parses HTTP headers.
        parse_line_start(): Parses the start line of an HTTP message.

    Usage:
        - Initialize an instance with an InfoHTTP object.
        - Continuously feed byte data to the parser using `feed_data`.
        - The parser will sequentially parse the HTTP message, updating the InfoHTTP object.
    """

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
    """
    Determines if the given data is the start of an HTTP message.

    Args:
        data (bytes): The data to be checked.

    Returns:
        bool: True if the data starts with an HTTP method or an HTTP version, False otherwise.

    Usage:
        - Call with a byte stream to check if it's likely to be the start of an HTTP message.
    """
    return (any(data.startswith(method) for method in HTTP_METHODS)
            or data.lower().startswith(b'http'))
