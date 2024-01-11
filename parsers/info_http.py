class InfoHTTP:
    """
    A class to store and manage HTTP request and response data.

    Attributes:
        url (str): The URL in the HTTP request.
        http_method (str): The HTTP method used in the request.
        status_code (int): The status code from the HTTP response.
        status_message (str): The status message associated with the response status code.
        headers (list): A list of tuples containing headers and their values.
        http_version (str): The HTTP version used.
        body (bytes): The body of the HTTP message.

    Methods:
        on_request(url: bytes, http_method: bytes): Processes the request line from an HTTP request.
        on_response(status_code: bytes, status_message: bytes): Processes the status line from an HTTP response.
        on_header(name: bytes, value: bytes): Adds a header to the headers list.
        on_body(body: bytes): Appends the given bytes to the message body.
        is_request(): Determines if the parsed message is an HTTP request.
        display(): Prints the parsed HTTP message.

    Usage:
        - Used by the HttpParser to store and manipulate parsed HTTP request and response data.
        - The parser callbacks update the attributes of this object as it parses an HTTP message.
    """

    def __init__(self):
        # Request
        self.url: str = ''
        self.http_method: str = ''
        # Response
        self.status_code: int = 0
        self.status_message: str = ''

        # Common
        self.headers = []
        self.http_version: str = ''
        self.body = b''

    # parser callbacks
    def on_request(self, url: bytes, http_method: bytes) -> None:
        self.http_method: str = http_method.decode("utf-8")
        self.url: str = url.decode("utf-8")
        self.headers = []

    def on_response(self, status_code: bytes, status_message: bytes) -> None:
        self.status_code: int = int(status_code)
        self.status_message: str = status_message.decode("utf-8")

    def on_header(self, name: bytes, value: bytes) -> None:
        self.headers.append((name.decode("utf-8"), value.decode("utf-8")))

    def on_body(self, body: bytes) -> None:
        self.body += body

    def is_request(self) -> bool:
        if len(self.http_method) >= 3:
            return True
        return False

    def display(self) -> None:
        print("Displaying HTTP message...")
        if self.is_request():
            print(f'Request method: {self.http_method}')
            print(f'Request URL: {self.url}')
        else:
            print(f'Response status code: {self.status_code}')
            print(f'Response status message: {self.status_message}')

        print(f'Request headers: {self.headers}')
        print(f'Response body: {self.body}')
