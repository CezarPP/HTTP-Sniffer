class ParserProtocol:
    def __init__(self):
        # Request
        self.url = b''
        self.http_method = b''

        # Response
        self.status_code = 0
        self.status_message = b''

        # Common
        self.headers = []
        self.http_version = b''
        self.body = b''

    # parser callbacks
    def on_request(self, url: bytes, http_method: bytes):
        print(f"Received url: {url}")
        self.http_method = http_method
        self.url = url
        self.headers = []

    def on_response(self, status_code: bytes, status_message: bytes):
        self.status_code = status_code
        self.status_message = status_message

    def on_header(self, name: bytes, value: bytes):
        print(f"Received header: ({name}, {value})")
        self.headers.append((name, value))

    def on_body(self, body: bytes):
        self.body += body
        print(f"Received body: {body}")

    def is_request(self):
        if len(self.http_method) >= 3:
            return True
        return False

    def display(self):
        print("Displaying HTTP message...")
        if self.is_request():
            print(f'Request method: {self.http_method}')
            print(f'Request URL: {self.url}')
        else:
            print(f'Response status code: {self.status_code}')
            print(f'Response status message: {self.status_message}')

        print(f'Request headers: {self.headers}')
        print(f'Response body: {self.body}')
