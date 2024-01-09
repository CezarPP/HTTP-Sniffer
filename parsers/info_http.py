class InfoHTTP:
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
