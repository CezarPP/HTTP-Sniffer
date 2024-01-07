class SplitBuffer:
    def __init__(self):
        self.data = b""

    def feed_data(self, data: bytes) -> None:
        self.data += data

    def pop(self, separator: bytes) -> bytes | None:
        first, *rest = self.data.split(separator, maxsplit=1)
        # no split was possible
        if not rest:
            return None
        else:
            self.data = separator.join(rest)
            return first

    def is_empty(self) -> bool:
        return self.data == b""

    def flush(self) -> bytes:
        temp = self.data
        self.data = b""
        return temp
