class SplitBuffer:
    """
    A class for managing a buffer that accumulates and splits binary data.

    Attributes:
        data (bytes): The accumulated data in the buffer.

    Methods:
        feed_data(data: bytes): Appends more data to the buffer.
        pop(separator: bytes): Splits the buffer at the first occurrence of the given separator.
        is_empty(): Checks if the buffer is empty.
        flush(): Clears the buffer and returns its content.

    Usage:
        - Used to accumulate binary data streams and split or parse the data based on a specified separator.

    Note:
        The class is designed to handle and accumulate binary data.
    """

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
