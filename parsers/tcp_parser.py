import struct


class TCPHeader:
    """
    A class for parsing and displaying the TCP header of a network packet.

    Attributes:
        source_port (int): The source port number.
        dest_port (int): The destination port number.
        sequence (int): The sequence number of the first data byte in this segment.
        acknowledgment (int): If the ACK flag is set, this field contains the value of the next sequence number.
        offset (int): The size of the TCP header in bytes.
        flag_ack (int): The acknowledgment flag.
        flag_syn (int): The synchronize sequence numbers flag.
        flag_fin (int): The finish flag indicating the sender has finished sending data.
        window (int): The size of the received window.
        checksum (int): The checksum used for error-checking of the header and data.
        payload (bytes): The raw payload data following the TCP header.

    Methods:
        display(): Prints the parsed TCP header information.

    Usage:
        - Initialize with raw byte data representing a TCP packet.
        - Parses the TCP header and extracts fields such as source port, destination port, sequence number, etc.
        - Provides a method to display the parsed information in a human-readable format.

    Note:
        The TCP header is crucial for the control and management of TCP segments in network communication.
        It contains information for data transmission control, error checking, and data flow management:

                2 bytes                    2 bytes
             Source Port             Destination port
                       Sequence number
                       Ack Number
        ++++     +++  +++++++++
        offset           flags        window size
              checksum                urgent ptr
                         options
                          data
    """

    def __init__(self, raw_data: bytes):
        (self.source_port, self.dest_port, self.sequence, self.acknowledgment, offset_reserved_flags) = struct.unpack(
            '!HHLLH', raw_data[:14])
        self.offset: int = (offset_reserved_flags >> 12) * 4
        # flag_urg = (offset_reserved_flags & 32) >> 5
        self.flag_ack: int = (offset_reserved_flags & 16) >> 4
        # flag_psh = (offset_reserved_flags & 8) >> 3
        # flag_rst = (offset_reserved_flags & 4) >> 2
        self.flag_syn: int = (offset_reserved_flags & 2) >> 1
        self.flag_fin: int = offset_reserved_flags & 1
        self.window: int = struct.unpack('!H', raw_data[14:16])[0]
        self.checksum: int = struct.unpack('!H', raw_data[16:18])[0]
        # urgent_pointer = struct.unpack('!H', raw_data[18:20])[0]
        self.payload: bytes = raw_data[self.offset:]

    def display(self):
        print(f"TCP Header:")
        print(f"Source Port: {self.source_port}, Destination Port: {self.dest_port}")
        print(f"Sequence Number: {self.sequence}, Acknowledgment Number: {self.acknowledgment}")
        print(
            f"Flags: ACK: {self.flag_ack}, SYN: {self.flag_syn}, FIN: {self.flag_fin}")
        print(f"Window Size: {self.window}, Checksum: {self.checksum}")
