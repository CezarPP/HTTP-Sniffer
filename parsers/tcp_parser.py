import struct


class TCPHeader:
    def __init__(self, raw_data: bytes):
        #    2 bytes                    2 bytes
        #      Source Port             Destination port
        #                Sequence number
        #                Ack Number
        # ++++     +++  +++++++++
        # offset           flags        window size
        #       checksum                urgent ptr
        #                  options
        #                   data
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
