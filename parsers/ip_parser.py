import struct
import socket


class IPHeader:
    def __init__(self, raw_data: bytes):
        # IP header:
        # ++++          ++++                        ++++++++                    16 - 31
        # Version       Header length (IHL)         Type of Service             Total length
        #                   Identification                                      0, DF. MF, Fragment offset
        #       TTL                                 Protocol                    Header Checksum
        #                                         Source Address
        #                                         Destination Address
        ip_header = struct.unpack("!BBHHHBBH4s4s", raw_data[:20])
        version_and_ihl = ip_header[0]
        self.version: int = version_and_ihl >> 4
        self.ihl: int = (version_and_ihl & 0x0F) * 4
        self.ttl: int = ip_header[5]
        self.protocol: int = ip_header[6]
        self.source: str = socket.inet_ntoa(ip_header[8])
        self.dest: str = socket.inet_ntoa(ip_header[9])
        self.payload: bytes = raw_data[self.ihl:]

    def display(self):
        print(f"IP header:")
        print(f"Version: {self.version}, IHL: {self.ihl}, TTL: {self.ttl}, Protocol: {self.protocol}")
        print(f"Source IP: {self.source}, Destination IP: {self.dest}")
