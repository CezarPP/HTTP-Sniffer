import struct
import socket


class IPHeader:
    """
    A class for parsing and displaying the IP header of a network packet.

    Attributes:
        version (int): The IP version number.
        ihl (int): Internet Header Length, the length of the IP header in bytes.
        ttl (int): Time to Live, indicating the remaining hops before the packet is discarded.
        protocol (int): The protocol used in the data portion of the IP datagram.
        source (str): The source IP address in human-readable format.
        dest (str): The destination IP address in human-readable format.
        payload (bytes): The raw payload data following the IP header.

    Methods:
        display(): Prints the parsed IP header information.

    Usage:
        - Initialize with raw byte data representing an IP packet.
        - Parses the IP header and extracts fields like version, source IP, destination IP, etc.
        - Provides a method to display the parsed information in a human-readable format.

    Note:
        The IP header includes fields like version, header length, TTL, and protocol, which are crucial
        for routing and delivery of IP packets. The header also includes source and destination IP addresses:

        ++++          ++++                        ++++++++                    16 - 31
        Version       Header length (IHL)         Type of Service             Total length
                          Identification                                      0, DF. MF, Fragment offset
              TTL                                 Protocol                    Header Checksum
                                                Source Address
                                                Destination Address
    """

    def __init__(self, raw_data: bytes):
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
