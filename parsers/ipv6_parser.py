import struct
import socket


class IPv6Header:
    """
    A class for parsing and displaying the IPv6 header of a network packet.

    Attributes:
        version (int): The IPv6 version number.
        traffic_class (int): The traffic class field, related to Quality of Service.
        flow_label (int): The flow label used to identify packets from the same flow.
        payload_length (int): The length of the payload in bytes.
        protocol (int): The next header field, indicating the protocol of the encapsulated payload.
        hop_limit (int): The hop limit, similar to the TTL in IPv4, for limiting the packet's lifetime.
        source (str): The source IPv6 address in human-readable format.
        dest (str): The destination IPv6 address in human-readable format.
        payload (bytes): The raw payload data following the IPv6 header.

    Methods:
        display(): Prints the parsed IPv6 header information.

    Usage:
        - Initialize with raw byte data representing an IPv6 packet.
        - Parses the IPv6 header and extracts various fields such as source and destination addresses, version, etc.
        - Provides a method to display the parsed information in a human-readable format.

    Note:
        The IPv6 header is designed for minimal overhead and includes essential fields like source and destination
        addresses, version, and next header. It is used in routing and managing IPv6 network traffic:

        0 - 3: Version (4 bits), Traffic class (8 bits), Flow label (20 bits)
        4 - 7: Payload length (16 bits), Next header (8 bits), Hop limit (8 bits)
        8 - 23: Source address (128 bits)
        24 - 39: Destination address (128 bits)
    """

    def __init__(self, raw_data: bytes):
        # Unpack the first 40 bytes of data for the IPv6 header
        unpacked_data = struct.unpack("!4sHBB16s16s", raw_data[:40])

        # Version, Traffic Class, and Flow Label
        version_tc_fl = unpacked_data[0]
        self.version = (version_tc_fl[0] >> 4) & 0x0F
        self.traffic_class = ((version_tc_fl[0] & 0x0F) << 4) | (version_tc_fl[1] >> 4)
        self.flow_label = ((version_tc_fl[1] & 0x0F) << 16) | (version_tc_fl[2] << 8) | version_tc_fl[3]

        # Payload Length, Next Header, Hop Limit
        self.payload_length = unpacked_data[1]

        # Actually next header, but for consistency it will also be called protocol
        self.protocol = unpacked_data[2]
        self.hop_limit = unpacked_data[3]

        # Source and Destination Addresses
        self.source = socket.inet_ntop(socket.AF_INET6, unpacked_data[4])
        self.dest = socket.inet_ntop(socket.AF_INET6, unpacked_data[5])

        self.payload = raw_data[40:]

    def display(self):
        print("IPv6 Header:")
        print(f"Version: {self.version}, Traffic Class: {self.traffic_class}, Flow Label: {self.flow_label}")
        print(f"Payload Length: {self.payload_length}, Next Header: {self.protocol}, Hop Limit: {self.hop_limit}")
        print(f"Source Address: {self.source}, Destination Address: {self.dest}")
