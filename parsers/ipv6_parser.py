import struct
import socket


class IPv6Header:
    def __init__(self, raw_data: bytes):
        # IPv6 header format:
        # 0 - 3: Version (4 bits), Traffic class (8 bits), Flow label (20 bits)
        # 4 - 7: Payload length (16 bits), Next header (8 bits), Hop limit (8 bits)
        # 8 - 23: Source address (128 bits)
        # 24 - 39: Destination address (128 bits)

        # Unpack the first 40 bytes of data for the IPv6 header
        unpacked_data = struct.unpack("!4sHBB16s16s", raw_data[:40])

        # Version, Traffic Class, and Flow Label
        version_tc_fl = unpacked_data[0]
        self.version = (version_tc_fl[0] >> 4) & 0x0F
        self.traffic_class = ((version_tc_fl[0] & 0x0F) << 4) | (version_tc_fl[1] >> 4)
        self.flow_label = ((version_tc_fl[1] & 0x0F) << 16) | (version_tc_fl[2] << 8) | version_tc_fl[3]

        # Payload Length, Next Header, Hop Limit
        self.payload_length = unpacked_data[1]
        self.next_header = unpacked_data[2]
        self.hop_limit = unpacked_data[3]

        # Source and Destination Addresses
        self.source = socket.inet_ntop(socket.AF_INET6, unpacked_data[4])
        self.dest = socket.inet_ntop(socket.AF_INET6, unpacked_data[5])

        self.payload = raw_data[40:]

    def display(self):
        print("IPv6 Header:")
        print(f"Version: {self.version}, Traffic Class: {self.traffic_class}, Flow Label: {self.flow_label}")
        print(f"Payload Length: {self.payload_length}, Next Header: {self.next_header}, Hop Limit: {self.hop_limit}")
        print(f"Source Address: {self.source}, Destination Address: {self.dest}")
