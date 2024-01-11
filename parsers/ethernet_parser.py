import struct


class EthernetHeader:
    """
    A class for parsing and displaying the Ethernet header of a network packet.

    Attributes:
        destination_mac (str): The destination MAC address in human-readable format.
        source_mac (str): The source MAC address in human-readable format.
        ethernet_type (int): The Ethernet type (EtherType) field indicating the protocol encapsulated in the payload.
        payload (bytes): The raw payload data following the Ethernet header.

    Methods:
        display(): Prints the parsed Ethernet header information.

    Usage:
        - Initialize with raw byte data representing an Ethernet frame.
        - Parses the Ethernet header and extracts relevant fields.
        - Provides a method to display the parsed information in a human-readable format.

    Note:
        The Ethernet header consists of a 6-byte destination MAC address, a 6-byte source MAC address,
        and a 2-byte EtherType field:
        6 bytes                    6 bytes              2 bytes
        destination MAC           Source MAC          Ethernet type           Data
    """

    def __init__(self, raw_data: bytes):
        self.destination_mac, self.source_mac, self.ethernet_type = struct.unpack("! 6s 6s H", raw_data[:14])
        self.destination_mac: str = ":".join(f"{byte:02x}" for byte in self.destination_mac)
        self.source_mac: str = ":".join(f"{byte:02x}" for byte in self.source_mac)
        self.payload = raw_data[14:]

    def display(self) -> None:
        print(f"Ethernet header:")
        print(
            f"Destination MAC: {self.destination_mac}, Source MAC: {self.source_mac}"
            f", EtherType: {hex(self.ethernet_type)}")
