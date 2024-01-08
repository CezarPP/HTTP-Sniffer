import struct


class EthernetHeader:
    def __init__(self, raw_data: bytes):
        # Ethernet header:
        # 6 bytes                    6 bytes              2 bytes
        # destination MAC           Source MAC          Ethernet type           Data
        self.destination_mac, self.source_mac, self.ethernet_type = struct.unpack("! 6s 6s H", raw_data[:14])
        self.destination_mac: str = ":".join(f"{byte:02x}" for byte in self.destination_mac)
        self.source_mac: str = ":".join(f"{byte:02x}" for byte in self.source_mac)
        self.payload = raw_data[14:]

    def display(self) -> None:
        print(f"Ethernet header:")
        print(
            f"Destination MAC: {self.destination_mac}, Source MAC: {self.source_mac}"
            f", EtherType: {hex(self.ethernet_type)}")
