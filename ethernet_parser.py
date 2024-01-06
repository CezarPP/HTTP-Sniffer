import struct


def parse_ethernet_header(raw_data):
    # Ethernet header:
    # 6 bytes                    6 bytes              2 bytes
    # destination MAC           Source MAC          Ethernet type           Data
    destination_mac, source_mac, ethernet_type = struct.unpack("! 6s 6s H", raw_data[:14])
    destination_mac = ":".join(f"{byte:02x}" for byte in destination_mac)
    source_mac = ":".join(f"{byte:02x}" for byte in source_mac)
    return destination_mac, source_mac, ethernet_type, raw_data[14:]
