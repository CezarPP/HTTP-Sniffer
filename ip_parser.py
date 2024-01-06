import struct
import socket


def parse_ipv4_header(raw_data):
    # IP header:
    # ++++          ++++                        ++++++++                    16 - 31
    # Version       Header length (IHL)         Type of Service             Total length
    #                   Identification                                      0, DF. MF, Fragment offset
    #       TTL                                 Protocol                    Header Checksum
    #                                         Source Address
    #                                         Destination Address
    ip_header = struct.unpack("!BBHHHBBH4s4s", raw_data[:20])
    version_and_ihl = ip_header[0]
    version = version_and_ihl >> 4
    ihl = (version_and_ihl & 0x0F) * 4
    ttl = ip_header[5]
    protocol = ip_header[6]
    source_ip = socket.inet_ntoa(ip_header[8])
    destination_ip = socket.inet_ntoa(ip_header[9])
    return version, ihl, ttl, protocol, source_ip, destination_ip, raw_data[ihl:]


def print_ipv4_header(version, ihl, ttl, protocol, source_ip, destination_ip):
    print(f"IP header:")
    print(f"Version: {version}, IHL: {ihl}, TTL: {ttl}, Protocol: {protocol}")
    print(f"Source IP: {source_ip}, Destination IP: {destination_ip}")
