import struct


def parse_tcp_header(raw_data: bytes) -> (int, int, int, int, int, int, int, int, bytes):
    #    2 bytes                    2 bytes
    #      Source Port             Destination port
    #                Sequence number
    #                Ack Number
    # ++++     +++  +++++++++
    # offset           flags        window size
    #       checksum                urgent ptr
    #                  options
    #                   data
    (source_port, dest_port, sequence, acknowledgment, offset_reserved_flags) = struct.unpack('!HHLLH', raw_data[:14])
    offset = (offset_reserved_flags >> 12) * 4
    # flag_urg = (offset_reserved_flags & 32) >> 5
    flag_ack = (offset_reserved_flags & 16) >> 4
    # flag_psh = (offset_reserved_flags & 8) >> 3
    # flag_rst = (offset_reserved_flags & 4) >> 2
    flag_syn = (offset_reserved_flags & 2) >> 1
    flag_fin = offset_reserved_flags & 1
    # window = struct.unpack('!H', raw_data[14:16])[0]
    checksum = struct.unpack('!H', raw_data[16:18])[0]
    # urgent_pointer = struct.unpack('!H', raw_data[18:20])[0]

    return source_port, dest_port, sequence, acknowledgment, flag_ack, flag_syn, flag_fin, checksum, raw_data[
                                                                                                     offset:]


def print_tcp_header(source_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn,
                     flag_fin, window, checksum, urgent_pointer):
    print(f"TCP Header:")
    print(f"Source Port: {source_port}, Destination Port: {dest_port}")
    print(f"Sequence Number: {sequence}, Acknowledgment Number: {acknowledgment}")
    print(
        f"Flags: URG: {flag_urg}, ACK: {flag_ack}, PSH: {flag_psh}, RST: {flag_rst}, SYN: {flag_syn}, "
        f"FIN: {flag_fin}")
    print(f"Window Size: {window}, Checksum: {checksum}, Urgent Pointer: {urgent_pointer}")
