from parsers.ethernet_parser import *
from parsers.ip_parser import *
from parsers.tcp_parser import *
from parsers.http_parser import *
from parser_protocol import *

import heapq
import time

start_time = time.time()

# This dictionary will hold the packets for each TCP connection in a min-heap
# The keys will be (source_ip, dest_ip, source_port, dest_port) tuples
tcp_buffers = {}

# This dictionary will hold the next expected sequence number for each TCP connection
next_expected_seq = {}

# This dictionary will hold the HTTP parser for each connection
tcp_http_parser = {}


def process_tcp_packet(ip: IPHeader, tcp: TCPHeader, on_packet_received):
    # print("Processing TCP packet")
    connection_key = (ip.source, ip.dest, tcp.source_port, tcp.dest_port)

    # Initialize buffer and sequence tracking if new connection
    if connection_key not in tcp_buffers:

        if not is_http_data(tcp.payload):
            return

        tcp_buffers[connection_key] = []
        next_expected_seq[connection_key] = tcp.sequence + len(tcp.payload)
        tcp_http_parser[connection_key] = HttpParser(ParserProtocol())
        tcp_http_parser[connection_key].feed_data(tcp.payload)
    else:
        # We have already seen this connection
        # Check if the packet is the next expected one
        if tcp.sequence == next_expected_seq[connection_key]:
            # Process the packet
            tcp_http_parser[connection_key].feed_data(tcp.payload)

            # Update the expected sequence number
            next_expected_seq[connection_key] += len(tcp.payload)

            # Check the buffer for the next packets
            while (tcp_buffers[connection_key]
                   and tcp_buffers[connection_key][0][0] <= next_expected_seq[connection_key]):

                # Handles retransmission
                if tcp_buffers[connection_key][0][0] < next_expected_seq[connection_key]:
                    heapq.heappop(tcp_buffers[connection_key])
                    continue

                _, buffered_payload = heapq.heappop(tcp_buffers[connection_key])
                tcp_http_parser[connection_key].feed_data(buffered_payload)
                next_expected_seq[connection_key] += len(buffered_payload)
        else:
            # Add out-of-order packet to the buffer
            heapq.heappush(tcp_buffers[connection_key], (tcp.sequence, tcp.payload))

    if tcp.flag_fin == 0x1 or tcp_http_parser[connection_key].is_message_complete:
        protocol: ParserProtocol = tcp_http_parser[connection_key].protocol
        protocol.display()

        request_type = protocol.http_method if protocol.is_request() else "HTTP Response"
        on_packet_received(time.time() - start_time, connection_key[0], connection_key[1], request_type,
                           str(protocol.status_code) + " " + protocol.status_message
                           if not protocol.is_request() else "HTTP Request",
                           protocol.body, protocol.headers)
        tcp_buffers.pop(connection_key)
        tcp_http_parser.pop(connection_key)
        next_expected_seq.pop(connection_key)


def create_ipv4_raw_socket():
    try:
        # Only capture IPv4
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    except socket.error as e:
        print(f"Error creating raw socket: {e}")
        return None


def sniff_packets(stop_event, on_packet_received):
    raw_socket = create_ipv4_raw_socket()
    if raw_socket is None:
        return

    print("Starting sniffing...")
    try:
        while not stop_event.is_set():
            raw_data, _ = raw_socket.recvfrom(65536)
            ethernet_header = EthernetHeader(raw_data)

            assert ethernet_header.ethernet_type == 0x0800

            if ethernet_header.ethernet_type == 0x0800:  # IPv4
                ip_header = IPHeader(ethernet_header.payload)

                if ip_header.protocol == 6:  # TCP
                    tcp_header = TCPHeader(ip_header.payload)
                    process_tcp_packet(ip_header, tcp_header, on_packet_received)
    except KeyboardInterrupt:
        for payload in tcp_http_parser.items():
            print(payload[1])
        print("Sniffing stopped")
