import socket
import heapq
import time

from parsers.ethernet_parser import EthernetHeader
from parsers.ip_parser import IPHeader
from parsers.ipv6_parser import IPv6Header
from parsers.tcp_parser import TCPHeader
from parsers.http_parser import HttpParser, is_http_data
from parsers.info_http import InfoHTTP


class Sniffer:
    """
    A class for sniffing and processing HTTP network requests and responses.

    Attributes:
        start_time (float): The time when the sniffer started.
        tcp_buffers (dict): Buffers to hold packets for each TCP connection, using min-heaps.
        next_expected_seq (dict): Dictionary to track the next expected sequence number for each TCP connection.
        tcp_http_parser (dict): Dictionary holding an HTTP parser for each TCP connection.
        raw_socket (socket.socket): The raw socket used for capturing packets.

    Methods:
        process_tcp_packet(ip, tcp, on_packet_received): Processes a single TCP packet.
        process_ip_packet(raw_data, on_packet_received): Processes a single IP packet.
        sniff_packets(stop_event, on_packet_received): Main loop for sniffing packets.

    Usage:
        - Initialize the Sniffer class, specifying whether to capture IPv4 or IPv6 traffic.
        - Call `sniff_packets` to start the packet sniffing process.
        - Processed packet data is provided to a callback function for further handling.

    Note:
        This sniffer is designed to work with both IPv4 and IPv6 packets and focuses on TCP and HTTP protocols.
        It handles out-of-order TCP packets and reassembles HTTP messages.
    """

    def __init__(self, is_ipv6=False):
        self.start_time = time.time()

        # This dictionary will hold the packets for each TCP connection in a min-heap
        # The keys will be (source_ip, dest_ip, source_port, dest_port) tuples
        self.tcp_buffers = {}

        # This dictionary will hold the next expected sequence number for each TCP connection
        self.next_expected_seq = {}

        # This dictionary will hold the HTTP parser for each connection
        self.tcp_http_parser = {}

        self.raw_socket = create_ipv6_raw_socket() if is_ipv6 else create_ipv4_raw_socket()
        if self.raw_socket is None:
            print("Could not create socket, aborting...")
            exit(0)

    def process_tcp_packet(self, ip: IPHeader | IPv6Header, tcp: TCPHeader, on_packet_received):
        connection_key = (ip.source, ip.dest, tcp.source_port, tcp.dest_port)

        # Initialize buffer and sequence tracking for a new connection
        if connection_key not in self.tcp_buffers:

            if not is_http_data(tcp.payload):
                return

            self.tcp_buffers[connection_key] = []
            self.next_expected_seq[connection_key] = tcp.sequence + len(tcp.payload)
            self.tcp_http_parser[connection_key] = HttpParser(InfoHTTP())
            self.tcp_http_parser[connection_key].feed_data(tcp.payload)
        else:
            # We have already seen this connection
            # Check if the packet is the next expected one
            if tcp.sequence == self.next_expected_seq[connection_key]:
                # Process the packet
                self.tcp_http_parser[connection_key].feed_data(tcp.payload)

                # Update the expected sequence number
                self.next_expected_seq[connection_key] += len(tcp.payload)

                # Check the buffer for the next packets
                while (self.tcp_buffers[connection_key] and
                       self.tcp_buffers[connection_key][0][0] <= self.next_expected_seq[connection_key]):

                    # Handles retransmission
                    if self.tcp_buffers[connection_key][0][0] < self.next_expected_seq[connection_key]:
                        heapq.heappop(self.tcp_buffers[connection_key])
                        continue

                    _, buffered_payload = heapq.heappop(self.tcp_buffers[connection_key])
                    self.tcp_http_parser[connection_key].feed_data(buffered_payload)
                    self.next_expected_seq[connection_key] += len(buffered_payload)
            else:
                # Add out-of-order packet to the buffer
                heapq.heappush(self.tcp_buffers[connection_key], (tcp.sequence, tcp.payload))

        if tcp.flag_fin == 0x1 or self.tcp_http_parser[connection_key].is_message_complete:
            info_http: InfoHTTP = self.tcp_http_parser[connection_key].info_http

            request_type = info_http.http_method if info_http.is_request() else "HTTP Response"
            on_packet_received(time.time() - self.start_time, connection_key[0], connection_key[1], request_type,
                               str(info_http.status_code) + " " + info_http.status_message
                               if not info_http.is_request() else "HTTP Request",
                               info_http.body, info_http.headers)
            self.tcp_buffers.pop(connection_key)
            self.tcp_http_parser.pop(connection_key)
            self.next_expected_seq.pop(connection_key)

    def process_ip_packet(self, raw_data: bytes, on_packet_received):
        ethernet_header = EthernetHeader(raw_data)

        assert ethernet_header.ethernet_type == 0x0800 or ethernet_header.ethernet_type == 0x86DD

        ip_header: IPHeader | IPv6Header = IPHeader(
            ethernet_header.payload) if ethernet_header.ethernet_type == 0x0800 else IPv6Header(
            ethernet_header.payload)

        if ip_header.protocol == 6:  # TCP
            tcp_header = TCPHeader(ip_header.payload)
            self.process_tcp_packet(ip_header, tcp_header, on_packet_received)

    def sniff_packets(self, stop_event, on_packet_received):
        print("Starting sniffing...")
        try:
            while not stop_event.is_set():
                raw_data, _ = self.raw_socket.recvfrom(65536)
                self.process_ip_packet(raw_data, on_packet_received)
        except KeyboardInterrupt:
            print("Sniffing stopped")


def create_ipv4_raw_socket():
    try:
        # Only capture IPv4
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    except socket.error as e:
        print(f"Error creating raw socket: {e}")
        return None


def create_ipv6_raw_socket():
    try:
        # Only capture IPv6
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x86DD))
    except socket.error as e:
        print(f"Error creating IPv6 raw socket: {e}")
        return None
