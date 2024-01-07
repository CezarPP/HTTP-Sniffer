from ethernet_parser import *
from ip_parser import *
from tcp_parser import *
from http_parser import *
import heapq


def create_ipv4_raw_socket():
    try:
        # Only capture IPv4
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    except socket.error as e:
        print(f"Error creating raw socket: {e}")
        return None


# This dictionary will hold the packets for each TCP connection in a min-heap
# The keys will be (source_ip, dest_ip, source_port, dest_port) tuples
tcp_buffers = {}

# This dictionary will hold the next expected sequence number for each TCP connection
next_expected_seq = {}

# This dictionary will hold the payload for the connection
tcp_payload = {}


def process_tcp_packet(source_ip, destination_ip, source_port, dest_port, sequence, acknowledgment, flag_fin, window,
                       checksum, payload):
    # print("Processing TCP packet")
    connection_key = (source_ip, destination_ip, source_port, dest_port)

    # Initialize buffer and sequence tracking if new connection
    if connection_key not in tcp_buffers:

        if not is_http_data(payload):
            return

        tcp_buffers[connection_key] = []
        next_expected_seq[connection_key] = sequence + len(payload)
        tcp_payload[connection_key] = payload
        print(payload)
    else:
        # We have already seen this connection
        # Check if the packet is the next expected one
        if sequence == next_expected_seq[connection_key]:
            # Process the packet
            tcp_payload[connection_key] += payload

            # Update the expected sequence number
            next_expected_seq[connection_key] += len(payload)

            # Check the buffer for the next packets
            while (tcp_buffers[connection_key]
                   and tcp_buffers[connection_key][0][0] <= next_expected_seq[connection_key]):

                # Handles retransmission
                if tcp_buffers[connection_key][0][0] < next_expected_seq[connection_key]:
                    heapq.heappop(tcp_buffers[connection_key])
                    continue

                _, buffered_payload = heapq.heappop(tcp_buffers[connection_key])
                tcp_payload[connection_key] += payload
                next_expected_seq[connection_key] += len(buffered_payload)
        else:
            # Add out-of-order packet to the buffer
            heapq.heappush(tcp_buffers[connection_key], (sequence, payload))

    if flag_fin == 0x1:
        print(tcp_payload[connection_key])
        tcp_buffers.pop(connection_key)
        tcp_payload.pop(connection_key)
        next_expected_seq.pop(connection_key)


def sniff_packets():
    raw_socket = create_ipv4_raw_socket()
    if raw_socket is None:
        return

    print("Starting sniffing...")
    try:
        while True:
            raw_data, _ = raw_socket.recvfrom(65536)
            destination_mac, source_mac, ethernet_type, payload = parse_ethernet_header(raw_data)

            assert ethernet_type == 0x0800

            if ethernet_type == 0x0800:  # IPv4
                version, ihl, ttl, protocol, source_ip, destination_ip, payload = parse_ipv4_header(payload)
                # print_ipv4_header(version, ihl, ttl, protocol, source_ip, destination_ip)

                # print(f"Payload: {payload}")

                if protocol == 6:  # TCP
                    source_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh, flag_rst, flag_syn, flag_fin, window, checksum, urgent_pointer, payload = parse_tcp_header(
                        payload)
                    # print_tcp_header(source_port, dest_port, sequence, acknowledgment, flag_urg, flag_ack, flag_psh,
                    #                flag_rst, flag_syn, flag_fin, window, checksum, urgent_pointer)
                    process_tcp_packet(source_ip, destination_ip, source_port, dest_port, sequence, acknowledgment,
                                       flag_fin, window, checksum,
                                       payload)
                    # print(f"TCP Payload Data: {payload}")
    except KeyboardInterrupt:
        for payload in tcp_payload.items():
            print(payload[1])
        print("Sniffing stopped")


def main():
    sniff_packets()


if __name__ == "__main__":
    main()
