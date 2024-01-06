from ethernet_parser import *
from ip_parser import *
from tcp_parser import *
from http_parser import *


def create_ipv4_raw_socket():
    try:
        # Only capture IPv4
        return socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    except socket.error as e:
        print(f"Error creating raw socket: {e}")
        return None


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

                    if is_http_data(payload):
                        parse_http_data(payload)
                    else:
                        continue
                    # print(f"TCP Payload Data: {payload}")
    except KeyboardInterrupt:
        print("Sniffing stopped")


def main():
    sniff_packets()


if __name__ == "__main__":
    main()
