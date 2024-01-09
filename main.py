from sniffer.sniffer import *
from gui.gui import *
import threading

stop_event = threading.Event()


def stop_action():
    print("Stop pressed")
    stop_event.set()
    exit(0)


def main():
    gui = Gui(stop_action)
    ipv4_sniffer = Sniffer(is_ipv6=False)
    ipv6_sniffer = Sniffer(is_ipv6=True)
    ipv4_sniffer_thread = threading.Thread(target=ipv4_sniffer.sniff_packets, args=(stop_event, gui.add_request))
    ipv4_sniffer_thread.start()
    ipv6_sniffer_thread = threading.Thread(target=ipv6_sniffer.sniff_packets, args=(stop_event, gui.add_request))
    ipv6_sniffer_thread.start()

    gui.start_gui()


if __name__ == "__main__":
    main()
