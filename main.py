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
    sniffer_thread = threading.Thread(target=sniff_packets, args=(stop_event, gui.add_request))
    sniffer_thread.start()
    gui.start_gui()


if __name__ == "__main__":
    main()
