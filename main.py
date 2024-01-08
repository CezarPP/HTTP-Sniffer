from sniffer.sniffer import *
from gui.gui import *
import threading

stop_event = threading.Event()


def start_action():
    print("Start pressed")


def stop_action():
    print("Stop pressed")
    stop_event.set()
    exit(0)


def main():
    gui = Gui(start_action, stop_action)
    sniffer_thread = threading.Thread(target=sniff_packets, args=(stop_event, gui.insert_into_list))
    sniffer_thread.start()
    gui.start_gui()


if __name__ == "__main__":
    main()
