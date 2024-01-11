import tkinter as tk
from tkinter import ttk
import threading


class Gui:
    """
    A class for creating and managing the GUI of a network packet sniffer application.

    Attributes:
        app (tk.Tk): The main window of the application.
        method_var (tk.StringVar): Variable to store the selected HTTP method for filtering.
        source_ip_var (tk.StringVar): Variable to store the selected source IP for filtering.
        destination_ip_var (tk.StringVar): Variable to store the selected destination IP for filtering.
        tree (ttk.Treeview): Widget to display the list of network requests.
        lock (threading.Lock): A lock to ensure thread-safe operations on shared resources.
        index (int): Counter to keep track of the number of requests.
        additional_info_dict (dict): Stores additional information (headers and body) for each request.
        request_info (dict): Stores basic information for each request.

    Methods:
        on_method_or_ip_select(_): Handles the selection of filters (HTTP method, source IP, destination IP).
        display_dialog_box(message: str): Displays a dialog box with detailed information about a request.
        show_additional_info(): Displays additional information for a selected request in the GUI.
        start_gui(): Configures and starts the main GUI loop.
        add_request(time, source, destination, request_type, info, body, headers): Adds a new request to the GUI.
        update_ip_dropdowns(source: str, destination: str): Updates the source and destination IP dropdowns.
        add_request_to_tree(index: int): Adds a request to the tree view based on the current filter criteria.

    Usage:
        - Used to create and manage the graphical interface for a network packet sniffer.
        - Provides interactive elements to filter and display network requests and their details.
        - Can handle real-time data updates from network sniffing threads.

    Note:
        The GUI is built using the Tkinter library and is designed to display network traffic.
    """

    def __init__(self, stop_action):
        self.app = tk.Tk()
        self.app.title("Sniffer")

        # Frame for dropdowns at the top
        top_frame = tk.Frame(self.app)
        top_frame.pack(side="top", fill="x", padx=10, pady=10)

        # Dropdown for HTTP requests
        method_frame = tk.Frame(top_frame)
        method_frame.pack(side="left", padx=10)
        http_methods_label = tk.Label(method_frame, text="Filter by HTTP Method")
        http_methods_label.pack()
        self.method_var = tk.StringVar()
        http_methods_dropdown = ['None', 'GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS', 'PATCH', 'CONNECT']
        self.dropdown = ttk.Combobox(method_frame, values=http_methods_dropdown, textvariable=self.method_var)
        self.dropdown.pack()
        self.dropdown.bind("<<ComboboxSelected>>", self.on_method_or_ip_select)

        # Dropdown for Source IP filtering
        source_ip_frame = tk.Frame(top_frame)
        source_ip_frame.pack(side="left", padx=10)
        source_ip_label = tk.Label(source_ip_frame, text="Filter by Source IP")
        source_ip_label.pack()
        self.source_ip_var = tk.StringVar()
        self.source_ip_dropdown = ttk.Combobox(source_ip_frame, textvariable=self.source_ip_var)
        self.source_ip_dropdown.pack()
        self.source_ip_dropdown.bind("<<ComboboxSelected>>", self.on_method_or_ip_select)

        self.source_ip_dropdown['values'] = ('None',)

        # Dropdown for Destination IP filtering
        destination_ip_frame = tk.Frame(top_frame)
        destination_ip_frame.pack(side="left", padx=10)
        destination_ip_label = tk.Label(destination_ip_frame, text="Filter by Destination IP")
        destination_ip_label.pack()
        self.destination_ip_var = tk.StringVar()
        self.destination_ip_dropdown = ttk.Combobox(destination_ip_frame, textvariable=self.destination_ip_var)
        self.destination_ip_dropdown.pack()
        self.destination_ip_dropdown.bind("<<ComboboxSelected>>", self.on_method_or_ip_select)

        self.destination_ip_dropdown['values'] = ('None',)

        # Stop button
        stop_button = tk.Button(top_frame, text="Stop", command=stop_action)
        stop_button.pack(side="left", padx=10)

        # Frame for the Treeview (List of Requests) at the bottom
        bottom_frame = tk.Frame(self.app)
        bottom_frame.pack(side="bottom", fill="both", expand=True, padx=10, pady=10)

        # Create a Frame for list of requests and its scrollbar
        self.tree_frame = tk.Frame(bottom_frame)
        self.tree_frame.pack(side="top", fill="both", expand=True)

        # Create a Treeview widget
        self.tree = ttk.Treeview(self.tree_frame,
                                 columns=("No.", "Time", "Source", "Destination", "Request Type", "Info"))

        # Initialize the lock object
        self.lock = threading.Lock()

        self.index = 0

        # Dictionary to store additional information for each item
        self.additional_info_dict = {}
        # Dictionary to store the information for each item
        self.request_info = {}

    def on_method_or_ip_select(self, _):
        # Combined filtering logic for method, source IP, and destination IP
        selected_method = self.method_var.get()
        selected_source_ip = self.source_ip_var.get()
        selected_destination_ip = self.destination_ip_var.get()

        # Delete all requests from the list
        for index in self.tree.get_children():
            self.tree.delete(index)

        # Add back requests conforming to the search criteria
        for req_index in range(0, self.index):
            req_info = self.request_info[req_index]
            if (selected_method in ['', 'None', req_info[3]] and
                    selected_source_ip in ['', 'None', req_info[1]] and
                    selected_destination_ip in ['', 'None', req_info[2]]):
                self.add_request_to_tree(req_index)

    def display_dialog_box(self, message: str):
        info_window = tk.Toplevel(self.app)
        info_window.title("HTTP Headers and Body")
        info_window.geometry("800x600")

        info_text = tk.Text(info_window, wrap="word")
        info_text.insert("1.0", message)
        info_text.config(state="disabled")  # Make the text widget read-only

        scrollbar = ttk.Scrollbar(info_window, command=info_text.yview)
        info_text.configure(yscrollcommand=scrollbar.set)
        info_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

    def show_additional_info(self) -> None:
        selected_item = self.tree.selection()
        if selected_item:
            item_values = self.tree.item(selected_item[0], "values")
            item_no = int(item_values[0])

            body, headers = self.additional_info_dict[item_no]

            try:
                body_string: str = body.decode("utf-8") if len(body) > 0 else ''
            except UnicodeDecodeError:
                body_string = ''

            header_string: str = '\n'.join([f'{key}: {value}' for key, value in headers])

            self.display_dialog_box(header_string + '\n\n' + body_string)

    def start_gui(self) -> None:
        # Define the column headings
        self.tree.heading("#1", text="No.")
        self.tree.heading("#2", text="Time")
        self.tree.heading("#3", text="Source")
        self.tree.heading("#4", text="Destination")
        self.tree.heading("#5", text="Request Type")
        self.tree.heading("#6", text="Info")

        # Configure column widths
        self.tree.column("#0", width=0)
        self.tree.column("#1", width=30)
        self.tree.column("#2", width=120)
        self.tree.column("#3", width=120)
        self.tree.column("#4", width=120)
        self.tree.column("#5", width=150)
        self.tree.column("#6", width=200)

        # Create a vertical scrollbar
        scrollbar = ttk.Scrollbar(self.tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Pack the Treeview and scrollbar
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Bind a double click event to the Treeview to show additional info
        self.tree.bind("<Double-1>", lambda event: self.show_additional_info())

        # Start the GUI main loop
        self.app.mainloop()

    def add_request(self, time: float, source: str, destination: str, request_type: str, info: str, body: str,
                    headers: list[tuple[str, str]]) -> None:
        # Lock is needed since this could be called by the IPv4 & IPv6 threads at the same time
        with self.lock:
            self.request_info[self.index] = (time, source, destination, request_type, info)
            self.additional_info_dict[self.index] = (body, headers)
            self.add_request_to_tree(self.index)
            self.index += 1
            self.update_ip_dropdowns(source, destination)

    def update_ip_dropdowns(self, source: str, destination: str):
        # Update source IP dropdown
        if source not in self.source_ip_dropdown['values']:
            self.source_ip_dropdown['values'] = (*self.source_ip_dropdown['values'], source)

        # Update destination IP dropdown
        if destination not in self.destination_ip_dropdown['values']:
            self.destination_ip_dropdown['values'] = (*self.destination_ip_dropdown['values'], destination)

    def add_request_to_tree(self, index: int):
        selected_method = self.method_var.get()
        selected_source_ip = self.source_ip_var.get()
        selected_destination_ip = self.destination_ip_var.get()

        req_info = self.request_info[index]
        # Add request to tree only if it conforms with the current search criteria
        if (selected_method in ['', 'None', req_info[3]] and
                selected_source_ip in ['', 'None', req_info[1]] and
                selected_destination_ip in ['', 'None', req_info[2]]):
            self.tree.insert("", "end",
                             values=(
                                 index, f"{req_info[0]:.3f}", req_info[1], req_info[2],
                                 req_info[3], req_info[4]))
