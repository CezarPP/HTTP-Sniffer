import tkinter as tk
from tkinter import ttk


class Gui:
    def __init__(self, start_action, stop_action):
        self.app = tk.Tk()
        self.app.title("Sniffer")

        # Start and stop buttons
        start_button = tk.Button(self.app, text="Start", command=start_action)
        start_button.pack(pady=10)

        stop_button = tk.Button(self.app, text="Stop", command=stop_action)
        stop_button.pack(pady=10)

        # List of requests
        self.frame = tk.Frame(self.app)
        self.frame.pack(padx=10, pady=10)

        # Create a Treeview widget
        self.tree = ttk.Treeview(self.frame, columns=("No.", "Time", "Source", "Destination", "Request Type", "Info"))

        self.index = 0

    def start_gui(self):
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
        scrollbar = ttk.Scrollbar(self.frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Pack the Treeview and scrollbar
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Start the GUI main loop
        self.app.mainloop()

    def insert_into_list(self, time, source, destination, request_type, info):
        self.tree.insert("", "end",
                         values=(
                             self.index, f"{time:.3f}", source, destination,
                             request_type, info))
