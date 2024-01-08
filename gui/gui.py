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

        # Dictionary to store additional information for each item
        self.additional_info_dict = {}

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

            body_string: str = body.decode("utf-8") if len(body) > 0 else ""
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
        scrollbar = ttk.Scrollbar(self.frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Pack the Treeview and scrollbar
        self.tree.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Bind a double click event to the Treeview to show additional info
        self.tree.bind("<Double-1>", lambda event: self.show_additional_info())

        # Start the GUI main loop
        self.app.mainloop()

    def insert_into_list(self, time: float, source: str, destination: str, request_type: str, info: str, body: str,
                         headers: list[tuple[str, str]]) -> None:
        self.index += 1
        self.tree.insert("", "end",
                         values=(
                             self.index, f"{time:.3f}", source, destination,
                             request_type, info))
        self.additional_info_dict[self.index] = (body, headers)