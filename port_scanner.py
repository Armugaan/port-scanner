import socket
import threading
import errno
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
from concurrent.futures import ThreadPoolExecutor, as_completed

SCAN_TIMEOUT = 1.0
MAX_WORKERS = 200


def scan_tcp_port(ip, port, timeout=SCAN_TIMEOUT):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            return sock.connect_ex((ip, port)) == 0
    except OSError:
        return False


def scan_udp_port(ip, port, timeout=SCAN_TIMEOUT):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(timeout)
            sock.sendto(b"", (ip, port))
            try:
                sock.recvfrom(1024)
                return "open"
            except socket.timeout:
                return "open/filtered"
            except ConnectionRefusedError:
                return "closed"
            except OSError as exc:
                if exc.errno in (errno.ECONNREFUSED, errno.EHOSTUNREACH, errno.ENETUNREACH):
                    return "closed"
                return "open/filtered"
    except OSError:
        return "filtered"


def resolve_target(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror as exc:
        raise ValueError(f"Unable to resolve target: {exc}")


def scan_target_port(protocol, ip, port):
    if protocol == "TCP":
        return scan_tcp_port(ip, port)
    return scan_udp_port(ip, port)


class PortScannerGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Port Scanner")
        self.geometry("640x540")
        self.resizable(False, False)
        self.create_widgets()

    def create_widgets(self):
        container = ttk.Frame(self, padding=12)
        container.pack(fill="both", expand=True)

        ttk.Label(container, text="Target IP / Hostname:").grid(row=0, column=0, sticky="w")
        self.target_entry = ttk.Entry(container, width=40)
        self.target_entry.grid(row=0, column=1, columnspan=3, sticky="ew", pady=2)
        self.target_entry.insert(0, "127.0.0.1")

        ttk.Label(container, text="Start port:").grid(row=1, column=0, sticky="w", pady=4)
        self.start_entry = ttk.Entry(container, width=12)
        self.start_entry.grid(row=1, column=1, sticky="w", pady=4)
        self.start_entry.insert(0, "1")

        ttk.Label(container, text="End port:").grid(row=1, column=2, sticky="w", pady=4)
        self.end_entry = ttk.Entry(container, width=12)
        self.end_entry.grid(row=1, column=3, sticky="w", pady=4)
        self.end_entry.insert(0, "1024")

        self.tcp_var = tk.BooleanVar(value=True)
        self.udp_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(container, text="Scan TCP", variable=self.tcp_var).grid(row=2, column=0, sticky="w", pady=4)
        ttk.Checkbutton(container, text="Scan UDP", variable=self.udp_var).grid(row=2, column=1, sticky="w", pady=4)

        ttk.Button(container, text="Start Scan", command=self.start_scan).grid(row=2, column=2, columnspan=2, sticky="ew", pady=4)

        self.status_label = ttk.Label(container, text="Ready", anchor="w")
        self.status_label.grid(row=3, column=0, columnspan=4, sticky="ew", pady=(8, 2))

        ttk.Label(container, text="Scan output:").grid(row=4, column=0, columnspan=4, sticky="w", pady=(10, 0))
        self.output_text = scrolledtext.ScrolledText(container, width=76, height=22, wrap="word", state="disabled")
        self.output_text.grid(row=5, column=0, columnspan=4, pady=(2, 0), sticky="nsew")

        ttk.Button(container, text="Clear", command=self.clear_output).grid(row=6, column=0, columnspan=4, sticky="ew", pady=(8, 0))

        container.columnconfigure(1, weight=1)
        container.columnconfigure(3, weight=1)
        container.rowconfigure(5, weight=1)

    def append_text(self, message):
        self.output_text.configure(state="normal")
        self.output_text.insert("end", message + "\n")
        self.output_text.see("end")
        self.output_text.configure(state="disabled")

    def safe_append(self, message):
        self.after(0, lambda: self.append_text(message))

    def set_status(self, text):
        self.status_label.config(text=text)

    def safe_set_status(self, text):
        self.after(0, lambda: self.set_status(text))

    def clear_output(self):
        self.output_text.configure(state="normal")
        self.output_text.delete("1.0", "end")
        self.output_text.configure(state="disabled")

    def start_scan(self):
        if not (self.tcp_var.get() or self.udp_var.get()):
            messagebox.showwarning("Protocol required", "Select at least one protocol to scan.")
            return

        target = self.target_entry.get().strip()
        if not target:
            messagebox.showwarning("Target required", "Enter an IP address or hostname.")
            return

        try:
            start_port = int(self.start_entry.get())
            end_port = int(self.end_entry.get())
        except ValueError:
            messagebox.showwarning("Invalid ports", "Start and end ports must be integers.")
            return

        if start_port < 1 or end_port < 1 or start_port > 65535 or end_port > 65535:
            messagebox.showwarning("Invalid range", "Ports must be between 1 and 65535.")
            return
        if start_port > end_port:
            messagebox.showwarning("Invalid range", "Start port must be less than or equal to end port.")
            return

        self.clear_output()
        self.safe_append(f"Resolving target '{target}'...")
        self.safe_set_status("Resolving...")
        threading.Thread(target=self.do_scan, args=(target, start_port, end_port), daemon=True).start()

    def do_scan(self, target, start_port, end_port):
        try:
            ip = resolve_target(target)
        except ValueError as exc:
            self.safe_append(str(exc))
            self.safe_set_status("Error")
            return

        protocols = []
        if self.tcp_var.get():
            protocols.append("TCP")
        if self.udp_var.get():
            protocols.append("UDP")

        total = len(protocols) * (end_port - start_port + 1)
        completed = 0
        open_tcp = []
        open_udp = []
        filtered_udp = []

        self.safe_append(f"Scanning {target} ({ip}) ports {start_port}-{end_port} for {', '.join(protocols)}...")
        self.safe_set_status("Scanning...")

        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            futures = {}
            for protocol in protocols:
                for port in range(start_port, end_port + 1):
                    future = executor.submit(scan_target_port, protocol, ip, port)
                    futures[future] = (protocol, port)

            for future in as_completed(futures):
                protocol, port = futures[future]
                try:
                    result = future.result()
                except Exception as exc:
                    result = None
                    self.safe_append(f"Error scanning {protocol} port {port}: {exc}")
                completed += 1
                self.safe_set_status(f"Scanning {completed}/{total}...")

                if protocol == "TCP" and result:
                    open_tcp.append(port)
                    self.safe_append(f"TCP port {port} is open")
                elif protocol == "UDP":
                    if result == "open":
                        open_udp.append(port)
                        self.safe_append(f"UDP port {port} is open")
                    elif result == "open/filtered":
                        filtered_udp.append(port)
                        self.safe_append(f"UDP port {port} is open/filtered")

        self.safe_append("")
        if open_tcp:
            self.safe_append("TCP open ports: " + ", ".join(str(port) for port in sorted(open_tcp)))
        if open_udp:
            self.safe_append("UDP open ports: " + ", ".join(str(port) for port in sorted(open_udp)))
        if filtered_udp:
            self.safe_append("UDP open/filtered ports: " + ", ".join(str(port) for port in sorted(filtered_udp)))
        if not open_tcp and not open_udp and not filtered_udp:
            self.safe_append("No open TCP or UDP ports found in the specified range.")

        self.safe_set_status("Scan complete")


def main():
    app = PortScannerGUI()
    app.mainloop()


if __name__ == "__main__":
    main()