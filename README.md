# Port Scanner

A multi-threaded TCP/UDP port scanner built in Python with a Tkinter GUI.

## Features
- Scans TCP and UDP ports concurrently (up to 200 threads)
- Accurate UDP state detection: open / open/filtered / closed
- Real-time scan progress in a clean GUI
- Hostname resolution support

## Screenshot
<!-- Add a screenshot here after taking one -->
<img width="642" height="570" alt="image" src="https://github.com/user-attachments/assets/837b6ede-e1bb-4cbe-807c-29833260fad9" />


## Requirements
- Python 3.8+
- No external libraries required (uses built-in modules only)

## How to Run
```bash
python port_scanner.py
```

## Concepts Used
- Python `socket` module (TCP connect scan, UDP probing)
- `concurrent.futures.ThreadPoolExecutor` for parallel scanning
- Thread-safe Tkinter UI updates using `after()`
- ICMP error response analysis for UDP state detection
