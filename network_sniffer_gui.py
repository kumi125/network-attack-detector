import tkinter as tk
from tkinter import scrolledtext
from scapy.all import sniff, IP, TCP, UDP
import threading
import time

# Track SYN and UDP packets from IPs
syn_packets = {}
udp_packets = {}

# Thresholds
SYN_THRESHOLD = 20
UDP_THRESHOLD = 100
TIME_WINDOW = 10  # seconds

# GUI Setup
root = tk.Tk()
root.title("Intrusion Detection System")
root.geometry("600x400")

log_display = scrolledtext.ScrolledText(root, width=70, height=20)
log_display.pack(pady=10)

status_label = tk.Label(root, text="Status: Monitoring for SYN and UDP flood attacks", fg="green")
status_label.pack()

# Utility to log messages in GUI
def log_message(message):
    log_display.insert(tk.END, message + "\n")
    log_display.see(tk.END)

# Packet Processing
def process_packet(packet):
    current_time = time.time()

    if packet.haslayer(IP):
        src_ip = packet[IP].src

        # Detect SYN Flood (TCP with SYN flag)
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            syn_packets.setdefault(src_ip, []).append(current_time)
            syn_packets[src_ip] = [t for t in syn_packets[src_ip] if current_time - t <= TIME_WINDOW]
            if len(syn_packets[src_ip]) > SYN_THRESHOLD:
                log_message(f"[ALERT] SYN Flood Detected from {src_ip}!")

        # Detect UDP Flood
        if packet.haslayer(UDP):
            udp_packets.setdefault(src_ip, []).append(current_time)
            udp_packets[src_ip] = [t for t in udp_packets[src_ip] if current_time - t <= TIME_WINDOW]
            if len(udp_packets[src_ip]) > UDP_THRESHOLD:
                log_message(f"[ALERT] UDP Flood Detected from {src_ip}!")

# Sniffing Function
def start_sniffing():
    sniff(prn=process_packet, store=0)

def run_sniffer_thread():
    sniff_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniff_thread.start()
    log_message("[INFO] Started packet sniffing...")

# Start sniffing on GUI load
run_sniffer_thread()

# Start GUI loop
root.mainloop()
