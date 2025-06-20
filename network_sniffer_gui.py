import tkinter as tk
from scapy.all import sniff, IP, TCP, UDP, DNS
from collections import defaultdict
import threading
import time
from datetime import datetime

# Thresholds
SYN_THRESHOLD = 10
UDP_THRESHOLD = 15
DNS_THRESHOLD = 10

# Counters
syn_count = defaultdict(int)
udp_count = defaultdict(int)
dns_count = defaultdict(int)

# Reset every 10 seconds
def reset_counters():
    while True:
        time.sleep(10)
        syn_count.clear()
        udp_count.clear()
        dns_count.clear()

# Detection logic
def process_packet(packet):
    if IP in packet:
        ip_src = packet[IP].src
        
        if packet.haslayer(TCP) and packet[TCP].flags == "S":
            syn_count[ip_src] += 1
            if syn_count[ip_src] > SYN_THRESHOLD:
                log_alert(f"SYN Flood detected from {ip_src}")

        elif packet.haslayer(UDP):
            udp_count[ip_src] += 1
            if udp_count[ip_src] > UDP_THRESHOLD:
                log_alert(f"UDP Flood detected from {ip_src}")

            if packet[UDP].dport == 53 or packet[UDP].sport == 53:
                if packet.haslayer(DNS):
                    dns_count[ip_src] += 1
                    if dns_count[ip_src] > DNS_THRESHOLD:
                        log_alert(f"⚠️ DNS Amplification suspected from {ip_src}")

# Log alerts to GUI
def log_alert(msg):
    timestamp = datetime.now().strftime("%H:%M:%S")
    alert_box.insert(tk.END, f"[{timestamp}] {msg}\n")
    alert_box.see(tk.END)

# Sniffing function
def start_sniffing():
    log_alert("🔍 Packet sniffing started...\n")
    sniff(prn=process_packet, store=0)

# Hover effect for buttons
def on_enter(e): e.widget['background'] = '#1abc9c'
def on_leave(e): e.widget['background'] = '#00ffcc'

# GUI setup
app = tk.Tk()
app.title("🛡️ Network Attack Detector")
app.geometry("700x500")
app.configure(bg="#121212")

# Title
title = tk.Label(app, text="Network Attack Detector", font=("Helvetica", 20, "bold"), bg="#121212", fg="#00ffcc")
title.pack(pady=20)

# Alert box (scrollable)
alert_frame = tk.Frame(app, bg="#121212")
alert_frame.pack()

scrollbar = tk.Scrollbar(alert_frame)
scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

alert_box = tk.Text(
    alert_frame, height=20, width=80, bg="#1e1e2e", fg="#ffffff",
    font=("Courier New", 10), yscrollcommand=scrollbar.set, bd=0, wrap=tk.WORD
)
alert_box.pack(side=tk.LEFT, fill=tk.BOTH)
scrollbar.config(command=alert_box.yview)

# Start Button
start_btn = tk.Button(app, text="🚀 Start Detection", font=("Arial", 12, "bold"), bg="#00ffcc", fg="black", padx=20, pady=8, borderwidth=0, command=lambda: threading.Thread(target=start_sniffing).start())
start_btn.pack(pady=20)
start_btn.bind("<Enter>", on_enter)
start_btn.bind("<Leave>", on_leave)

# Reset thread
threading.Thread(target=reset_counters, daemon=True).start()

# Run
app.mainloop()
