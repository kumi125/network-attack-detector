# 🛡️ Network Attack Detector - GUI Based

A real-time network attack detection system with a user-friendly GUI, built using Python and Scapy. Detects and alerts against various network-based attacks.

![GUI Screenshot](https://via.placeholder.com/800x400.png?text=Network+Attack+Detector+GUI)

---

## 🚀 Features

- ✅ GUI interface using `Tkinter`
- 📡 Live packet sniffing using `Scapy`
- 🧠 Detects:
  - SYN Flood Attacks
  - UDP Flood Attacks
  - DNS Amplification Attacks
  - (More attacks can be added easily)
- 🔔 Real-time alert logging
- 🧰 Generates standalone `.exe` for Windows

---

## 🛠️ Requirements

- Python 3.10+
- Scapy
- Tkinter (comes with Python)
- pyinstaller (for EXE creation)

Install dependencies:

```bash
pip install -r requirements.txt
▶️ How to Run
bash
Copy
Edit
python network_sniffer_gui.py
🏗️ How to Build EXE
To create an executable:

bash
Copy
Edit
pyinstaller --onefile --windowed --icon=icon.ico network_sniffer_gui.py
The output will be in the dist/ folder.

🧠 How It Works
Captures packets using Scapy

Checks for abnormal patterns (e.g. excessive SYN or UDP)

Logs alerts in real-time to the GUI

Allows easy detection and response to suspicious traffic

📂 Project Structure
css
Copy
Edit
project/
├── dist/
│   └── network_sniffer_gui.exe
├── build/
├── icon.ico
├── network_sniffer_gui.py
├── requirements.txt
└── README.md
🙌 Credits
Made with ❤️ by Kumail Hussain
GitHub: @kumi125

yaml
Copy
Edit

You can update the image URL and GitHub link as needed.

---

## ✅ Step 2: How to Add README to GitHub

1. **Create the README.md**  
   In your project folder (locally), create the file:
   ```bash
   code README.md
(or open it in VS Code)

Add it to Git:

bash
Copy
Edit
git add README.md
git commit -m "📝 Added README with project details"
git push
Check GitHub
Go to your repo https://github.com/kumi125/network-attack-detector and you'll see the README.md as the front page.

