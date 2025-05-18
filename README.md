# EVE - Event Verification Engine

## 🧠 Overview

**EVE (Event Verification Engine)** is a Python-based tool for analyzing Windows Event Logs, with a focus on detecting security-relevant behavior by leveraging **ETW (Event Tracing for Windows)** concepts and **Sysmon** logs.

EVE is designed for **SOC analysts**, **threat hunters**, and anyone working with **Windows-based security telemetry**.

It provides detection capabilities for:

- 🧬 **DLL Hijacking**
- 🧨 **Unmanaged PowerShell Execution**
- 🧠 **LSASS Dumping Attempts**
- 🧪 **Suspicious Parent-Child Process Relationships (Strange PPID)**

All detections can be exported to a **CSV file** for further analysis or reporting.

---

## ✨ Features

- 🔍 **Modular Detection Functions**  
  Easily extend or adjust detections based on different threat behaviors.

- 🧠 **Suspicious PPID Detection**  
  Detect strange parent-child process relationships via Sysmon Event ID 1.

- 📦 **CSV Output**  
  Export detection results for external analysis or archival.

- ⚙️ **Custom Time-Based Filtering**  
  Filter logs based on event time to focus on recent or targeted activity.

---

## ⚙️ Requirements

- **Python**: 3.12.7 or higher recommended  
- **PowerShell**: Version 2.0+ (available by default on Windows 7 and later)

> 📁 `Get-WinEvent` is used to manually examine logs if needed. No additional installation required on modern Windows systems.

---

## 🧰 Installation

### Linux (Ubuntu/Debian)

```
sudo apt install python3 python3-pip
pip install python-evtx
```

## 📂 Usage
```
python3 eve.py
```

## 🧠 Future Improvements

 -  Integration with Sigma rules
 -  Real-time monitoring via ETW providers
 -  JSON and Excel output support
 -  Implementation of EVE as a CLI tool (in progress)
