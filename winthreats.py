# Python Toolbox - ETW Log Analyzer
# Author: moonpie (aka Alison Caique)
# Date: April 28, 2025

# ===============================
# Configurations and Arrays
# ===============================

# Python imports
from Evtx.Evtx import Evtx
import xml.etree.ElementTree as ET
import csv

# Placeholder: Add target DLLs here for DLL hijacking detection

array = ["wininet.dll"]

# ===============================
# Functions
# ===============================

def show_menu():
    print("=== ETW Log Analyzer Toolbox ===")
    print("1) DLL Hijacking Detection")
    print("2) Unmanaged PowerShell Detection (Coming Soon)")
    print("3) C# Injection Detection (Coming Soon)")
    print("3) Exit")
    
    while True:
        try:
            choice = int(input("Select an option (1-3): "))
            if choice in [1, 2, 3]:
                return choice
            else:
                print("Invalid choice. Please select a valid option (1-3).")
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 3.")


def get_evtx_path():
    evtx_path = input("Enter the full path to the .evtx file:")
    
    if not evtx_path:
        print("No path provided. Exiting.")
        exit(1)
    elif not evtx_path.endswith(".evtx"):
        print("Invalid file type. Please provide a .evtx file.")
        exit(1)
    else:
        print(f"File successfully loaded: {evtx_path}")
    
    return evtx_path


def Evtx_to_CSV(evtx_path, csv_path):
    
    # Define the event data header fields to extract for the XML
    event_data_fields = [
        "RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "ImageLoaded",
        "Hashes", "Signed", "Signature", "SignatureStatus", "SourceProcessGuid", "SourceProcessId",
        "SourceImage", "TargetProcessGuid", "TargetProcessId", "TargetImage", "CallTrace",
        "User", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "ParentUser"
    ]

    all_rows = []

    with Evtx(evtx_path) as log:
        for record in log.records():
            xml_str = record.xml()
            root = ET.fromstring(xml_str)

            data_fields = root.findall("./EventData/Data")
            data_values = [data.text if data.text is not None else "" for data in data_fields]
            # Pad the list to always have 23 values
            data_values += [""] * (len(event_data_fields) - len(data_values))
            all_rows.append(data_values[:23])  # ensure exactly 23

    # Save to CSV
    with open(csv_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow(event_data_fields)
        writer.writerows(all_rows)

    return all_rows


def detect_DLLHijack():
    evtx_path = get_evtx_path()
    csv_path = evtx_path.replace(".evtx", ".csv")
    
    # Convert the .evtx file to .csv
    all_rows = Evtx_to_CSV(evtx_path, csv_path)
    
    # Placeholder: TODO Add detection logic for DLL hijacking here
    print("DLL Hijacking detection logic goes here.")
    
    # Placeholder: Print the results
    print("Detection complete. Results saved to:", csv_path)



# ===============================
# Main Program Loop
# ===============================

while True:
    show_menu
    selection = input("Please enter the number of your choice")

    options = {
        "1": detect_DLLHijack, 
        #"2": detect_UnmanagedPowerShell,
        #"3": detect_CSharpInjection,
        #"4": exit
    }
    if selection in options:
        options[selection]()
        break
    
    else:
        print("Invalid selection. Please try again.")
    