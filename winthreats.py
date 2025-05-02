# Python Toolbox - ETW Log Analyzer
# Author: moonpie (aka Alison Caique)
# Date: April 28, 2025

# ===============================
# Configurations and Arrays
# ===============================

# Python imports
from Evtx.Evtx import Evtx
from pprint import pprint
import xml.etree.ElementTree as ET
import csv
import os

# Placeholder: Add target DLLs here for DLL hijacking detection

hijackable_arrays = ["wininet.dll"]

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
                # In case user enters a number outside the range
                # This will be handled in the main loop
                print("Invalid choice. Please select a valid option (1-3).")
        
        # In case user enters a non-integer value
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

# def filter_events_by_id(events, allowed_ids):
#    return [event for event in events if event.get("EventID") in map(str, allowed_ids)]

# USAGE
# all_events = evtx_parser("path/to/log.evtx", "csv/path.csv")
# filtered_events = filter_events_by_id(all_events, [13])


def evtx_parser(evtx_path, csv_path):

    event_data_fields = [
        "EventID", "RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "ImageLoaded",
        "Hashes", "Signed", "Signature", "SignatureStatus", "SourceProcessGuid", "SourceProcessId",
        "SourceImage", "TargetProcessGuid", "TargetProcessId", "TargetImage", "CallTrace",
        "User", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "ParentUser"
    ]

    all_rows = []

    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            
            try:
                xml_str = record.xml()
                root = ET.fromstring(xml_str)
                # print(ET.tostring(root, encoding='unicode', method='xml'))  # DEBUG XML format

                # Namespace-aware parsing
                ns = {"ns0": "http://schemas.microsoft.com/win/2004/08/events/event"}

                row_dict = {key: "" for key in event_data_fields}  # default empty values

                # ACTUAL xml format: <ns0:EventID Qualifiers="">10</ns0:EventID>
                # Extract using namespace
                event_id_elem = root.find(".//ns0:EventID", ns)
                if event_id_elem is not None and event_id_elem.text:
                    row_dict["EventID"] = event_id_elem.text

                # ACTUAL xml format: <ns0:EventData><ns0:Data Name="RuleName">-</ns0:Data>
                # Extract using namespace
                for data in root.findall(".//ns0:Data", ns): # DEBUG
                    
                    name = data.attrib.get("Name")
                    value = data.text or ""
                    # print(name + "##########" + value) # DEBUG data names from event_data_fields and their value

                    if name in row_dict:
                        row_dict[name] = value

                all_rows.append(row_dict)

            except Exception as e:
                print(f"Error processing record: {e}")
                print(f"Record XML: {record.xml()}")

    # for row in all_rows:
    #    print(row) # DEBUG all rows, where all_rows = [row_dict_1, row_dict_2, row_dict_3, ...]


    # Save to CSV
    with open(csv_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=event_data_fields)
        writer.writeheader()
        writer.writerows(all_rows)

    return all_rows


def detect_DLLHijack():
    evtx_path = get_evtx_path()
    csv_path = evtx_path.replace(".evtx", ".csv")
    
    # Placeholder: TODO Add detection logic for DLL hijacking here
    data_rows = evtx_parser(evtx_path, csv_path)

    # data_rows = [row_dict_1, row_dict_2, row_dict_3, ...], where each dict is an event
    # for data in data_rows:
    #    for key, value in data.items():
    #        print(f"{key}: {value}") # DEBUG 

    # Placeholder: Add detection logic for DLL hijacking
    # Example: Check if the loaded image is in the array of target DLLs
    for row in data_rows:
        assert(int(row["EventID"]) == 7) # DEBUG ------------------>
        try:
            if row["Image"].endswith(".exe") and row["ImageLoaded"]:
                # Check if the loaded image is a DLL
                dll_name = os.path.basename(row["ImageLoaded"]).split("\\")[-1].lower() # Get the last part of the path
                # Check if the loaded DLL is in the hijackable array
                if dll_name in [dll.lower() for dll in hijackable_arrays]:

                    print("\n")
                    
                    print("\033[33m[+] Potential DLL Hijack detected\033[0m")
                    print(f"Executable: {row['Image']}" + "\n" + "\033[32mEvent Time:\033[0m " + f"{row['UtcTime']}" + "\n")
                    pprint(row)
                    
                    print("\n")

        except KeyError:
            print("KeyError: 'Image' not found in row data.")
            continue
        except Exception as e:
            print(f"An error occurred: {e}")
            continue
    
    print(10*'=' + " Analysis complete. Results saved to: ", csv_path + 10*'=')
    print("\n\n")
    

# ===============================
# Main Program Loop
# ===============================

while True:
    selection  = show_menu()
    options = {
        "1": detect_DLLHijack(), 
        #"2": detect_UnmanagedPowerShell,
        #"3": detect_CSharpInjection,
        #"4": exit
    }
    if selection in options:
        options[selection]()
        break
    