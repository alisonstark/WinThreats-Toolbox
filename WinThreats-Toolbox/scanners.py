# Python Toolbox - ETW Log Analyzer
# Author: moonpie (aka Alison Caique)
# Date: April 28, 2025

# ===============================
# DLL Hijacking Detection, * Program
# ===============================

import os, csv
from converters import evtx_parser, evtx_to_csv
from utils import get_hijackable_dlls, print_event

hijackable_dlls = get_hijackable_dlls()

def print_hijackable_dlls():
    for dll in hijackable_dlls:
        print(dll)

def detect_DLLHijack(evtx_path, target_dll=None):
    # evtx_path = get_evtx_path()
    
    
    data_rows = evtx_parser(evtx_path)
    spotted_rows = []

    # Example: Check if the loaded image is in the array of target DLLs
    for row in data_rows:
        # Check if the row contains the necessary keys
        # and if the EventID is '7' (DLL loaded) and the Image ends with ".exe"
        # and if the ImageLoaded is not empty
        try:
            if row["EventID"] == '7' and row["Image"].endswith(".exe") and row["ImageLoaded"]:
                # Check if the loaded image is a DLL
                dll_name = os.path.basename(row["ImageLoaded"]).split("\\")[-1].lower() # Get the last part of the path
                
                # Check if the loaded DLL is in the hijackable array or equals the target DLL
                if target_dll and target_dll.lower() == dll_name:
                    print_event(row)
                    spotted_rows.append(row)
                
                # If no target DLL is provided, check if the loaded DLL is in the hijackable array
                elif not target_dll and dll_name in [dll.lower() for dll in hijackable_dlls]:
                    print_event(row)
                    spotted_rows.append(row)

        except KeyError:
            print("KeyError: 'Image' not found in row data.")
            continue
        except Exception as e:
            print(f"An error occurred: {e}")
            continue
    
    print(10*'=', " Analysis complete", 10*'=', "\nWould you like to save the matched results to a CSV file? Y/N\n")
    save_results = input("Enter your choice: ").strip().lower()
    
    if save_results == 'y':
        # Save the results to a CSV file
        evtx_to_csv(spotted_rows, evtx_path)
        
    else:
        print("Results not saved.")
    print("\n\n")


def detect_UnmanagedPowerShell():
    # Placeholder for Unmanaged PowerShell detection logic
    pass