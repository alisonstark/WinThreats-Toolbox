# Python Toolbox - ETW Log Analyzer
# Author: moonpie (aka Alison Caique)
# Date: April 28, 2025

# ===============================
# DLL Hijacking Detection, * Program
# ===============================

import os
from evtx_converter import evtx_parser
from utils import get_evtx_path
from pprint import pprint

hijackable_arrays = ["wininet.dll"]

def detect_DLLHijack():
    evtx_path = get_evtx_path()
    csv_path = evtx_path.replace(".evtx", ".csv")
    
    data_rows = evtx_parser(evtx_path, csv_path)

    # Example: Check if the loaded image is in the array of target DLLs
    for row in data_rows:
        # Check if the row contains the necessary keys
        # and if the EventID is '7' (DLL loaded) and the Image ends with ".exe"
        # and if the ImageLoaded is not empty
        try:
            if row["EventID"] == '7' and row["Image"].endswith(".exe") and row["ImageLoaded"]:
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