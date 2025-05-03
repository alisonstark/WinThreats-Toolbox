# Python Toolbox - ETW Log Analyzer
# Author: moonpie (aka Alison Caique)
# Date: April 28, 2025

# ===============================
# Auxiliary Functions
# ===============================

import os
from pprint import pprint

def show_menu():
    print("=== ETW Log Analyzer Toolbox ===")
    print("1) DLL Hijacking Detection")
    print("2) Unmanaged PowerShell Detection (Coming Soon)")
    print("3) C# Injection Detection (Coming Soon)")
    print("4) Exit")
    
    target_dll = None  # Initialize target_dll to None
    # Loop until a valid choice is made
    while True:
        try:
            choice = int(input("Select an option (1-4): "))
            if choice in [1, 2, 3, 4]:
                if choice == 1:
                    print("Provide a specific DLL to check for hijacking (optional).")
                    target_dll = input("Enter the DLL name (e.g., example.dll) or press Enter to skip: ")
                    
                    if target_dll and not target_dll.endswith(".dll"):
                        target_dll = input("Invalid DLL name. Please include the .dll extension:")

                    elif target_dll:
                        target_dll = target_dll.strip().lower()
                    
                    # If the user provides a DLL name, return it along with the choice
                    return choice, target_dll if target_dll else None
                
                # If the user selects options 2 or 3, return the choice and None for target_dll
                return choice, None
            
            else:
                # In case user enters a number outside the range
                # This will be handled in the main loop
                print("Invalid choice. Please select a valid option (1-4).")
        
        # In case user enters a non-integer value
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 4.")

# Function to print the event details
# This function is called when a potential DLL hijack is detected
def print_event(event):
    print("\n")
    print("\033[33m[+] Potential DLL Hijack detected\033[0m")
    print(f"Executable: {event['Image']}" + "\n" + "\033[32mEvent Time:\033[0m " + f"{event['UtcTime']}" + "\n")
    pprint(event)
    print("\n")


def get_evtx_path():
    evtx_path = input("Enter the full path to the .evtx file: ")
    
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

# generate a list of hijackable DLLs from a text file
# The text file should be in the same directory as this script
def get_hijackable_dlls():
    hijackable_dlls = set()
    current_dir = os.path.dirname(__file__)
    file_path = os.path.join(current_dir, "hijackable_dlls.txt")
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            dll_array = line.split(" \t")
            
            if len(dll_array) == 4 and dll_array[2].endswith(".dll"):
                dll = dll_array[2].lower()
                hijackable_dlls.add(dll)
            
            elif len(dll_array) == 3 and dll_array[1].endswith(".dll"):
                dll = dll_array[1].lower()
                hijackable_dlls.add(dll)

            # no need for 'else: continue' – just skip it

    sorted(hijackable_dlls)
    return hijackable_dlls






    


    