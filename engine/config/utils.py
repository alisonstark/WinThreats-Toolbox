# Python Toolbox - ETW Log Analyzer
# Author: moonpie (aka Alison Caique)
# Date: April 28, 2025

# ===============================
# Auxiliary Functions
# ===============================

import os
from pprint import pprint
from datetime import datetime, timedelta

def show_menu():
    print("=== ETW Log Analyzer Toolbox ===")
    print("1) DLL Hijacking Detection")
    print("2) Unmanaged PowerShell Detection")
    print("3) Detect LSASS Dump")
    print("4) Exit")
    
    target_dll = None
    # Loop until a valid choice is made
    while True:
        try:
            choice = int(input("Select an option (1-4): "))
            if choice in [1, 2, 3, 4]:
                if choice == 1:
                    print("\nProvide a specific DLL to check for hijacking (optional).")
                    target_dll = input("Enter the DLL name (e.g., example.dll) or press Enter to skip: ")
                    
                    if target_dll and not target_dll.endswith(".dll"):
                        target_dll = input("\033[31m[-] Invalid DLL name. Please include the .dll extension:\033[0m")

                    elif target_dll:
                        target_dll = target_dll.strip().lower()
                    
                    # If the user provides a DLL name, return it along with the choice
                    return choice, target_dll if target_dll else None

                elif choice == 2:
                    print("Provide a specific DLL to check for unmanaged powershell code execution (optional).")
                    target_dll = input("Enter the DLL name (e.g., example.dll) or press Enter to skip: ")
                    
                    if target_dll and not target_dll.endswith(".dll"):
                        target_dll = input("\033[31m[-] Invalid DLL name. Please include the .dll extension:\033[0m")

                    elif target_dll:
                        target_dll = target_dll.strip().lower()
                    
                    # If the user provides a DLL name, return it along with the choice
                    return choice, target_dll if target_dll else None
                
                # If the user selects options 2 or 3, return the choice and None for target_dll
                else:
                    return choice, None
                   
            else:
                # In case user enters a number outside the range
                # This will be handled in the main loop
                print("\033[31m[-] Invalid choice. Please select a valid option (1-4).\033[0m")
        
        # In case user enters a non-integer value
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 4.")

# Function to print the event details
# This function is called when a potential malicious activity is detected
def print_sysmon_event(event):
    print("\033[36m\n[+] Summary of the activity\033[0m")
    
    # Case of Unmanaged Powershell attacks
    if event['Image'] == "" or event['EventID'] == '8' or event['EventID'] == '10':
        print(f"Injector process: {event['SourceImage']}" + "\n",
              f"Injected process: {event['TargetImage']}" + "\n", 
              f"Event Time: {event['UtcTime']}" + "\n")
    
    else:
        print(f"Initiator process: {event['Image']}" + "\n",
          f"Event Time: {event['UtcTime']}" + "\n")
    
    pprint(event)

def print_security_event(event):

    print("\033[36m\n[+] Summary of the activity\033[0m")
    print(f"Process name: {event['ProcessName']}" + "\n",
          f"Event Time: {event['TimeCreated']}" + "\n")
    pprint(event)

# Function to display all events after a specific time
# Filter the events based on the earliest event time
# TODO: Generalize func. Potential solutions are...
# [ ] Adapt func to recognize the events type (use flags)
# [ ] Make this func so that it only filters events and stores them to a list or set
# [ ] Call event printing function (separation of responsibilities)
def filter_events_by_time(data_rows, time_frame=None, user_minutes=None):
    if not data_rows:
        print("\033[31m[-] No data rows available.\033[0m")
        return
    # Get the earliest event time
    elif time_frame is not None:

        sysmon_filtered_events = []
        security_filtered_events = []
        high_value_event_ids = ["4688", "4689", "4690", "4691", "4692", "4693", "4624", "4672", "4656", "4663"]

        if user_minutes is not None:
            if user_minutes < 0:
                print("\033[31m[-] Invalid time frame. Please enter a positive number.\033[0m")
                exit(1)
            elif user_minutes > 0:
                # Filter events within the specified time frame
                time_threshold = time_frame + timedelta(minutes=user_minutes)
                
                for row in data_rows: 
                    utc_time = row.get("UtcTime", "")
                    time_created = row.get("TimeCreated", "")

                    if utc_time:
                        if time_frame <= datetime.strptime(row["UtcTime"], "%Y-%m-%d %H:%M:%S.%f") <= time_threshold:
                            return sysmon_filtered_events.append(row)
                    elif time_created:
                        if time_frame <= datetime.strptime(row["TimeCreated"], "%Y-%m-%d %H:%M:%S.%f") <= time_threshold:
                            return security_filtered_events.append(row)
                
        # if user_minutes is None
        else:
            # Filter events after the specified time
            for row in data_rows:
                utc_time = row.get("UtcTime", "") # TODO: DEBUG here
                time_created = row.get("TimeCreated", "")

                if utc_time:
                    if time_frame <= datetime.strptime(utc_time, "%Y-%m-%d %H:%M:%S.%f"):
                        sysmon_filtered_events.append(row)
                elif time_created:
                    if time_frame <= datetime.strptime(time_created, "%Y-%m-%d %H:%M:%S.%f"):
                        security_filtered_events.append(row)

        # Print the filtered Sysmon LSASS events
        if sysmon_filtered_events:
            for event in sysmon_filtered_events:
                # print(event["EventID"]) # DEBUG
                # Additional filtering
                if event["EventID"] == '10':
                    if event["TargetImage"].lower().endswith("lsass.exe"):
                        print_sysmon_event(event)
        
        elif security_filtered_events:
            for event in security_filtered_events:
                # print(event["EventID"]) # DEBUG
                # Additional filtering for specific log types
                if event["EventID"] in high_value_event_ids:
                    print_security_event(event)

        print("\033[32m[+] Filtered events based on the earliest detection time of the dump\033[0m")
        
    else:
        print("\033[31m[-] No events filtered.\033[0m")


def get_evtx_path():
    evtx_path = input("Enter the full path to the .evtx file: ")
    
    if not evtx_path:
        print("\033[31m[-] No path provided. Exiting.\033[0m")
        exit(1)
    elif not evtx_path.endswith(".evtx"):
        print("\033[31m[-] Invalid file type. Please provide a .evtx file.\033[0m")
        exit(1)
    else:
        print(f"[+] File successfully loaded: {evtx_path}")
    
    return evtx_path

# USAGE
# all_events = evtx_parser("path/to/log.evtx", "csv/path.csv")
# filtered_events = filter_events_by_id(all_events, [13])

# Generate a list of hijackable DLLs from a text file
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

    sorted(hijackable_dlls)
    return hijackable_dlls

# Generate a set of common LOLBins from a text file
def get_lolbins():
    lolbins = set()
    current_dir = os.path.dirname(__file__)
    file_path = os.path.join(current_dir, "lolbins.txt")
    with open(file_path, "r", encoding="utf-8") as f:
        for line in f:
            lolbins.add(line.strip().lower())

    sorted_lolbins = sorted(lolbins)
    return sorted_lolbins

# Check if the image path is a LOLBin
def is_lolbin(image_path, lolbins):
    if not image_path:
        return False
    binary = os.path.basename(image_path).split("\\")[-1].lower()
    return bool(binary and lolbins and binary in lolbins)







    


    