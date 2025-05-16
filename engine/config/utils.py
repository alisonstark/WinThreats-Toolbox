# ===============================
# Auxiliary Functions
# ===============================

import os
from datetime import timedelta

def show_menu():
    print("=== ETW Log Analyzer Toolbox ===")
    print("1) DLL Hijacking Detection")
    print("2) Unmanaged PowerShell Detection")
    print("3) Detect LSASS Dump")
    # print("4) All of the above")
    print("4) Exit")
    print("=================================")

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

# Function to display all events after a specific time
# Filter the events based on the earliest event time
# [x] Make this func so that it only filters events and stores them to a list or set
# [x] Call event printing function (separation of responsibilities)
def filter_events_by_time(data_rows, starting_time, user_minutes=None):
    if not data_rows:
        print("\033[31m[-] No data rows available.\033[0m")
        return []
    # Check if starting_time is not None
    elif starting_time:
        filtered_events = []
        event_count = 0
        max_events = 20
        
        # Filter events based on the earliest event time
        while True:
            user_input = input("Enter the time frame in minutes (or press Enter to skip): ").strip()

            if user_input == "":
                user_minutes = 0
                break

            try:
                user_minutes = int(user_input)
                if user_minutes < 0:
                    print("\033[31m[-] Invalid time frame. Please enter a positive number.\033[0m")
                else:
                    break
            except ValueError:
                print("\033[31m[-] Invalid input. Please enter a valid number or press Enter to skip.\033[0m")

        # Filter events within the specified time frame
        time_threshold = starting_time + timedelta(minutes=user_minutes)
        
        # Populate the filtered events list
        for row in data_rows: 
            time_created = row.get('TimeCreated', "")

            # Check if the event is within the specified time frame
            if time_threshold != starting_time and starting_time <= time_created <= time_threshold:
                filtered_events.append(row)
            
            # Filter events after the specified time
            elif time_threshold == starting_time:
                
                if time_created >= starting_time:
                    filtered_events.append(row)
                    event_count += 1
                    # Limit the number of events to be displayed
                    if event_count > max_events:
                        print("\033[31m[!] There are more than 20 events. Proceed?\033[0m")
                        user_input = input("Press 'y' to continue or any other key to stop: ").strip().lower()
                        if user_input != 'y':
                            print("\033[31m[!] Stopping the filtering.\033[0m")
                            break
                        else:
                            print("\033[32m[+] Continuing to filter events...\033[0m")
                            # Reset the event count
                            event_count = 0
                            continue

        print("\033[32m[+] Filtered events based on the earliest detection time\033[0m")
        
    else:
        print("\033[31m[-] No events filtered.\033[0m")
        return []

    return filtered_events

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

# Generate a list of hijackable DLLs from a text file
# The text file should be in the same directory as this script
def get_hijackable_dlls():
    hijackable_dlls = set()
    
    # Path to the current script
    current_dir = os.path.dirname(__file__)
    
    # Go to the parent of 'config' and then into 'data'
    base_dir = os.path.abspath(os.path.join(current_dir, ".."))
    file_path = os.path.join(base_dir, "data", "hijackable_dlls.txt")

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

    # Path to the current script
    current_dir = os.path.dirname(__file__)
    
    # Go to the parent of 'config' and then into 'data'
    base_dir = os.path.abspath(os.path.join(current_dir, ".."))
    file_path = os.path.join(base_dir, "data", "lolbins.txt")
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







    


    