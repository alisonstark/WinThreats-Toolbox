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
    print("4) Detect Strange PPID")
    # print("4) All of the above")
    print("5) Exit")
    print("=================================\n")

    target_dll = None
    # Loop until a valid choice is made
    while True:
        try:
            choice = int(input("Select an option (1-5): "))
            if choice in [1, 2, 3, 4, 5]:
                if choice == 1 or choice == 2:
                    print("\nProvide a specific DLL to help filter search (optional).")
                    target_dll = input("Enter the DLL name (e.g., example.dll) or press Enter to skip: ")
                    
                    if target_dll and not target_dll.endswith(".dll"):
                        target_dll = input("\033[31m[-] Invalid DLL name. Please include the .dll extension:\033[0m")

                    elif target_dll:
                        target_dll = target_dll.strip().lower()
                    
                    # If the user provides a DLL name, return it along with the choice
                    print("\n")
                    return choice, target_dll if target_dll else None
                
                # If the user selects options 2 or 3, return the choice and None for target_dll
                else:
                    print("\n")
                    return choice, None
                   
            else:
                # In case user enters a number outside the range
                # This will be handled in the main loop
                print("\033[31m[-] Invalid choice. Please select a valid option (1-4).\033[0m")
        
        # In case user enters a non-integer value
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 5.")

# Function to display all events after a specific time
# Filter the events based on the earliest event time
def filter_events_by_time(data_rows, starting_time, user_minutes):
    if not data_rows:
        print("\033[31m[-] No data rows available.\033[0m")
        return []
    # Check if starting_time is not None
    elif starting_time:
        filtered_events = []
        event_count = 0
        max_events = 20

        if user_minutes is None:
            user_minutes = 0
        # Filter events within the specified time frame
        time_threshold = starting_time + timedelta(minutes=user_minutes)
        
        # Populate the filtered events list
        for row in data_rows: 
            time_created = row.get('DateTime', "")

            # Check if the event is within the specified time frame
            if time_threshold != starting_time and starting_time <= time_created <= time_threshold:
                filtered_events.append(row)
            
            # Filter events after the specified time
            elif time_threshold == starting_time:
                
                if time_created >= starting_time:
                    filtered_events.append(row)
                    event_count += 1
                    # Limit the number of events to be displayed #FIXME: Keeps displaying max_events msg with every loop iteration that exceeds 20
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

        print("\n\033[32m[+] Filtered events based on the earliest detection time\033[0m\n")
        
    else:
        print("\033[31m[-] No events filtered.\033[0m")
        return []

    return filtered_events

def get_evtx_path():
    print("Enter the full path to the .evtx file: ")

    while True:
        evtx_path = input()

        if not evtx_path:
            print("\033[31m[-] No path provided. Please provide a path.\033[0m")
            continue

        elif not evtx_path.endswith(".evtx"):
            print("\033[31m[-] Invalid file type. Please provide a .evtx file.\033[0m")
            continue
        
        else:
            print("[+] File successfully loaded")
            break
    
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
def is_lolbin(image_path):
    if not image_path:
        return False
    binary = os.path.basename(image_path).split("\\")[-1].lower()
    return bool(binary and get_lolbins() and binary in get_lolbins())


def get_events_filtered_by_time(events, starting_time):
    user_minutes = None
    while True:
        # Filter the events based on the earliest event time
        try:
            time_input = input("Enter the time frame in minutes (leave blank to display all events): ").strip().lower()
            if time_input != "":
                user_minutes = int(time_input)

                if user_minutes < 0:
                    print("\033[31m[-] Invalid time frame. Please enter a positive number.\033[0m")
                    continue
                else:
                    break
            else:
                break
        except ValueError:
            print("\033[31m[-] Invalid input. Please enter a valid number.\033[0m")
            continue
        except Exception as e:
            print(f"An error occurred in `get_events_filtered_by_time()`: {e}")
            continue

    # Return filtered events
    return filter_events_by_time(events, starting_time, user_minutes)

  






    


    