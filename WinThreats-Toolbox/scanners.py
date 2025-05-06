# Python Toolbox - ETW Log Analyzer
# Author: moonpie (aka Alison Caique)
# Date: April 28, 2025

# ===============================
# DLL Hijacking Detection, 
# Unmanaged PowerShell Detection Program
# ===============================

import os
from converters import evtx_to_csv
from datetime import datetime, timedelta
from utils import get_hijackable_dlls, get_lolbins, is_lolbin, print_event

hijackable_dlls = get_hijackable_dlls()
lolbins = get_lolbins()

# DEBUG: Function to print the hijackable DLLs
# def print_hijackable_dlls():
#    for dll in hijackable_dlls:
#        print(dll)

# DEBUG: Function to print the LOLBins
# def print_lolbins():
#    for lolbin in lolbins:
#        print(lolbin)

def detect_DLLHijack(evtx_path, data_rows, target_dll=None):

    spotted_rows = []

    # Check if the loaded image is in the array of target DLLs
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
    
    print("\033[32m[+] Analysis complete\033[0m", "\nWould you like to save the matched results to a CSV file? Y/N\n")
    user_input = input("Enter your choice: ").strip().lower()
    
    if user_input == 'y':
        # Save the results to a CSV file
        evtx_to_csv(spotted_rows, evtx_path)
        
    else:
        print("\033[31m[-] Results not saved.\033[0m")
    print("\n\n")

def detect_UnmanagedPowerShell(evtx_path, data_rows, target_dll=None): # DEBUG ------------------------>
    
    spotted_rows = []
    clr_dlls = ["clr.dll", "clrjit.dll"]

    # Number of hits
    injection_suspects = []
    clr_hits = []
    # network_alerts = []

    earliest_event_time = None

    for row in data_rows:
        try:
            event_id = row["EventID"]
            
            if event_id == '7':          
                if row["ImageLoaded"]:
                
                    # Check if the loaded image is a DLL
                    dll_name = os.path.basename(row["ImageLoaded"]).split("\\")[-1].lower() # TODO: is os.path.basename necessary?
                    
                    # If a target DLL is provided, check if it matches the loaded DLL
                    if target_dll and target_dll.lower() == dll_name:
                        print_event(row)
                        spotted_rows.append(row)
                        clr_hits.append(row)
                        
                        # Check if the event time is greater than the previous time frame
                        event_time = datetime.strptime(row["UtcTime"], "%Y-%m-%d %H:%M:%S.%f")
                        
                        # Initialize time_frame if it's the first iteration
                        if earliest_event_time is None or event_time < earliest_event_time:
                            earliest_event_time = event_time
                    
                    # If no target DLL is provided, check if the loaded DLL is in the clr_dlls array
                    elif not target_dll and dll_name in clr_dlls:
                        print_event(row)
                        spotted_rows.append(row)
                        clr_hits.append(row)

                        # Check if the event time is greater than the previous time frame
                        event_time = datetime.strptime(row["UtcTime"], "%Y-%m-%d %H:%M:%S.%f")
                        
                        # Initialize time_frame if it's the first iteration
                        if earliest_event_time is None or event_time < earliest_event_time:
                            earliest_event_time = event_time
        
            
             # Event ID 10 (ProcessAccess) or event ID 8 (CreateRemoteThread)
            # TODO: Uncomment and implement process access and create remote thread detection logic
            elif event_id == '10' or event_id == '8': 
                injection_suspects.append(row)


        except KeyError:
            print("KeyError: 'ImageLoaded' not found in row data.")
            continue
        except Exception as e:
            print(f"An error occurred: {e}")
            continue
    
    print("\033[31m[!] CLR-based dll detected. Fetch events starting from the earliest detection time? (Y/N)\033[0m")
    user_input = input("Enter your choice: ").strip().lower()
    if user_input == 'y':
        # Filter the events based on the earliest event time
        try:
            time_input = int(input("Enter the time frame in minutes (leave blank to display all events): ").strip().lower())
            user_minutes = int(time_input)

            if user_minutes < 0:
                print("\033[31m[-] Invalid time frame. Please enter a positive number.\033[0m")
                exit(1)
            elif user_minutes > 0:
                # Filter events within the specified time frame
                time_threshold = earliest_event_time + timedelta(minutes=user_minutes)
                filtered_events = [
                    row for row in data_rows 
                    if earliest_event_time <= datetime.strptime(row["UtcTime"], "%Y-%m-%d %H:%M:%S.%f") <= time_threshold
                ]
            # if time_input == 0:
            else:
                filtered_events = [
                    row for row in data_rows 
                    if datetime.strptime(row["UtcTime"], "%Y-%m-%d %H:%M:%S.%f") >= earliest_event_time
                ]
        
        except ValueError:
            print("\033[31m[-] Invalid input. Please enter a valid number.\033[0m")
            exit(1)
        
        # Print the filtered events
        for event in filtered_events:
            if event["EventID"] == '10' or event["EventID"] == '8':
                if is_lolbin(event["SourceImage"], lolbins) or is_lolbin(event["TargetImage"], lolbins):
                    print_event(event)
                    spotted_rows.append(event)
            
            elif event["EventID"] == '3':
                if is_lolbin(event["Image"], lolbins) and event["DestinationPort"] == "443":
                    print("\033[31m[!] LOLBin made outbound HTTPS connection to: \033[0m", 
                          f"{event['DestinationIp']}:{event['DestinationPort']} (Event ID 3):")
                    print_event(event)
                    spotted_rows.append(event)

        print("\033[32m[+] Filtered events based on the earliest detection time:\033[0m")
    
    else:
        print("\033[31m[-] No events filtered.\033[0m")
    
    print("\033[32m[+] Analysis complete\033[0m", 
          "\nWould you like to save the matched results to a CSV file? (Y/N)\n")
    user_input = input("Enter your choice: ").strip().lower()
    
    if user_input == 'y':
        # Save the results to a CSV file
        evtx_to_csv(spotted_rows, evtx_path)
        
    else:
        print("\033[31m[-] Results not saved.\033[0m")
    print("\n\n")

    
