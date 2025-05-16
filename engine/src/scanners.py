# ===============================
# DLL Hijacking Detection Program
# Unmanaged PowerShell Detection Program
# LSASS Dump Detection Program
# ===============================

import os
from config.converters import security_evtx_parser, sysmon_evtx_to_csv
from datetime import timedelta
from config.utils import get_hijackable_dlls, get_lolbins, is_lolbin, filter_events_by_time
from config.logprint import print_sysmon_event, print_security_event

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

def detect_DLLHijack(data_rows, evtx_path=None, target_dll=None):

    spotted_rows = []
    earliest_event_time = None

    # Precompute the hijackable DLLs in lowercase for efficiency
    hijackable_dlls_lower = [dll.lower() for dll in hijackable_dlls]

    # Check if the loaded image is in the array of target DLLs
    for row in data_rows:
        # Check if the row contains the necessary keys
        # and if the EventID is '7' (DLL loaded) and the Image ends with ".exe"
        # and if the ImageLoaded is not empty
        try:         
            event_id = row["EventID"]
            image = row["Image"]
            image_loaded = row["ImageLoaded"]
        
        except KeyError:
            print(f"An error occurred: KeyError - {e}")
            continue
        except Exception as e:
            print(f"An error occurred: {e}")
            continue
            
        # Check if the event ID is '7' (DLL loaded) and the Image ends with ".exe"
        if event_id == '7' and image.endswith(".exe") and image_loaded:
            # Check if the loaded image is a DLL
            dll_name = os.path.basename(image_loaded).split("\\")[-1].lower() # TODO: is os.path.basename necessary?

            event_time = row.get("TimeCreated", "")
            if earliest_event_time is None or earliest_event_time > event_time:
                earliest_event_time = event_time

            # Check if the loaded DLL is in the hijackable array or equals the target DLL
            if target_dll and target_dll.lower() == dll_name:
                print_sysmon_event(row)
                spotted_rows.append(row)

            # If no target DLL is provided, check if the loaded DLL is in the hijackable array
            elif not target_dll and dll_name in hijackable_dlls_lower:
                print_sysmon_event(row)
                spotted_rows.append(row)
        
    if len(spotted_rows) != 0:
        print("\033[31m[!] Potential DLL Hijacking detected. Fetch events starting from the earliest detection time? (Y/N)\033[0m")
        
        while True:
            user_input = input("Enter your choice: ").strip().lower()
            if user_input in ['y', 'n']:
                break
            print("\033[31m[-] Invalid input. Please enter 'Y' or 'N'.\033[0m")

        if user_input == 'y':
            time_input = ""
            while True:
                # Filter the events based on the earliest event time
                try:
                    time_input = input("Enter the time frame in minutes (leave blank to display all events): ").strip().lower()
                    if time_input != "":
                        print("ENTERED HERE")
                        user_minutes = int(time_input)

                        if user_minutes < 0:
                            print("\033[31m[-] Invalid time frame. Please enter a positive number.\033[0m")
                            continue

                        elif user_minutes > 0:
                            # Filter events within the specified time frame
                            filtered_events = filter_events_by_time(spotted_rows, earliest_event_time, user_minutes)
                            print_sysmon_event(filtered_events)
                            break

                    else:
                        # Display all events
                        print("\033[32m[+] Displaying all events\033[0m")
                        filtered_events = filter_events_by_time(spotted_rows, earliest_event_time, None)
                        print_sysmon_event(filtered_events)
                        break

                except ValueError:
                    print("\033[31m[-] Invalid input. Please enter a valid number.\033[0m")
                    continue
                except KeyError:
                    print(f"An error occurred: KeyError - {e}")
                    continue
                except Exception as e:
                    print(f"An error occurred: {e}")
                    continue

        else:
            print("\033[31m[-] No events filtered.\033[0m")
    
    else:
        print("\033[31m[-] No DLL Hijacking events detected.\033[0m")
        print("\033[31m[-] No events filtered.\033[0m")
        return
    
    print("\033[32m[+] Analysis complete\033[0m", "\nWould you like to save the matched results to a CSV file? Y/N\n")
    user_input = input("Enter your choice: ").strip().lower()
    
    if user_input == 'y' and evtx_path:
        # Save the results to a CSV file for further analysis or record-keeping
        sysmon_evtx_to_csv(spotted_rows, evtx_path)
    else:
        print("\033[31m[-] Results not saved.\033[0m")
    
    print("\n\n")

def detect_UnmanagedPowerShell(data_rows, evtx_path=None, target_dll=None):

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
                    dll_name = os.path.basename(row["ImageLoaded"]).split("\\")[-1].lower() # NOTE is os.path.basename necessary?
                    
                    # If a target DLL is provided, check if it matches the loaded DLL
                    if target_dll and target_dll.lower() == dll_name:
                        print_sysmon_event(row)
                        spotted_rows.append(row)
                        clr_hits.append(row)
                        
                        # Check if the event time is greater than the previous time frame
                        event_time = row['TimeCreated']
                        
                        # Initialize time_frame if it's the first iteration
                        if earliest_event_time is None or event_time < earliest_event_time:
                            earliest_event_time = event_time
                    
                    # If no target DLL is provided, check if the loaded DLL is in the clr_dlls array
                    elif not target_dll and dll_name in clr_dlls:
                        print_sysmon_event(row)
                        spotted_rows.append(row)
                        clr_hits.append(row)

                        # Check if the event time is greater than the previous time frame
                        event_time = row['TimeCreated']

                        # Initialize time_frame if it's the first iteration
                        if earliest_event_time is None or event_time < earliest_event_time:
                            earliest_event_time = event_time
        
            
             # Event ID 10 (ProcessAccess) or event ID 8 (CreateRemoteThread)
            # TODO: Uncomment and implement process access and create remote thread detection logic
            # [ ]  ProcessAccess logic
            # [ ]  CreateRemoteThread logic
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
                    if earliest_event_time <= row['TimeCreated'] <= time_threshold
                ]
            # if time_input == 0:
            else:
                filtered_events = [
                    row for row in data_rows 
                    if row['TimeCreated'] >= earliest_event_time
                ]

        except ValueError:
            print("\033[31m[-] Invalid input. Please enter a valid number.\033[0m")
            exit(1)
        
        # Print the filtered events
        for event in filtered_events:
            if event["EventID"] == '10' or event["EventID"] == '8':
                if is_lolbin(event["SourceImage"], lolbins) or is_lolbin(event["TargetImage"], lolbins):
                    print_sysmon_event(event)
                    spotted_rows.append(event)
            
            elif event["EventID"] == '3':
                if is_lolbin(event["Image"], lolbins) and event["DestinationPort"] == "443":
                    print("\033[31m[!] LOLBin made outbound HTTPS connection to: \033[0m", 
                          f"{event['DestinationIp']}:{event['DestinationPort']} (Event ID 3):")
                    print_sysmon_event(event)
                    spotted_rows.append(event)

        print("\033[32m[+] Filtered events based on the earliest detection time:\033[0m")
    
    else:
        print("\033[31m[-] No events filtered.\033[0m")
    
    print("\033[32m[+] Analysis complete\033[0m", 
          "\nWould you like to save the matched results to a CSV file? (Y/N)\n")
    user_input = input("Enter your choice: ").strip().lower()
    
    if user_input == 'y' and evtx_path:
        # Save the results to a CSV file
        sysmon_evtx_to_csv(spotted_rows, evtx_path)
        
    else:
        print("\033[31m[-] Results not saved.\033[0m")
    print("\n\n")

def detect_LsassDump(data_rows, evtx_path=None, placeholder=None):

    spotted_rows = []
    earliest_dump_time = None

    for row in data_rows:
        try:
            event_id = row["EventID"]
            if event_id == '10':
                # Check if the process name is "lsass.exe", the granted access is "0x1fffff"
                # and the source user is different from the target user
                if (row["TargetImage"].lower().endswith("lsass.exe") and
                    row["GrantedAccess"].lower() == "0x001fffff" and
                    row["SourceUser"].split("\\")[-1].lower() != row["TargetUser"].split("\\")[-1].lower()):

                     # Check if the event time is greater than the previous time frame
                    dump_time = row['TimeCreated']

                    # Initialize time_frame if it's the first iteration
                    if earliest_dump_time is None or dump_time < earliest_dump_time:
                        earliest_dump_time = dump_time
                    
                    print_sysmon_event(row)
                    spotted_rows.append(row)

        except KeyError:
            print("KeyError: 'SourceImage' not found in row data.")
            continue
        except Exception as e:
            print(f"An error occurred: {e}")
            continue
    
    if earliest_dump_time and placeholder is None:
        print("\033[31m\n[!] Lsass dump detected. Fetch events starting from the earliest detection time? (Y/N)\033[0m\n")
        user_input = input("Enter your choice: ").strip().lower()
        if user_input == 'y':
            security_logs_path = input("Enter the full path to the Security Logs .evtx file: ")
            if not security_logs_path:
                print("\033[31m[-] No path provided. Exiting.\033[0m")
                exit(1)
            elif not security_logs_path.endswith(".evtx"):
                print("\033[31m[-] Invalid file type. Please provide a .evtx file.\033[0m")
                exit(1)
            
            else:
                # Convert the Security Logs .evtx file to CSV
                security_logs_rows = security_evtx_parser(security_logs_path)
                # print(security_logs_rows) DEBUG
            
            while True: # FIXME: DEBUG NOT OK
                # Filter the events based on the earliest event time
                try:
                    time_input = input("Now enter the time frame in minutes (or leave blank to display all events): ").strip()
        
                    if time_input == "":
                        user_minutes = None  # or some default logic to handle 'all events'
                        filtered_events = filter_events_by_time(security_logs_rows, earliest_dump_time, user_minutes) # TODO: security log rows are empty
                        print_security_event(filtered_events)
                        break
                    
                    user_minutes = int(time_input)
                    filtered_events = filter_events_by_time(security_logs_rows, earliest_dump_time, user_minutes)
                    print_security_event(filtered_events)
                    break

                except ValueError:
                    print("\033[31m[-] Invalid input. Please enter a valid number.\033[0m")

        else:
            print("\033[31m[-] No events filtered.\033[0m")
    
    print("\033[32m[+] Analysis complete\033[0m", 
          "\nWould you like to save the matched results to a CSV file? (Y/N)\n")
    user_input = input("Enter your choice: ").strip().lower()
    
    if user_input == 'y' and evtx_path:
        # Save the results to a CSV file
        sysmon_evtx_to_csv(spotted_rows, evtx_path)
        
    else:
        print("\033[31m[-] Results not saved.\033[0m")
    print("\n\n")