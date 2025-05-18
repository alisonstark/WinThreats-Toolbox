# ===============================
# DLL Hijacking Detection Program
# Unmanaged PowerShell Detection Program
# LSASS Dump Detection Program
# ===============================

import os
from config.converters import security_evtx_parser, evtx_to_csv
import config.utils as conf
from config.logprint import print_sysmon_event, print_security_event

hijackable_dlls = conf.get_hijackable_dlls()
lolbins = conf.get_lolbins()

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
      
        event_id = row.get("EventID", "")
        image = row.get("Image", "")
        image_loaded = row.get("ImageLoaded", "")
            
        # Check if the event ID is '7' (DLL loaded) and the Image ends with ".exe"
        if event_id == '7' and image.endswith(".exe") and image_loaded != "":
            # Check if the loaded image is a DLL
            dll_name = os.path.basename(image_loaded).split("\\")[-1].lower() # TODO: is os.path.basename necessary?

            event_time = row.get("DateTime", "")
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
    
    # Display all other types of events starting from the earliest possible DLL hijacking time
    # User can choose to capture all events within a fixed time window
    len_of_rows = len(spotted_rows)
    filtered_events = []
    if len_of_rows != 0:
        print(f"\n\033[31m[!]{len_of_rows} potential DLL Hijacking events were detected.\033[0m")
        print("Fetch all events starting from the earliest detection time? (Y/N)")
        
        while True:
            user_input = input("Enter your choice: ").strip().lower()
            if user_input in ['y', 'n']:
                break
            print("\033[31m[-] Invalid input. Please enter 'Y' or 'N'.\033[0m")

        if user_input == 'y':
            filtered_events = conf.get_events_filtered_by_time(data_rows, earliest_event_time)
            for event in filtered_events:
                print_sysmon_event(event)

        else:
            print("\033[31m[-] No additional events filtered.\033[0m")
    
    else:
        print("\033[1;31m[-] No DLL Hijacking events detected.\033[0m")
        print("\033[1;31m[-] No events filtered.\033[0m")
        return
    
    len_of_filtered_events = len(filtered_events)
    if len_of_filtered_events > 0:
        print("\n\n\033[1;32m[+] Analysis complete\033[0m\n", 
              f"{len_of_filtered_events} events were filtered\n",
              f"of a total of {len_of_rows} events.\n",
              "\nWould you like to save the matched results to a CSV file? (Y/N)")
    
    elif len_of_filtered_events == 0:
        print("\n\n\033[1;32m[+] Analysis complete\033[0m\n", 
              f"{len_of_rows} events detected.\n",
              "\nWould you like to save the matched results to a CSV file? (Y/N)")

    while True:
        user_input = input("Enter your choice: ").strip().lower()
        if user_input in ['y', 'n']:
            break 
        print("\033[31m[-] Invalid input. Please enter 'Y' or 'N'.\033[0m")
        
    if user_input == 'y' and evtx_path:
        # Save the results to a CSV file for further analysis or record-keeping
        evtx_to_csv(spotted_rows, evtx_path)
        evtx_to_csv(filtered_events, evtx_path)
    
    else:
        print("\033[1;31m[-] Results not saved.\033[0m")
    
    print("\n")

def detect_UnmanagedPowerShell(data_rows, evtx_path=None, target_dll=None):

    spotted_rows = []
    clr_dlls = ["clr.dll", "clrjit.dll"]

    # Number of hits
    injection_suspects = []
    clr_hits = []
    network_alerts = []

    earliest_event_time = None

    for row in data_rows:
        image_loaded = row.get("ImageLoaded", "")
        event_id = row.get("EventID", "")
            
        if event_id == '7' and image_loaded != "":          
            
            # Check if the loaded image is a DLL
            dll_name = os.path.basename(image_loaded).split("\\")[-1].lower()
            
            # If a target DLL is provided, check if it matches the loaded DLL
            if target_dll and target_dll.lower() == dll_name:
                print_sysmon_event(row)
                spotted_rows.append(row)
                clr_hits.append(row)
                
                # Check if the event time is greater than the previous time frame
                event_time = row['DateTime']
                
                # Initialize time_frame if it's the first iteration
                if earliest_event_time is None or event_time < earliest_event_time:
                    earliest_event_time = event_time
            
            # If no target DLL is provided, check if the loaded DLL is in the clr_dlls array
            elif not target_dll and dll_name in clr_dlls:
                print_sysmon_event(row)
                spotted_rows.append(row)
                clr_hits.append(row)

                # Check if the event time is greater than the previous time frame
                event_time = row['DateTime']

                # Initialize time_frame if it's the first iteration
                if earliest_event_time is None or event_time < earliest_event_time:
                    earliest_event_time = event_time

        # ----------------- Event ID 10: ProcessAccess (often used in process injection); Event ID 8: CreateRemoteThread (also used in injection)
        elif event_id == '10' or event_id == '8':
            injection_suspects.append(row)

        # ----------------- Optional: Event ID 3 - Network activity after payload runs
        elif event_id == '3':
            network_alerts.append(row)

    len_of_rows = len(spotted_rows)
    filtered_events = []
    if len_of_rows != 0:
        print("\n\033[31m[!] CLR-based dll detected. Fetch suspicious events starting from the earliest detection time? (Y/N)\033[0m")

        while True:
            user_input = input("Enter your choice: ").strip().lower()
            if user_input in ['y', 'n']:
                break 
            print("\033[31m[-] Invalid input. Please enter 'Y' or 'N'.\033[0m")

        if user_input == 'y':
            # Filter the events based on the earliest event time
            filtered_events = conf.get_events_filtered_by_time(data_rows, earliest_event_time)
                    
            # Print the filtered events
            for event in filtered_events:
                print_sysmon_event(event)

                event_id = event.get("EventID", "")
                image = event.get("Image", "")
                source_image = event.get("SourceImage", "")
                target_image = event.get("TargetImage", "")
                dest_port = event.get("DestinationPort", "")
                dest_ip = event.get("DestinationIp", "")

                # Additional filtering for more targeted detection
                if event_id == '10' or event_id == '8':
                    if conf.is_lolbin(source_image) or conf.is_lolbin(target_image):
                        if event_id == '10':
                            print("\033[31m[!] Potential process injection: A process was accessed. \033[0m")
                        elif event_id == '8':
                            print("\033[31m[!] Potential injection: A remote thread was created. \033[0m")
                        
                        print_sysmon_event(event)
                        spotted_rows.append(event)
                
                elif event_id == '3':
                    if conf.is_lolbin(image) and dest_port == "443":
                        print("\n\033[31m[!] LOLBin made outbound HTTPS connection to socket: \033[0m", 
                            f"{dest_ip}:{dest_port}. Event details:")
                        print_sysmon_event(event)
                        spotted_rows.append(event)
        
        else:
            print("\033[1;31m[-] No unmanaged Powershell executed.\033[0m")
            print("\033[1;31m[-] No events filtered.\033[0m")
    
    len_of_filtered_events = len(filtered_events)
    len_of_data_rows = len(data_rows)
    if len_of_filtered_events > 0:
        print("\n\n\033[1;32m[+] Analysis complete\033[0m\n",
              "Summary:\n",
                f"{len_of_filtered_events} events were filtered\n",
                f"of a total of {len_of_data_rows} events.\n",  
                f"CLR-related hits: {len(clr_hits)} | Injection events: {len(injection_suspects)} | HTTPS connections: {len(network_alerts)}",
                "\nWould you like to save the matched results to a CSV file? (Y/N)")
    
    else:
        print("\n\n\033[1;32m[+] Analysis complete\033[0m\n", 
              "Summary:\n",
                f"{len_of_rows} events detected.\n",  
                f"CLR-related hits: {len(clr_hits)} | Injection events: {len(injection_suspects)} | HTTPS connections: {len(network_alerts)}\n\n",
                "\nWould you like to save the matched results to a CSV file? (Y/N)")

    while True:
        user_input = input("Enter your choice: ").strip().lower()
        if user_input in ['y', 'n']:
            break 
        print("\033[1;31m[-] Invalid input. Please enter 'Y' or 'N'.\033[0m")
        
    if user_input == 'y' and evtx_path:
        # Save the results to a CSV file for further analysis or record-keeping
        evtx_to_csv(spotted_rows, evtx_path)
        evtx_to_csv(filtered_events, evtx_path)
        
    else:
        print("\033[1;31m[-] Results not saved.\033[0m")
    print("\n")

def detect_LsassDump(data_rows, evtx_path=None, placeholder=None):

    spotted_rows = []
    security_events = []
    earliest_dump_time = None

    for row in data_rows:
        event_id = row.get("EventID", "")
        target_image = row.get("TargetImage", "")
        granted_access = row.get("GrantedAccess", "")
        source_user = row.get("SourceUser", "")
        target_user = row.get("TargetUser", "")

        if event_id == '10':
            # Check if the process name is "lsass.exe", the granted access is "0x1fffff"
            # and the source user is different from the target user
            if (target_image.lower().endswith("lsass.exe") and
                granted_access.lower() == "0x001fffff" and
                source_user.split("\\")[-1].lower() != target_user.split("\\")[-1].lower()):

                # Check if the event time is greater than the previous time frame
                dump_time = row['DateTime']

                # Initialize time_frame if it's the first iteration
                if earliest_dump_time is None or dump_time < earliest_dump_time:
                    earliest_dump_time = dump_time
                
                print_sysmon_event(row)
                spotted_rows.append(row)

    len_spotted_rows = len(spotted_rows)
    filtered_events = []
    if len_spotted_rows != 0 and placeholder is None: #TODO: Check whether "placeholder is None" is really necessary
        print("\033[31m\n[!] Lsass dump detected. Fetch events starting from the earliest detection time? (Y/N)\033[0m\n")
        
        while True:
            user_input = input("Enter your choice: ").strip().lower()
            if user_input in ['y', 'n']:
                break 
            print("\033[31m[-] Invalid input. Please enter 'Y' or 'N'.\033[0m")
        
        security_logs_path = ""
        if user_input == 'y':

            print("You need to provide the path to the Security Logs .evtx file.")
            security_logs_path = conf.get_evtx_path()
            security_logs_rows = security_evtx_parser(security_logs_path)

            filtered_events = conf.get_events_filtered_by_time(security_logs_rows, earliest_dump_time)      
            for security_event in filtered_events:
                print_security_event(security_event)
                security_events.append(security_event)

        else:
            print("\033[31m[-] No events filtered.\033[0m")
    
    len_of_security_events = len(filtered_events)
    len_of_spotted_rows = len(spotted_rows)
    len_of_datarows = len(data_rows)
    if len_of_security_events > 0:
        print("\n\n\033[1;32m[+] Analysis complete\033[0m\n", 
              f"{len_of_spotted_rows} suspicious events were detected\n",
              f"of a total of {len_of_datarows} events.\n",
              10*"-" + "\n",
              f"{len_of_security_events} security events were additionally filtered\n",
              f"of a total of {len(security_logs_rows)} security events.\n",
              "\nWould you like to save the matched results to a CSV file? (Y/N)")
    
    elif len_of_security_events == 0:
        print("\n\n\033[1;32m[+] Analysis complete\033[0m\n", 
              f"{len_of_spotted_rows} suspicious events were detected",
              f"of a total of {len_of_datarows} events.",
              "\nWould you like to save the matched results to a CSV file? (Y/N)")

    user_input = input("Enter your choice: ").strip().lower()
    
    if user_input == 'y' and evtx_path:
        # Save the results to a CSV file
        evtx_to_csv(spotted_rows, evtx_path)
        if(len(security_logs_rows) != 0):
            evtx_path(security_logs_rows, evtx_path)
        
    else:
        print("\033[1;31m[-] Results not saved.\033[0m")
    print("\n")


def detect_strange_PPID(data_rows, evtx_path=None, target_dll=None):

    spotted_rows = []
    suspicious_pairs = [
        ("werfault.exe", "cmd.exe"),
        ("explorer.exe", "powershell.exe"),
        ("winword.exe", "cmd.exe"),
        ("excel.exe", "powershell.exe"),
        ("outlook.exe", "cmd.exe"),
        ("wscript.exe", "powershell.exe"),
        ("mshta.exe", "powershell.exe"),
        ("svchost.exe", "cmd.exe"),
        ("services.exe", "cmd.exe"),
        ("rundll32.exe", "powershell.exe"),
        ("regsvr32.exe", "powershell.exe")
    ]

    earliest_event_time = None
    for row in data_rows:
        event_id = row.get("EventID", "")
        image = row.get("Image", "").split("\\")[-1].lower()
        parent_image = row.get("ParentImage", "").split("\\")[-1].lower()
            
        if event_id == '1' and image != "":          
            
            # Tuple is definied by (ParentImage, Image)
            if (parent_image.lower(), image.lower()) in suspicious_pairs:
                print_sysmon_event(row)
                spotted_rows.append(row)

                # Check if the event time is greater than the previous time frame
                event_time = row['DateTime']

                # Initialize time_frame if it's the first iteration
                if earliest_event_time is None or event_time < earliest_event_time:
                    earliest_event_time = event_time

    len_of_rows = len(spotted_rows)
    len_of_data_rows = len(data_rows)
    print("\n\n\033[1;32m[+] Analysis complete\033[0m\n", 
            "Summary:\n",
            f"{len_of_rows} events detected.\n",
            f"of a total of {len_of_data_rows} events."
            "\nWould you like to save the matched results to a CSV file? (Y/N)")

    while True:
        user_input = input("Enter your choice: ").strip().lower()
        if user_input in ['y', 'n']:
            break 
        print("\033[1;31m[-] Invalid input. Please enter 'Y' or 'N'.\033[0m")
        
    if user_input == 'y' and evtx_path:
        # Save the results to a CSV file for further analysis or record-keeping
        evtx_to_csv(spotted_rows, evtx_path)
        
    else:
        print("\033[1;31m[-] Results not saved.\033[0m")
    print("\n")