# Python Toolbox - ETW Log Analyzer
# Author: moonpie (aka Alison Caique)
# Date: April 28, 2025

# ===============================
# Auxiliary Functions
# ===============================

def show_menu():
    print("=== ETW Log Analyzer Toolbox ===")
    print("1) DLL Hijacking Detection")
    print("2) Unmanaged PowerShell Detection (Coming Soon)")
    print("3) C# Injection Detection (Coming Soon)")
    print("4) Exit")
    
    while True:
        try:
            choice = int(input("Select an option (1-4): "))
            if choice in [1, 2, 3, 4]:
                return choice
            else:
                # In case user enters a number outside the range
                # This will be handled in the main loop
                print("Invalid choice. Please select a valid option (1-4).")
        
        # In case user enters a non-integer value
        except ValueError:
            print("Invalid input. Please enter a number between 1 and 4.")


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






    


    