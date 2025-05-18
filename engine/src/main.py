# ===============================
# Main Program Loop
# ===============================

from pathlib import Path
import sys

# Add the parent directory of src to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

import scanners as scan
from config.utils import show_menu, get_evtx_path
from config.converters import sysmon_evtx_parser
# from config.logprint import display_suspicious_events
# from scanners import print_hijackable_dlls, print_lolbins  # DEBUG

evtx_path = get_evtx_path()
data_rows = sysmon_evtx_parser(evtx_path)

while True:
    # Display the menu and get the user's selection
    # If the user selects option 1, prompt for a specific DLL to check for hijacking
    selection  = show_menu()

    options = {
        1: scan.detect_DLLHijack, 
        2: scan.detect_UnmanagedPowerShell,
        3: scan.detect_LsassDump,
        4: scan.detect_strange_PPID,
        5: exit
    }

    if selection[0] in options:
        if selection[0] == 5:
            print("\033[32m[+] Exiting the program...\033[0m\n")
            break
        
        else:
            options[selection[0]](data_rows, evtx_path, selection[1])  # Pass the target_dll if provided
        # break  # Exit the loop after processing the selection