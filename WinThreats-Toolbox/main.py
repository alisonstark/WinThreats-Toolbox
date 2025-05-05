# Python Toolbox - ETW Log Analyzer
# Author: moonpie (aka Alison Caique)
# Date: April 28, 2025

# ===============================
# Main Program Loop
# ===============================

from scanners import detect_DLLHijack, detect_UnmanagedPowerShell
from utils import show_menu, get_evtx_path
from converters import evtx_parser
# from scanners import print_hijackable_dlls  # DEBUG

# "C:\\path\\to\\your\\evtx_file.evtx"  Replace with your actual path
evtx_path = get_evtx_path()
data_rows = evtx_parser(evtx_path)

while True:
    print("Entered loop")
    # Display the menu and get the user's selection
    # If the user selects option 1, prompt for a specific DLL to check for hijacking
    selection  = show_menu()

    options = {
        1: detect_DLLHijack, 
        2: detect_UnmanagedPowerShell,
        #"3": detect_CSharpInjection,
        4: exit 
    }

    if selection[0] in options:
        options[selection[0]](evtx_path, data_rows, selection[1])  # Pass the target_dll if provided
        break  # Exit the loop after processing the selection