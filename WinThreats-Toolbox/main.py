# Python Toolbox - ETW Log Analyzer
# Author: moonpie (aka Alison Caique)
# Date: April 28, 2025

# ===============================
# Main Program Loop
# ===============================

from scanners import detect_DLLHijack
from utils import show_menu
# from scanners import print_hijackable_dlls  # DEBUG



while True:
    # Display the menu and get the user's selection
    # If the user selects option 1, prompt for a specific DLL to check for hijacking
    selection  = show_menu()

    options = {
        1: detect_DLLHijack, 
        #"2": detect_UnmanagedPowerShell,
        #"3": detect_CSharpInjection,
        4: exit 
    }

    if selection[0] in options:
        options[selection[0]](selection[1])  # Pass the target_dll if provided
        break  # Exit the loop after processing the selection