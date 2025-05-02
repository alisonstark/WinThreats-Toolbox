# Python Toolbox - ETW Log Analyzer
# Author: moonpie (aka Alison Caique)
# Date: April 28, 2025

# ===============================
# Main Program Loop
# ===============================

from scanners import detect_DLLHijack
from utils import show_menu



while True:
    selection  = show_menu()

    options = {
        1: detect_DLLHijack, 
        #"2": detect_UnmanagedPowerShell,
        #"3": detect_CSharpInjection,
        4: exit  # DEBUG ----------------> FIXED
    }

    if selection in options:
        options[selection]()
        break