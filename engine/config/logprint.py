# ===============================
# Log Printing Functions
# ===============================

from pprint import pprint
# import src.scanners as scan

# Function to print the event details
# This function is called when a potential malicious activity is detected
def print_sysmon_event(event):
    print("\033[1;36m[+] Summary of the activity\033[0m")

    event_id = event.get("EventID", "")
    image = event.get("Image", "")
    source_image = event.get("SourceImage", "")
    target_image = event.get("TargetImage", "")
    utc_time = event.get("UtcTime", "")
    
    # Case of Unmanaged Powershell attacks
    if image == "" or event_id == '8' or event_id == '10':
        print(f"Injector process: {source_image}" + "\n",
              f"Injected process: {target_image}" + "\n", 
              f"Event Time: {utc_time}" + "\n")
    
    else:
        print(f"Initiator process: {image}" + "\n",
          f"Event Time: {utc_time}" + "\n")
    
    pprint(event)
    print("\n")

def print_security_event(event):

    process_name = event.get("ProcessName", "")
    time_created = event.get("TimeCreated", "")

    if process_name != "" and time_created != "":
        print("\033[1;36m\n[+] Summary of the activity\033[0m")
        print(f"Process name: {event['ProcessName']}" + "\n",
            f"Event Time: {event['TimeCreated']}" + "\n")
    pprint(event)
    print("\n")

#BUG: circular import (scanners.py)
#def display_suspicious_events(events, placeholder1=None, placeholder2=None):
#    if not events:
#        print("\033[31m[-] No suspicious events found.\033[0m")
#        return
#
#    print("\033[32m[+] Displaying suspicious DLL events\033[0m")
#    scan.detect_DLLHijack(events)
#    print("\033[32m[+] Displaying suspicious Unmanaged PowerShell events\033[0m")
#    scan.detect_UnmanagedPowerShell(events)
#    print("\n\033[32m[+] Displaying suspicious LSASS dump events\033[0m")
#    scan.detect_LsassDump(events)

    # List of high-value event IDs
    # These event IDs are considered high-value and may indicate malicious activity
   # high_value_event_ids = ["4688", "4689", "4690", "4691", "4692", "4693", "4624", "4672", "4656", 
   #                          "4663", "4670", "4673", "4674", "4675", "4676", "4677", "4678", "4679", 
   #                          "4680", "4681", "4682", "4683", "4684", "4685", "4686", "4687"]
   # for event in events:
   #      # Additional filtering
   #      # Check for high-value event IDs
   #     if event["EventID"] == '8' and event["SourceImage"].lower().endswith("powershell.exe"):
   #          print("\033[31m[!] Potential malicious activity detected from PowerShell!\033[0m")
   #          print_sysmon_event(event)
 #       elif event["EventID"] in high_value_event_ids:
  #          print("\033[31m[!] Potential malicious activity detected from high-value event ID!\033[0m")
  #          print_security_event(event)