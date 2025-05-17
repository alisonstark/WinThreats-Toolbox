# ===============================
# .evtx to .csv Converter Program
# ===============================

# Python imports
from Evtx.Evtx import Evtx
from datetime import datetime
import csv

import xml.etree.ElementTree as ET

sysmon_event_data_fields = [
    "EventID", "RuleName", "TimeCreated", "ProcessGuid", "ProcessId", "Image", "ImageLoaded",
    "Hashes", "Signed", "Signature", "SignatureStatus", "SourceProcessGuid", "SourceProcessId",
    "SourceImage", "TargetProcessGuid", "TargetProcessId", "TargetImage", "GrantedAccess", "CallTrace",
    "User", "SourceUser", "TargetUser", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", 
    "ParentUser", "SourceIp", "SourceHostname", "SourcePort", "DestinationIp", "DestinationHostname", 
    "DestinationPort", "Protocol"
]

security_event_data_fields = [
    "EventID", "TimeCreated", "SubjectUserSid", "SubjectUserName", "SubjectDomainName", "SubjectLogonId",
    "NewProcessId", "NewProcessName", "ProcessId", "ProcessName", "ParentProcessName", "CreatorProcessId",
    "TokenElevationType", "ObjectServer", "ObjectType", "ObjectName", "HandleId", "AccessMask", "AccessReasons",
    "Privileges", "PrivilegeList", "OperationType", "AuditPolicyChanges", "TargetUserSid", "TargetUserName",
    "TargetDomainName", "TargetLogonId", "CallTrace",
]

def sysmon_evtx_parser(evtx_path):

    # BUG: Creates 'CreateKey' somewhere in this logic when it finds no value/key
    # SUSPICION: It may be that "name" in properties[] is a match but for a specific event this property name does not exist 

    all_rows = []
    properties = []

    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            
            try:
                xml_str = record.xml()
                root = ET.fromstring(xml_str)
                # print(ET.tostring(root, encoding='unicode', method='xml'))  # DEBUG XML format

                # Namespace-aware parsing
                ns = {"ns0": "http://schemas.microsoft.com/win/2004/08/events/event"}

                properties.append("EventID")
                properties.append("DateTime")
                for data in root.findall(".//ns0:Data", ns):
                    if data.text != "":
                        name = data.attrib.get("Name")                    
                        properties.append(name)
            
                # ACTUAL xml format: <ns0:EventID Qualifiers="">10</ns0:EventID>
                # Extract using namespace
                row_dict = {}
                event_id_elem = root.find(".//ns0:EventID", ns)
                if event_id_elem is not None and event_id_elem.text:
                    row_dict["EventID"] = event_id_elem.text

                # ACTUAL xml format: <ns0:EventData><ns0:Data Name="RuleName">-</ns0:Data>
                # Extract using namespace
                for data in root.findall(".//ns0:Data", ns): # DEBUG           
                    name = data.attrib.get("Name")
                    value = data.text
                    
                    if name == "UtcTime":
                        try:
                            # Try with T and Z (ideal ISO format)
                            utc_time = datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ")
                        except ValueError:
                            try:
                                # Fallback to space-separated format (what you have)
                                utc_time = datetime.strptime(value, "%Y-%m-%d %H:%M:%S.%f")
                            except ValueError:
                                print(f"[-] Failed to parse UtcTime: {value}")
                                continue
                        
                        # local_time = utc_time.strftime("%Y-%m-%d %H:%M:%S.%f")
                        row_dict['DateTime'] = utc_time # Not local_time
                    
                    if name in properties:
                        row_dict[name] = value

                all_rows.append(row_dict)

            except Exception as e:
                print(f"Error processing Sysmon record: {e}")
                print(f"Record XML: {record.xml()}")

    # for row in all_rows:
    #    print(row) # DEBUG all rows, where all_rows = [row_dict_1, row_dict_2, row_dict_3, ...]

    return all_rows

def sysmon_evtx_to_csv(data_rows, evtx_path):
    csv_path = evtx_path.replace(".evtx", ".csv")
    with open(csv_path, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=sysmon_event_data_fields)
            writer.writeheader()
            writer.writerows(data_rows)
    print("\033[32m[+] Results saved to CSV file:\033[0m " + csv_path)

def security_evtx_parser(evtx_path):
    all_rows = []
    properties = []

    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            try:
                xml_str = record.xml()
                # print(ET.tostring(record.xml(), encoding='unicode', method='xml'))
                root = ET.fromstring(xml_str)

                # Namespace-aware parsing
                ns = {"ns0": "http://schemas.microsoft.com/win/2004/08/events/event"}

                properties.append("EventID")
                properties.append("DateTime")
                for data in root.findall(".//ns0:Data", ns):
                    if data.text != "":
                        name = data.attrib.get("Name")          
                        properties.append(name)

                row_dict = {}  # default empty values

                # Extract using namespace
                event_id_elem = root.find(".//ns0:EventID", ns)
                if event_id_elem is not None and event_id_elem.text:
                    row_dict["EventID"] = event_id_elem.text
                
                # ACTUAL xml format: <ns0:TimeCreated SystemTime="2025-04-28T12:34:56.789Z"/>
                time_created_elem = root.find(".//ns0:TimeCreated", ns)
                if time_created_elem is not None and time_created_elem.attrib.get("SystemTime"):
                    try:
                        # Parse to datetime object
                        utc_time = datetime.strptime(time_created_elem.attrib.get("SystemTime"), "%Y-%m-%dT%H:%M:%S.%fZ")
                        row_dict['DateTime'] = utc_time
                    except ValueError:
                        print(f"[-] Failed to parse SystemTime: {time_created_elem.attrib.get('SystemTime')}")

                # Extract using namespace
                for data in root.findall(".//ns0:Data", ns): # DEBUG
                    
                    name = data.attrib.get("Name")
                    value = data.text or ""

                    if name in properties:
                        row_dict[name] = value

                all_rows.append(row_dict)

            except Exception as e:
                print(f"Error processing Security record: {e}")
                print(f"Record XML: {record.xml()}")

    return all_rows