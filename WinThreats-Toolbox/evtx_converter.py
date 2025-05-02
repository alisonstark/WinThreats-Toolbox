# Python Toolbox - ETW Log Analyzer
# Author: moonpie (aka Alison Caique)
# Date: April 28, 2025

# ===============================
# .evtx to .csv Converter Program
# ===============================

# Python imports
from Evtx.Evtx import Evtx
import csv
import xml.etree.ElementTree as ET


def evtx_parser(evtx_path, csv_path):

    event_data_fields = [
        "EventID", "RuleName", "UtcTime", "ProcessGuid", "ProcessId", "Image", "ImageLoaded",
        "Hashes", "Signed", "Signature", "SignatureStatus", "SourceProcessGuid", "SourceProcessId",
        "SourceImage", "TargetProcessGuid", "TargetProcessId", "TargetImage", "CallTrace",
        "User", "LogonGuid", "LogonId", "TerminalSessionId", "IntegrityLevel", "ParentUser"
    ]

    all_rows = []

    with Evtx(str(evtx_path)) as log:
        for record in log.records():
            
            try:
                xml_str = record.xml()
                root = ET.fromstring(xml_str)
                # print(ET.tostring(root, encoding='unicode', method='xml'))  # DEBUG XML format

                # Namespace-aware parsing
                ns = {"ns0": "http://schemas.microsoft.com/win/2004/08/events/event"}

                row_dict = {key: "" for key in event_data_fields}  # default empty values

                # ACTUAL xml format: <ns0:EventID Qualifiers="">10</ns0:EventID>
                # Extract using namespace
                event_id_elem = root.find(".//ns0:EventID", ns)
                if event_id_elem is not None and event_id_elem.text:
                    row_dict["EventID"] = event_id_elem.text

                # ACTUAL xml format: <ns0:EventData><ns0:Data Name="RuleName">-</ns0:Data>
                # Extract using namespace
                for data in root.findall(".//ns0:Data", ns): # DEBUG
                    
                    name = data.attrib.get("Name")
                    value = data.text or ""
                    # print(name + "##########" + value) # DEBUG data names from event_data_fields and their value

                    if name in row_dict:
                        row_dict[name] = value

                all_rows.append(row_dict)

            except Exception as e:
                print(f"Error processing record: {e}")
                print(f"Record XML: {record.xml()}")

    # for row in all_rows:
    #    print(row) # DEBUG all rows, where all_rows = [row_dict_1, row_dict_2, row_dict_3, ...]


    # Save to CSV
    with open(csv_path, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=event_data_fields)
        writer.writeheader()
        writer.writerows(all_rows)

    return all_rows