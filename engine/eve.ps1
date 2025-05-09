# ===============================
# Configurations and Arrays
# ===============================


$TargetDLLs = @("wininet.dll", "mswsock.dll", "ws2_32.dll", "wsock32.dll", "wininet.dll", "urlmon.dll", 
"mshtml.dll", "shdocvw.dll", "actxprxy.dll", "msxml3.dll", "msxml6.dll", "msxml2.dll", "scrrun.dll", "vbscript.dll", "jscript.dll",
"msxml.dll", "msxml3.dll", "msxml6.dll", "msxml2.dll", "scrrun.dll", "vbscript.dll", "jscript.dll", "msxml.dll", "msxml3.dll",
"msxml6.dll", "msxml2.dll", "scrrun.dll", "vbscript.dll", "jscript.dll", "msxml.dll", "msxml3.dll", "msxml6.dll", "msxml2.dll")


# Load the list of hijackable DLLs
# $TargetDLLs = Get-HijackableDlls

# ===============================
# Functions
# ===============================

function Show-Menu {
    Clear-Host
    Write-Host "=== ETW Log Analyzer Toolbox ===" -ForegroundColor Cyan
    Write-Host "1) DLL Hijacking Detection"
    Write-Host "2) Unmanaged PowerShell Detection"
    Write-Host "3) LSASS Dump Detection"
    Write-Host "4) Strange Parent-Child Process Detection"
    Write-Host "5) Process Injection Detection"
    Write-Host "6) Process Creation Detection"
    Write-Host "7) Exit"
}

function Get-EvtxPath {
    param(
        [string]$PromptMessage = "Enter the full path to the .evtx file:"
    )
    $evtxPath = Read-Host $PromptMessage
    return $evtxPath
}

function Get-SecurityLogsPath {
    param(
        [string]$PromptMessage = "Enter the full path to the .evtx of the Security Logs file:"
    )
    $evtxPath = Read-Host $PromptMessage
    return $evtxPath
}

function Detect-DLLHijack {
    $EvtxPath = Get-EvtxPath

    # Validate that the file exists
    if (-Not (Test-Path $EvtxPath)) {
        Write-Host "The file path provided does not exist. Exiting DLL Hijack Detection." -ForegroundColor Red
        return
    }

    # FilterHashtable settings
    $Filter = @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Path    = $EvtxPath
        ID      = 7
    }

    Write-Host "`n[+] Parsing logs for possible DLL Hijacking attempts..." -ForegroundColor Yellow

    # Process the events
    Get-WinEvent -FilterHashtable $Filter | Where-Object {
        # Create a variable to store Properties 4 and 5 (Null object pointer exception)
        $_Image = $_.Properties[4].Value
        $_ImageLoaded = $_.Properties[5].Value
        ($_Image -like "*.exe") -and (
            $TargetDLLs | ForEach-Object { 
                $_DLL = $_.ToLower()
                $_CurrentLoadedDLL = $_ImageLoaded.ToLower()
                if ($_CurrentLoadedDLL -like "*$_DLL*") {
                    return $true
                }
            }
        )
    } | Format-List TimeCreated, ID, Message
}

# Placeholder for future function:
function Detect-UnmanagedPowerShell {
    $EvtxPath = Get-EvtxPath

    # Validate that the file exists
    if (-Not (Test-Path $EvtxPath)) {
        Write-Host "The file path provided does not exist. Exiting Unmanaged PowerShell Detection." -ForegroundColor Red
        return
    }

    # FilterHashtable settings
    $Filter = @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Path    = $EvtxPath
        ID      = 7
    }

    Write-Host "`n[+] Parsing logs for possible unmanaged PowerShell instances..." -ForegroundColor Yellow

    Get-WinEvent -FilterHashtable $Filter | Where-Object {
     ($_.Properties[5].Value -like "*clr.dll") -or 
     ($_.Properties[5].Value -like "*clrjit.dll")
    } |
    Format-List TimeCreated, ID, Message
}

function Detect-LSASSDump {

    $EvtxPath = Get-EvtxPath

    # Validate that the file exists
    if (-Not (Test-Path $EvtxPath)) {
        Write-Host "The file path provided does not exist. Exiting LSASS Dump Detection." -ForegroundColor Red
        return
    }

    # FilterHashtable settings
    $Filter = @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Path    = $EvtxPath
        ID      = 10
    }

    Write-Host "`n[+] Parsing logs for possible LSASS Dump attempts..." -ForegroundColor Yellow

    Get-WinEvent -FilterHashtable $Filter | Where-Object {
        $_.Properties[8].Value -like "*lsass.exe" -and
        $_.Properties[9].Value -eq 0x1FFFFF -and
        $_.Properties[11].Value.ToLower() -notlike $_.Properties[12].Value.ToLower()
    } | 
    Format-List TimeCreated, ID, Message

}

function Detect-StrangeParentChild {
    $EvtxPath = Get-EvtxPath

    # Validate that the file exists
    if (-Not (Test-Path $EvtxPath)) {
        Write-Host "The file path provided does not exist. Exiting Strange Parent-Child Process Detection." -ForegroundColor Red
        return
    }

    # FilterHashtable settings
    $Filter = @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Path    = $EvtxPath
        ID      = 1
    }
    
    # TODO: Implement a more comprehensive array of parent processes to check against 
    Get-WinEvent -FilterHashtable $Filter | Where-Object {
        $_.Properties[4].Value -like "*powershell.exe" -and
        $_.Properties[5].Value -like "*cmd.exe"
    } | 
    Format-List TimeCreated, ID, Message
}
function Detect-ProcessInjection {
    $EvtxPath = Get-EvtxPath

    # Validate that the file exists
    if (-Not (Test-Path $EvtxPath)) {
        Write-Host "The file path provided does not exist. Exiting Process Injection Detection." -ForegroundColor Red
        return
    }

    # FilterHashtable settings
    $Filter = @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Path    = $EvtxPath
        ID      = 8
    }
    
    Get-WinEvent -FilterHashtable $Filter | Where-Object {
        $_.Properties[4].Value -like "*powershell.exe" -and
        $_.Properties[5].Value -like "*cmd.exe"
    } | 
    Format-List TimeCreated, ID, Message
}
function Detect-ProcessCreation {
    $EvtxPath = Get-EvtxPath

    # Validate that the file exists
    if (-Not (Test-Path $EvtxPath)) {
        Write-Host "The file path provided does not exist. Exiting Process Creation Detection." -ForegroundColor Red
        return
    }

    # FilterHashtable settings
    $Filter = @{
        LogName = 'Microsoft-Windows-Sysmon/Operational'
        Path    = $EvtxPath
        ID      = 1
    }
    
    Get-WinEvent -FilterHashtable $Filter | Where-Object {
        $_.Properties[4].Value -like "*powershell.exe" -and
        $_.Properties[5].Value -like "*cmd.exe"
    } | 
    Format-List TimeCreated, ID, Message
}

# ===============================
# Main Program Loop
# ===============================

do {
    Show-Menu
    $selection = Read-Host "Please enter the number of your choice"

    switch ($selection) {
        "1" { Detect-DLLHijack }
        "2" { Detect-UnmanagedPowerShell }
        "3" { Detect-LSASSDump }
        "4" { Detect-StrangeParentChild }
        "5" { Detect-ProcessInjection }
        "6" { Detect-ProcessCreation }
        "7" { Write-Host "Exiting..." -ForegroundColor Green; break }
        default { Write-Host "Invalid selection, please try again." -ForegroundColor Red }
    }

    Write-Host "`nPress Enter to return to menu..."
    [void][System.Console]::ReadLine()

} while ($true)
