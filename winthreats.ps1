# PowerShell Toolbox - ETW Log Analyzer
# Author: moonpie (aka Alison Caique)
# Date: April 28, 2025

# ===============================
# Configurations and Arrays
# ===============================

# Placeholder: Add target DLLs here for DLL hijacking detection
$TargetDLLs = @(
    "wininet.dll"
    # Add more DLLs here
)

# ===============================
# Functions
# ===============================

function Show-Menu {
    Clear-Host
    Write-Host "=== ETW Log Analyzer Toolbox ===" -ForegroundColor Cyan
    Write-Host "1) DLL Hijacking Detection"
    Write-Host "2) Unmanaged PowerShell Detection (Coming Soon)"
    Write-Host "3) C# Injection Detection (Coming Soon)"
    Write-Host "4) Exit"
}

function Get-EvtxPath {
    param(
        [string]$PromptMessage = "Enter the full path to the .evtx file:"
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
        LogName = 'Microsoft-Windows-Sysmon'
        Path    = $EvtxPath
        ID      = 7
    }

    Write-Host "`n[+] Parsing logs for possible DLL Hijacking attempts..." -ForegroundColor Yellow

    # Process the events
    Get-WinEvent -FilterHashtable $Filter | Where-Object {
        ($_.Properties[4].Value -like "*.exe") -and (
            $TargetDLLs | ForEach-Object { 
                $_DLL = $_.ToLower()
                $_CurrentLoadedDLL = $_.Properties[5].Value.ToLower()
                if ($_CurrentLoadedDLL -like "*$_DLL*") {
                    return $true
                }
            }
        )
    } | Format-List TimeCreated, ID, Message
}

# Placeholder for future function:
function Detect-UnmanagedPowerShell {
    Write-Host "Unmanaged PowerShell detection is under construction." -ForegroundColor Yellow
}

function Detect-CSharpInjection {
    Write-Host "C# Injection detection is under construction." -ForegroundColor Yellow
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
        "3" { Detect-CSharpInjection }
        "4" { Write-Host "Exiting..." -ForegroundColor Green; break }
        default { Write-Host "Invalid selection, please try again." -ForegroundColor Red }
    }

    Write-Host "`nPress Enter to return to menu..."
    [void][System.Console]::ReadLine()

} while ($true)
