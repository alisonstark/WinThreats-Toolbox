# ETW Toolbox: PowerShell Event Log Analyzer

## Overview

The **ETW Toolbox** is a PowerShell-based tool designed to analyze Windows Event Logs using **Event Tracing for Windows (ETW)**. It provides functionalities to filter, detect, and log various system events, such as **DLL Hijacking**, through customized queries and filters.

This tool is an essential utility for those working with **Sysmon Logs** and **Windows Event Logs**, particularly for security analysts and anyone interested in **Windows-based security monitoring**.

## Features

- **DLL Hijacking Detection**: Identify potentially malicious hijacking of legitimate DLLs (with customizable DLL lists).
- **Customizable Filters**: Easily add or modify event filters to detect different kinds of system anomalies and suspicious behaviors.
- **Event Log Analysis**: Use powerful filters to analyze Windows Event Logs with ease.

## Installation

To use the ETW Toolbox, you must have **PowerShell** installed. If you don't have PowerShell, follow the instructions below:

### 1. Install PowerShell

- **Ubuntu/Linux**:  
  sudo snap install powershell --classic
