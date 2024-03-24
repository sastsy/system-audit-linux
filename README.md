# System Audit for Linux

## Overview
This program is designed for auditing and monitoring system activity on Linux. It tracks system calls made by a specified process and logs them along with relevant information such as user, timestamp, and syscall details.

## Features
- Tracks system calls of a specified process.
- Logs syscall events with user information and timestamp.
- Appends logs to a file for auditing purposes.
- Provides usage instructions for easy execution.

## Prerequisites
- Linux operating system.
- C++ compiler supporting C++11 or later.

## Installation
1. Clone the repository: `git clone https://github.com/your/repository.git`
2. Compile the code: `g++ -o audit audit.cpp`
3. Run the executable with sudo privileges: `sudo ./audit <pid>` or `sudo ./audit \`pidof <process name>\``

## Usage
- Specify the process ID (PID) of the target process as a command-line argument.
- View audit logs in the `audit.log` file located in the same directory.

## Example
```bash
sudo ./audit 1234
```

## Logging
The program logs syscall events to the audit.log file. Each log entry includes:

- PID of the target process.
- Timestamp of the syscall event.
- User executing the syscall.
- Syscall code and details.