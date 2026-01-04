// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 supervoidcoder
// This file is part of win-witr.

#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <optional>
#include <chrono>
#include <thread>
#include <filesystem>

#pragma comment(lib, "advapi32.lib")  // For Security/Registry (Elevation check)
#pragma comment(lib, "iphlpapi.lib")  // For Network stuff (Port to PID mapping)
#pragma comment(lib, "ws2_32.lib")    // For Winsock (Networking)
#pragma comment(lib, "shell32.lib")  // For ShellExecute (Elevation)

/* 

This is a Windows version of the tool witr, which is a utility for finding details about specific processes.
The original witr project is made by Pranshu Parmar (@pranshuparmar) and is available at: https://github.com/pranshuparmar/witr
This Windows adaptation is a separate project, created in C++, unlike the original which is in Go.
*/



// Function to check if Virtual Terminal Processing is enabled
// This will help in determining if ANSI escape codes can be used for colored output and other terminal features.
// This is to avoid spitting out raw escape codes in terminals that do not support them, like old versions of Windows CMD.
// Reference: https://learn.microsoft.com/en-us/windows/console/console-virtual-terminal-sequences



/* 
----------
Global variables
This is kept as a bunch of strings to be easier to call than a dictionary, map, class, list, etc. 
Less words to type ;)
*/
std::string forkAuthor = ""; // if this is a fork of this project, put your name here! Please be nice and leave my name too :)
std::string version = "v0.1.0"; // Version of this Windows port


bool IsVirtualTerminalModeEnabled() {
    HANDLE hOut = GetStdHandle(STD_OUTPUT_HANDLE);
    if (hOut == INVALID_HANDLE_VALUE) return false;

    DWORD dwMode = 0;
    if (!GetConsoleMode(hOut, &dwMode)) return false;

    return (dwMode & ENABLE_VIRTUAL_TERMINAL_PROCESSING) != 0;
}

bool EnableDebugPrivilege() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tp;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
        return false;
    }

    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        CloseHandle(hToken);
        return false;
    }

    CloseHandle(hToken);
    return GetLastError() == ERROR_SUCCESS;
}

BOOL IsProcessElevated()
{
	BOOL fIsElevated = FALSE;
	HANDLE hToken = NULL;
	TOKEN_ELEVATION elevation;
	DWORD dwSize;

	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken))
	{

		std::cerr << "\nFailed to get Process Token. Error code: " << GetLastError() << std::endl; 
		goto Cleanup;  // if Failed, we treat as False
	}


	if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
	{	
		std::cerr << "\nFailed to get Token Information. Error code: " << GetLastError() << std::endl;
		goto Cleanup;// if Failed, we treat as False
	}

	fIsElevated = elevation.TokenIsElevated;

Cleanup:
	if (hToken)
	{
		CloseHandle(hToken);
		hToken = NULL;
	}
    if (fIsElevated) {
        EnableDebugPrivilege(); // try to enable debug privilege if we're elevated
    } 
	return fIsElevated; 
}
// The above function is taken from https://vimalshekar.github.io/codesamples/Checking-If-Admin , modified to use C++ 
// style I/O instead of printf like the original code.
// Thanks!

std::string WideToString(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], size_needed, NULL, NULL);
    return strTo;
}
// The above stupid function is to convert wide strings (used by Windows API) to normal strings (used by C++ standard library) because cout chokes on wide strings.

// Helper to get creation time of a PID
ULONGLONG GetProcessCreationTime(DWORD pid) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (!hProcess) return 0;

    FILETIME createTime, exitTime, kernelTime, userTime;
    if (GetProcessTimes(hProcess, &createTime, &exitTime, &kernelTime, &userTime)) {
        ULARGE_INTEGER li;
        li.LowPart = createTime.dwLowDateTime;
        li.HighPart = createTime.dwHighDateTime;
        CloseHandle(hProcess);
        return li.QuadPart;
    }
    CloseHandle(hProcess);
    return 0;
}

void PrintAncestry(DWORD pid, int depth = 0) {
    if (pid == 0 || pid == 4) return;

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;

    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32);
    DWORD parentPid = 0;
    std::string exeName = "Unknown/Dead Process";
    bool found = false;

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                parentPid = pe32.th32ParentProcessID;
                exeName = WideToString(pe32.szExeFile);
                found = true;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);

    for (int i = 0; i < depth; ++i) std::cout << "  ";
    std::cout << exeName << " (PID " << pid << ")" << std::endl;

    if (found && parentPid != 0 && parentPid != pid) {
        // VERIFICATION STEP:
        ULONGLONG childTime = GetProcessCreationTime(pid);
        ULONGLONG parentTime = GetProcessCreationTime(parentPid);

        // If parentTime is 0, the parent is dead.
        // If parentTime > childTime, the parent is an impostor (recycled PID).
        if (parentTime != 0 && parentTime < childTime) {
            PrintAncestry(parentPid, depth + 1);
        } else {
            for (int i = 0; i < depth + 1; ++i) std::cout << "  ";
            std::cout << "[Parent Process Exited]" << std::endl;
        }
    }
}



void PIDinspect(DWORD pid) { // ooh guys look i'm in the void
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (!hProcess) {
        if (IsVirtualTerminalModeEnabled()) {
            std::cerr << "\033[1;31mError:\033[0m Could not open process with PID " 
                      << pid << ". Error code: " << GetLastError() 
                      << "\nMaybe it doesn't exist or access is denied." << std::endl;
        } else {
            std::cerr << "Error: Could not open process with PID " 
                      << pid << ". Error code: " << GetLastError() 
                      << "\nMaybe it doesn't exist or access is denied." << std::endl;
        }
        return;
    }

    // Query executable path
    char exePath[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameA(hProcess, 0, exePath, &size)) {
        std::cout << "Executable Path: " << exePath << std::endl;
    } else {
        std::cerr << "Error: Unable to query executable path. Error code: " 
                  << GetLastError() 
                  << "\n Maybe Access is Denied or the process is living in RAM." << std::endl;
    }

    // Print ancestry chain
    std::cout << "\nProcess Ancestry:\n";
    PrintAncestry(pid);

    CloseHandle(hProcess);
}

int findMyProc(const char *procname) {

  HANDLE hSnapshot;
  PROCESSENTRY32 pe;
  int pid = 0;
  BOOL hResult;

  // snapshot of all processes in the system
  hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (INVALID_HANDLE_VALUE == hSnapshot) return 0;

  // initializing size: needed for using Process32First
  pe.dwSize = sizeof(PROCESSENTRY32);

  // info about first process encountered in a system snapshot
  hResult = Process32First(hSnapshot, &pe);

  // retrieve information about the processes
  // and exit if unsuccessful
  while (hResult) {
    // if we find the process: return process ID
    if (strcmp(procname, WideToString(pe.szExeFile).c_str()) == 0) { 
      pid = pe.th32ProcessID;
      break;
    }
    hResult = Process32Next(hSnapshot, &pe);
  }

  // closes an open handle (CreateToolhelp32Snapshot)
  CloseHandle(hSnapshot);
  return pid;
}
// The above function is taken from https://cocomelonc.github.io/pentest/2021/09/29/findmyprocess.html , modified simply to use WideToString for the process name comparison among other things.
// Thanks!
 

int main(int argc, char* argv[]) {
    for (int i = 0; i < argc; ++i) {
        std::string arg = argv[i];

        
        if (i == 0 && argc > 1) {
            continue; 
        }
        
         
         

        if (argc == 1 || std::string(argv[1]) == "-h" || std::string(argv[1]) == "--help") {
            if (!forkAuthor.empty()) {
                std::cout << "\nwin-witr - Why is this running? Windows version by supervoidcoder. Fork by " << forkAuthor << std::endl;
            } else {
                std::cout << "\nwin-witr - Why is this running? Windows version by supervoidcoder." << std::endl;
            }
            
            if (IsVirtualTerminalModeEnabled()) {
                if (IsProcessElevated()) {
                    std::cout << "\033[1;32mRunning with elevated privileges (Admin).\033[0m" << std::endl;
                } else {
                    std::cout << "\033[1;91mNot running with elevated privileges. Some information may be inaccessible.\033[0m" << std::endl;
                }
                std::cout << "\033[1;32mUsage:\033[0m win-witr [options]" << std::endl;
                std::cout << "\033[1;32mOptions:\033[0m" << std::endl;
                std::cout << "  \033[1;33m-h, --help\033[0m       Show this help message and exit" << std::endl;
                std::cout << "  \033[1;33m-v, --version\033[0m    Show version information and exit" << std::endl;
                std::cout << "  \033[1;33m--port <port>\033[0m    Specify the port to check" << std::endl;
                std::cout << "  \033[1;33m--pid <pid>\033[0m      Specify the PID to check" << std::endl;
                std::cout << "  \033[1;33m <name>\033[0m          Specify the process name to check" << std::endl;
                 
            } else {
                if (IsProcessElevated()) {
                    std::cout << "Running with elevated privileges (Admin)." << std::endl;
                } else {
                    std::cout << "Not running with elevated privileges. Some information may be inaccessible." << std::endl;
                }
                std::cout << "Usage: win-witr [options]" << std::endl;
                std::cout << "Options:" << std::endl;
                std::cout << "  -h, --help       Show this help message and exit" << std::endl;
                std::cout << "  -v, --version    Show version information and exit" << std::endl;
                std::cout << "  --port <port>    Specify the port to check" << std::endl;
                std::cout << "  --pid <pid>      Specify the PID to check" << std::endl;
                std::cout << "   <name>          Specify the process name to check" << std::endl;
                

            }
            return 0; // exit after printing help because it might try to process -help as a process name otherwise
        }


        if (arg == "-v" || arg == "--version") {
            std::cout << "\nwin-witr " << version << std::endl;
            return 0;
        }

        if (arg == "--pid") {
            if (i + 1 < argc) {
                
                std::string pidStr = argv[i + 1]; // never increment the actual variable unless you're actually trying to find the next argument, otherwise 
                                                  // skipping arguments will happen and can crash if there is, in fact, no next argument.

                int pid = 0;    
                // make sure it's actually a number
               try { 
                      
                     
                     pid = std::stoi(pidStr);

                     
                     i++; 
                } catch (const std::invalid_argument& ia) {
                     if (IsVirtualTerminalModeEnabled()) {
                         std::cerr << "\033[1;31mError:\033[0m PID argument is not a valid number." << std::endl;
                     } else {
                         std::cerr << "Error: PID argument is not a valid number." << std::endl;
                     }
                     return 1; // someday we should probably have proper error codes instead of just 1 for everything
                            
                } catch (const std::out_of_range& oor) {
                     if (IsVirtualTerminalModeEnabled()) {
                         std::cerr << "\033[1;31mError:\033[0m PID argument is out of range." << std::endl;
                     } else {
                         std::cerr << "Error: PID argument is out of range." << std::endl;
                     }
                     return 1;
                }
                

                std::cout << "PID specified: " << pid << std::endl;
                PIDinspect(static_cast<DWORD>(pid));
            } else {
                if (IsVirtualTerminalModeEnabled()) { // ugh i have to do this EVERY SINGLE TIME
                    std::cerr << "\033[1;31mError:\033[0m --pid option requires an argument." << std::endl;
                } else {
                    std::cerr << "Error: --pid option requires an argument." << std::endl;
                }

                // writing c++ is shockingly uncomplicated


                return 1;
            }
            return 0;
        }
        // check for process name if no recognized flags
        else if (arg[0] != '-') { // if it doesn't start with -- or -
            std::string procName = arg;
            int pid = findMyProc(procName.c_str());
            if (pid != 0) {
                std::cout << "Process Name specified: " << procName << " (PID " << pid << ")" << std::endl;
                PIDinspect(static_cast<DWORD>(pid));
            } else {
                if (IsVirtualTerminalModeEnabled()) {
                    std::cerr << "\033[1;31mError:\033[0m Could not find process with name " << procName << "." << std::endl;
                } else {
                    std::cerr << "Error: Could not find process with name " << procName << "." << std::endl;
                }
            }
        }
    }
    return 0;
    
}
// I know, I'm gonna go all out with the Ifs statements...
// eh, I can optimize it later.
