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
#include <iomanip> 
#include <sstream>  
#include <ctime>      
#include <algorithm> 
 
#define windows_time_to_unix_epoch(x) ((x) - 116444736000000000LL) / 10000000LL
// The above macro converts Windows FILETIME to Unix epoch time in seconds.
// I explain more about why this is needed below and in the README. 
// TLDR: FILETIME is an arbitrary number and we need math to convert it into something useful.
// I took this macro from https://stackoverflow.com/a/74650247
// Thanks!

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
// The above function checks if Virtual Terminal mode is enabled. 
// This means that the terminal can render things like ANSI escape codes for colors and stuff.
// If we tried spitting out escape codes in a terminal that doesn't support it, it would look like unreadable garbage,
// and that's probably not very pleasant to the user. This is very rare and I have yet to encounter a terminal that doesn't support it, 
// but I'm sure there's someone out there using some ANCIENT old version of Windows that doesn't support it, and we want to support this for all versions.
// Who knows, I might even test this on windows XP hahahahahaha... 

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
// Process uptime helper
// Reference: https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getprocesstimes
// While this does indeed give you the time since the process was created,
// it actually returns a raw FILETIME, meaning it is an unsigned 64-bit integer that
// shows the amount of 100-nanosecond intervals since January 1, 1601 (UTC), which is just straight up not readable, and
// in my opinion INSANELY arbritrary, but I guess Microsoft is Microsoft...
// In short, we need to do some more math on this.

std::string GetReadableFileTime(DWORD pid) {
    ULONGLONG creationTime = GetProcessCreationTime(pid);
    if (creationTime == 0) return "N/A";
    time_t unixTime = windows_time_to_unix_epoch(creationTime);
    // Here's the macro we defined earlier! Now we finally have something useful to work with.
    time_t now = std::time(nullptr);
    double diffSeconds = std::difftime(now, unixTime);

     
    std::string ago;
    if (diffSeconds < 60) ago = std::to_string((int)diffSeconds) + " seconds ago";
    else if (diffSeconds < 3600) ago = std::to_string((int)diffSeconds / 60) + " minutes ago";
    else if (diffSeconds < 86400) ago = std::to_string((int)diffSeconds / 3600) + " hours ago";
    else ago = std::to_string((int)diffSeconds / 86400) + " days ago";

     
    std::tm bt{};
    localtime_s(&bt, &unixTime);

    std::ostringstream oss;
    oss << ago << " (" << std::put_time(&bt, "%a %Y-%m-%d %H:%M:%S %z") << ")";

    // All this shenanginanny stuff we do with the timestamp is to make it look just like witr's output, which I quote from the README in that repo:
    // Started     : 2 days ago (Mon 2025-02-02 11:42:10 +05:30)

    return oss.str();
}


void PrintAncestry(DWORD pid) {

/*
~~~~~~~~~~~~~TODO: This tree is flipped. The output should be like this, as shown in the original witr:
systemd (pid 1)
  └─ PM2 v5.3.1: God (pid 1481580)
    └─ python (pid 1482060)

UPDATE: This is done now!!

*/

    
    

    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32);
    DWORD parentPid = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return;
    DWORD targetpid = pid; // the function already passes pid into us, but 
                          // just to be safe that pid doesn't get overwritten in the loop below
    std::string exeName = "Unknown/Dead Process";
    std::vector<std::string> exeNames;
    std::vector<ULONGLONG> exeTimes; // sorry for the crap code but idk how to make multidimensional arrays yet 😭😭😭
    std::vector<DWORD> pidNames;     // hopefully the compiler can fix it
    std::vector<DWORD> parentPids;
    bool found = false;
    while (pid != 0 && pid != 4) {
    found = false;
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == pid) {
                // Without comments, this literally looks like alien gibberish so lemme explain
              
                ULONGLONG creationTime = GetProcessCreationTime(pid); // this stores the creation time of the CURRENT pid (not parent)
                exeTimes.emplace_back(creationTime); // immediately stores the above to the list
                exeName = WideToString(pe32.szExeFile); //this stores the NAME of the current pid, converted to something that the terminal won't choke and die on
                exeNames.emplace_back(exeName); // this adds the above to the name list
                pidNames.emplace_back(pid); // this adds the current pid (no need to store in var as already passed into if)
                
                parentPid = pe32.th32ParentProcessID; // this gets the pid of the PARENT pid (if there hopefully is one)
                parentPids.emplace_back(pe32.th32ParentProcessID); // adds above to list
                ULONGLONG parentTime = GetProcessCreationTime(parentPid); // this gets the creation time of that one

                if (parentPid == 0 || parentPid == 4 || parentTime == 0 || parentTime >= creationTime) {
                    // we can't be sure if the parent actually exists and windows isn't lying to us,
                    // so always double check
                        pid = 0; 
                } else {

                    pid = parentPid;
                }
                found = true;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));

    }
     
    if (!found) break;
    }
    // we're close... but not done yet. we need to find the CHILDREN of the process now. 
    // We can create another loop, but this time going downwards, checking if a process
    // tells us that our target pid is it's parent. This time, we don't have to worry about
    // Checking if the parent is alive, because, well, since the target IS the parent, 
    // it must be alive.
    int children = 0; // i wonder what would happen if you could set an emoji as var name
    if (Process32First(hSnapshot, &pe32)) {
        do {
            
               // this time, our target pid is already stored at the very top of our list.
               // this means we don't have to add target pid stuff.
               // TODO: (for future optimization) we should probably move this before the 
               // the previous loop, since emplacing to the front requires shifting the entire list
               // and therefore is inefficient, robbing us of a couple milliseconds of precious cpu time :(

                if (pe32.th32ParentProcessID == targetpid) {
                    exeName = WideToString(pe32.szExeFile); // this stores the name of our pid we're looking at in a var
                    exeNames.emplace(exeNames.begin(), exeName); // this adds this to the front of the list
                    // in this case, we are adding stuff to the front of the list, since we're looking at children
                    // you might've noticed this doesn't have an emplace_front() like emplace_back() since 
                    // it's inefficient and the creators of the vector lib didn't do it
                    pidNames.emplace(pidNames.begin(), pe32.th32ProcessID);
                    ULONGLONG childTime = GetProcessCreationTime(pe32.th32ProcessID);
                    exeTimes.emplace(exeTimes.begin(), childTime); // we don't even use this but we need to keep all the vectors the same length
                    parentPids.emplace(parentPids.begin(), pe32.th32ProcessID); // just fill it up, we aren't using it
                    children++; // keeps track of how many children we have (that sounds wrong when you say it)

                }
                

                
            
        } while (Process32Next(hSnapshot, &pe32));

    }

    
CloseHandle(hSnapshot); // we're only closing the handle until we finish messing with the snapshot
    //phew thankfully we're done with that mess
    // now we need to reverse all the vector lists we made so
    // that the ancestry tree is correctly diisplayed from root to children like witr
    // in c++20 there is a new way to reverse called ranges or smth but i won't use that
    std::reverse(exeNames.begin(), exeNames.end()); 
    std::reverse(exeTimes.begin(), exeTimes.end());
    std::reverse(pidNames.begin(), pidNames.end());  
    std::reverse(parentPids.begin(), parentPids.end());  
    // now get the size of one of the lists to know how many we got (they should all be the same length)
    size_t nameSize = exeNames.size();

    for (size_t i = 0; i < nameSize; i++ ){ // size_t is an unsigned integer designed to be ridiculously big to handle monstrosities,
                                          // idk just in case some psycho has a gazillion nested procs
    
        // surprise we have nested for loops 
        for (size_t j = 0; j < i; j++) {
            if (i > pidNames.size() - children) {
                std::cout << "  "; // this adds indentation
            }

        
        if (i > 0) {
        if (IsVirtualTerminalModeEnabled()) {
        std::cout << "\033[35m└─\033[0m ";  // it's the little thingy thing └─ unicode from witr 
        } else {
        std::cout << "└─ ";  
        }
        }   // peak indentation
        if (IsVirtualTerminalModeEnabled()) {
            if (targetpid == pidNames[i])  {
                std::cout << "\033[1;32m" << exeNames[i] << " (PID " << pidNames[i] << ")" << "\033[0m" << std::endl;
            } else {
               std::cout   << exeNames[i] << " (PID " << pidNames[i] << ")"  << std::endl;
            } 
            }else {
                if (targetpid == pidNames[i])  {
                 std::cout   << exeNames[i] << " (PID " << pidNames[i] << ") ⬅"  << std::endl;

                // since we don't have virtual terminal colors to highlight it,
                // we're gonna use arrows
                }
                else {
                    std::cout   << exeNames[i] << " (PID " << pidNames[i] << ")"  << std::endl;
                }

                
            

        
        }

    }
    
   if (nameSize > 0) {
    DWORD lastParentPid = parentPids.back();
    ULONGLONG lastParentTime = GetProcessCreationTime(lastParentPid);
    ULONGLONG lastChildTime = exeTimes.back();
    
    if (lastParentPid != 0 && lastParentPid != 4 && 
        (lastParentTime == 0 || lastParentTime >= lastChildTime)) {
        for (size_t j = 0; j < nameSize; j++) {
            
            std::cout << "  ";
            
            }
        }
        std::cout << "└─ [Parent Process Exited]" << std::endl;
    }
} 
    }

 



void PIDinspect(DWORD pid) { // ooh guys look i'm in the void
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    // The above little handle opener is currently a somwehat "agressive" flag, since it
    // Requests read access directly to the process' actual memory. This can get us rejected if called
    // on a very high privilege process, such as lsass.exe This means that we can't read the memory
    // even WITH SeDebugPrivilege enabled. Windows doesn't want ya sneaking around in that!
    // So for that reason, I've added  a fallback that only requests limited memory access, 
    // which should hopefully allow us to read some informatoin about hte process
    if (!hProcess && GetLastError() == ERROR_ACCESS_DENIED) {
        // This lets us know if the error was denied specifically for access reasons. THis will initiate our little fallback.
         hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid); // poor little guy getting limited of his full power
         // This has been tested and it does let us get info about lsass.exe and even System! Woohoo!
    }
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

     
    char exePath[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
    if (QueryFullProcessImageNameA(hProcess, 0, exePath, &size)) {
        std::cout << "Executable Path: " << exePath << std::endl;
    } else {
        std::cerr << "Error: Unable to query executable path. Error code: " 
                  << GetLastError() 
                  << "\n Maybe Access is Denied or the process is living in RAM." << std::endl;
    }

     
     // TODO: add color text
     
    std::cout << "\nProcess Ancestry:\n";
    PrintAncestry(pid);

    std::cout << "\nStarted: " << GetReadableFileTime(pid) << std::endl; 
    /*
    TODO: 
    This definitely needs a lot more details to be complete like witr. Unfortunately, windows needs even more shenanigans and a whole
    lotta more code and admin access to get the same details. I will explain this some other day.

    This is the output from witr for reference:
    Target      : node

    Process     : node (pid 14233)
    User        : pm2
    Command     : node index.js
    Started     : 2 days ago (Mon 2025-02-02 11:42:10 +05:30)
    Restarts    : 1

    Why It Exists :
    systemd (pid 1) → pm2 (pid 5034) → node (pid 14233)

    Source      : pm2

    Working Dir : /opt/apps/expense-manager
    Git Repo    : expense-manager (main)
    Listening   : 127.0.0.1:5001
    */

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
    SetConsoleOutputCP(CP_UTF8);
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
