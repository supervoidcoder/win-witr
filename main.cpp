// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2025 supervoidcoder
// This file is part of win-witr.


#define NO_STRICT
#include <windows.h>
#include <winternl.h>
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
#include <conio.h> 
#include <cassert>
#include <psapi.h>
#include <iphlpapi.h>

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


// i stole the following from google in totally NOT sketchy sites
// go to GetCommandLine function to see how these are used (and why)
typedef struct _UNICODE_STRING64 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG  Pad;
    ULONG64 Buffer;
} UNICODE_STRING64;

typedef struct _UNICODE_STRING32 {
    USHORT Length;
    USHORT MaximumLength;
    ULONG Buffer;
} UNICODE_STRING32;

typedef struct _PROCESS_BASIC_INFORMATION64 {
    ULONG64 Reserved1;
    ULONG64 PebBaseAddress;
    ULONG64 Reserved2[2];
    ULONG64 UniqueProcessId;
    ULONG64 Reserved3;
} PROCESS_BASIC_INFORMATION64;

typedef struct _RTL_USER_PROCESS_PARAMETERS64 {
    BYTE Reserved1[16];
    ULONG64 Reserved2[10];
    UNICODE_STRING64 ImagePathName;
    UNICODE_STRING64 CommandLine; // Offset 0x70
} RTL_USER_PROCESS_PARAMETERS64;

// --- Function Pointers for Undocumented NT Functions ---
typedef NTSTATUS (NTAPI *pNtQueryInformationProcess)(HANDLE, UINT, PVOID, ULONG, PULONG);
typedef NTSTATUS (NTAPI *pNtWow64ReadVirtualMemory64)(HANDLE, ULONG64, PVOID, ULONG64, PULONG64);
typedef NTSTATUS (NTAPI *pNtWow64QueryInformationProcess64)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

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
#define STRINGIZE2(x) #x
#define STRINGIZE(x) STRINGIZE2(x)
std::string version = []() {
#ifdef VERSION_NUMBER
    return std::string(STRINGIZE(VERSION_NUMBER));  // Release builds only
#else
    return std::string("dev-build");     // Local builds - no env var check
#endif
}();
thread_local std::string currentParentExe = ""; // to store the name of our own parent process for error hints
bool virtualTerminalEnabled = false; // cached result of virtual terminal check to avoid repeated function calls

std::string WideToString(const std::wstring& wstr);

void EnsureCurrentParentExe(HANDLE hSnapshot) {
    if (!currentParentExe.empty()) return;

    

    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32);

    DWORD currentProcessId = GetCurrentProcessId();
    DWORD parentPid = 0;

    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == currentProcessId) {
                parentPid = pe32.th32ParentProcessID;
                break;
            }
        } while (Process32Next(hSnapshot, &pe32));
    }

    if (parentPid != 0) {
        pe32.dwSize = sizeof(PROCESSENTRY32);
        if (Process32First(hSnapshot, &pe32)) {
            do {
                if (pe32.th32ProcessID == parentPid) {
                    currentParentExe = WideToString(pe32.szExeFile);
                    break;
                }
            } while (Process32Next(hSnapshot, &pe32));
        }
    }

   
}


bool IsVirtualTerminalModeEnabled() {
    if (GetEnvironmentVariableA("force_ansi", NULL, 0) > 0) {
        return true;
    }
    // i'll probably make force-ansi a flag later but eh
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



// Here, we will create an unordered map, essentially a lookup table filled with useful stuff like hints for specific errors
std::unordered_map<int, std::string> errorHints = {
    {5, "Access is denied."},
    {87, "The process or PID doesn't exist."},
    {31, "This error indicates a driver error, but in win-witr, it often means you are calling a pseudo-process, such as System, Registry, or other processes that only exist in RAM as a kernel process. It is often easy to tell them apart if they lack a .exe extension."}
    // So far, these are the only error codes I myself have encountered while using win-witr.   
    // Something funny about this tool is that the error descriptions in Windows documentation are sometimes
    // Completely unrelated to what the actual error means in the context of win-witr.
    // For example, ERROR_INVALID_PARAMETER (87) is described as "The parameter is incorrect.", but in win-witr,
    // it usually means that the process or PID you're trying to query doesn't exist.
    // Same for 31, which is described as "A device attached to the system is not functioning.", but in win-witr,
    // I've only gotten it when calling processes like System, Registry, etc.
    
    // If you want the full list of win32 error codes, you can find them here: https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-
    
};


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

ULONGLONG GetProcessCreationTime(DWORD pid, const std::unordered_map<DWORD, PROCESSENTRY32>& pidMap) {
    if (!pidMap.empty() && pidMap.find(pid) == pidMap.end()) return 0;
    return GetProcessCreationTime(pid);
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

std::string GetReadableFileTime(DWORD pid, const std::unordered_map<DWORD, PROCESSENTRY32>& pidMap) {
    ULONGLONG creationTime = GetProcessCreationTime(pid, pidMap);
    if (creationTime == 0) return "N/A";
    time_t unixTime = windows_time_to_unix_epoch(creationTime);
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
    return oss.str();
}

void PrintErrorHints(int errorCode, HANDLE hshot) {
    EnsureCurrentParentExe(hshot);
    // Use our little lookup table to give hints for specific errors
    if (errorHints.find(errorCode) != errorHints.end()) {
        if (virtualTerminalEnabled) {
            std::cerr << "\033[1;33mHint:\033[0m " << errorHints[errorCode] << std::endl;
        } else {
            std::cerr << "Hint: " << errorHints[errorCode] << std::endl;

        }
        // if it's 5 specifically, we can add an extra hint
        if (errorCode == 5) {
            if (currentParentExe == "powershell.exe" || currentParentExe == "pwsh.exe" || currentParentExe == "PowerShell.exe") {
                std::cerr << "Try reopening Powershell as Administrator and running win-witr again." << std::endl;
            } else if (currentParentExe == "cmd.exe") {
                std::cerr << "Try reopening Command Prompt as Administrator and running win-witr again." << std::endl;
            }
            else if (currentParentExe == "WindowsTerminal.exe") {
                std::cerr << "Try reopening Windows Terminal as Administrator and running win-witr again." << std::endl;
            } else if (currentParentExe == "explorer.exe") {
                std::cerr << "It seems you might be opening this as a shortcut with flags from Explorer. For best results, try running win-witr from an elevated Command Prompt or Powershell. " << std::endl;
                std::cout << "\nPress any key to exit...";
                _getch();
                // the process will automatically exit since if you open a terminal based script from explorer, the terminal will close immediately after execution is over
                // either way we want to give the user a chance to read the error message even if they did something as weird as this
                // it's crazy I even thought of this scenario lol

            } else if (currentParentExe == "wsl.exe" || currentParentExe == "wslhost.exe") {
                std::cerr << "Hah, you're running this in Windows Subsystem for Linux. Run wsl as Admin!" << std::endl;


            } else if (currentParentExe == "bash.exe") {
                std::cerr << "Uh, you're running this from Git Bash. Try running this program from an elevated Command Prompt or Powershell." << std::endl;
            }
                else {
                std::cerr << "Try reopening this program (or more likely, the shell you're running this in, currently " << currentParentExe << ") as Administrator and running win-witr again." << std::endl;
            }



        }


    }
}

std::optional<std::wstring> GetUserNameFromProcess(DWORD id)
{
     HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, id);
    

    if (!hProcess && GetLastError() == ERROR_ACCESS_DENIED) {
        hProcess = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, id); // cute fallback
	}
    std::wstring endUser = L"";
    std::wstring endDomain = L"";

    if (hProcess != NULL)
    {
        HANDLE  hToken = NULL;

        if (OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) // 2- OpenProcessToken
        {
            DWORD tokenSize = 0;
            if (!GetTokenInformation(hToken, TokenUser, nullptr, 0, &tokenSize) &&
                GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                CloseHandle(hToken);
                CloseHandle(hProcess);
                return {};
            }

            if (tokenSize > 0)
            {
                std::vector<BYTE> data(tokenSize);
                if (!GetTokenInformation(hToken, TokenUser, data.data(), tokenSize, &tokenSize)) {
                    CloseHandle(hToken);
                    CloseHandle(hProcess);
                    return {};
                }
                TOKEN_USER* pUser = reinterpret_cast<TOKEN_USER*>(data.data());
                PSID pSID = pUser->User.Sid;
                DWORD userSize = 0;
                DWORD domainSize = 0;
                SID_NAME_USE sidName;
                if (!LookupAccountSidW(nullptr, pSID, nullptr, &userSize, nullptr, &domainSize, &sidName) &&
                    GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
                    CloseHandle(hToken);
                    CloseHandle(hProcess);
                    return {};
                }
                std::wstring user(userSize, L'\0');
                std::wstring domain(domainSize, L'\0');
                if (!LookupAccountSidW(nullptr, pSID, user.data(), &userSize, domain.data(), &domainSize, &sidName)) {
                    CloseHandle(hToken);
                    CloseHandle(hProcess);
                    return {};
                }
                user.resize(userSize);
                domain.resize(domainSize);
                endUser = user;
                endDomain = domain;
            }
            

            CloseHandle(hToken);
        }

        CloseHandle(hProcess);

        if (endUser != L"")
            return endUser;
    }

    return {};
}
// I just straight up stole this function from Stack Overflow lol
// https://stackoverflow.com/questions/2686096/c-get-username-from-process
// Permalink: https://stackoverflow.com/a/73242956
// Thanks!

std::string GetProcessNameFromPid(DWORD pid, HANDLE snapshot) {
    

    PROCESSENTRY32 pe{};
    pe.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &pe)) {
        do {
            if (pe.th32ProcessID == pid) {
                
                return WideToString(pe.szExeFile);
            }
        } while (Process32Next(snapshot, &pe));
    }

    
    return "";
}

std::string GetCommandLine(HANDLE hproc) {
#ifdef _M_X64


BOOL isWow64 = FALSE;
if (!IsWow64Process(hproc, &isWow64)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:wow64checkfail)\033[0m";
    } else {
        return "Failed to Access (wwitr:wow64checkfail)";
    }
}
bool isWoW64 = isWow64; // this variable naming will surely not cause any problemes in the forseeable future

if (!isWoW64) {
 // we have to read the PEB, which is essentially the "header" of a process' RAM
 // so far this implementation only works with x64 --> x64 process
 // so it's wip

typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
if (!queryInfo) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:functionptrs)\033[0m";
    } else {
        return "Failed to Access (wwitr:functionptrs)";
    }
}
// this is a very sketchy line of code
// it calls NtQueryInformationProcess from internal kernel functions
// i would've saved myself all this pain if I just used the WMI wrapper
// but wmi has a reputation for being slow as heck
// thankfully, even though microslop claims this stuff is "undocumented", many generous
// red teamers and other people have created a quite sizable amount of docs
// so thank them, not me

PROCESS_BASIC_INFORMATION pbi;
if (queryInfo(hproc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {
    // all this code seems very C-style since most of the stuff like docs were thought for c
    // the code I'm basing this off manually creates a handle right here but we already created one
    // so the handle gets passed to this function and we don't need to clean up our handle just yet, just return
    // but we still should add a cout to see where it failed

    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:ntqueryfailed)\033[0m"; // failure
    } else {
        return "Failed to Access (wwitr:ntqueryfailed)"; // failure
    }
}

// the PEB for the cmd line stuff is somewhere in the PEB, called ProcessParamters 
// then from there we can read the CommandLine struct
// it's all a bunch of dang structs with pointers to other structs

PVOID procParamPtr = nullptr;
if (!ReadProcessMemory(hproc, (BYTE*)pbi.PebBaseAddress + 0x20, &procParamPtr, sizeof(PVOID), NULL)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:procParamPtrRead)\033[0m";
    } else {
        return "Failed to Access (wwitr:procParamPtrRead)";
    }
}

UNICODE_STRING cmdLStruct;
SIZE_T bytesRead2 = 0;
if (!ReadProcessMemory(hproc, (BYTE*)procParamPtr + 0x70, &cmdLStruct, sizeof(cmdLStruct), &bytesRead2)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:cmdLStructFail)\033[0m";
    } else {
        return "Failed to Access (wwitr:cmdLStructFail)";
    }
}

if (cmdLStruct.Length == 0 || (cmdLStruct.Length % sizeof(wchar_t)) != 0 || cmdLStruct.Length > 65534) {
    return "";
}

size_t wchar_count = cmdLStruct.Length / sizeof(wchar_t);
std::vector<wchar_t> buffer(wchar_count + 1, 0);
if (!ReadProcessMemory(hproc, cmdLStruct.Buffer, buffer.data(), cmdLStruct.Length, NULL))
{
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:bufferReadFail)\033[0m"; 
    } else {
        return "Failed to Access (wwitr:bufferReadFail)"; 
    }
}

std::wstring stringBuffer = buffer.data();
// we don't wanna return a wstring so let's convert it
return WideToString(stringBuffer);


} else {
    // haahhahahah reading wow64 from x64 is so funny waahahahah
    // what if we do the most logical thing and just put everything in a 
    // try catch... honestly I don't know what's all the hate with
    // it, the performance hit is negligible if there's no errors
    // and I think it's only slow in python
    auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!queryInfo) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:functionptrs)\033[0m";
        } else {
            return "Failed to Access (wwitr:functionptrs)";
        }
    }

    ULONG_PTR peb32Address = 0;
    NTSTATUS status = queryInfo(hproc, ProcessWow64Information, &peb32Address, sizeof(peb32Address), NULL);
    if (status != 0 || peb32Address == 0) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:ntqueryfailed)\033[0m";
        } else {
            return "Failed to Access (wwitr:ntqueryfailed)";
        }
    }

    ULONG procParamPtr32 = 0;
    if (!ReadProcessMemory(hproc, (BYTE*)peb32Address + 0x10, &procParamPtr32, sizeof(procParamPtr32), NULL)) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:procParamPtrRead)\033[0m";
        } else {
            return "Failed to Access (wwitr:procParamPtrRead)";
        }
    }

    UNICODE_STRING32 cmdLStruct32{};
    if (!ReadProcessMemory(hproc, (BYTE*)(ULONG_PTR)procParamPtr32 + 0x40, &cmdLStruct32, sizeof(cmdLStruct32), NULL)) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:cmdLStructFail)\033[0m";
        } else {
            return "Failed to Access (wwitr:cmdLStructFail)";
        }
    }

    if (cmdLStruct32.Length == 0 || (cmdLStruct32.Length % sizeof(wchar_t)) != 0 || cmdLStruct32.Length > 65534) {
        return "";
    }

    size_t wchar_count = cmdLStruct32.Length / sizeof(wchar_t);
    std::vector<wchar_t> buffer(wchar_count + 1, 0);
    if (!ReadProcessMemory(hproc, (PVOID)(ULONG_PTR)cmdLStruct32.Buffer, buffer.data(), cmdLStruct32.Length, NULL))
    {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:bufferReadFail)\033[0m";
        } else {
            return "Failed to Access (wwitr:bufferReadFail)";
        }
    }

    std::wstring stringBuffer = buffer.data();
    return WideToString(stringBuffer);
}
 #elif defined(_M_IX86) 
 // so yknow, this part is for 32 bit processes
 // but you can run 32 bit processes on 64 bit windows
 // how? 🤔 it's because of what's called WoW64 (Windows on Windows 64)
 // it's not really emulation (unlike Prism on Arm64) but more like a compatibility layer
 // x64 processors can already run x86 code natively since x64 is sorta an "extension" of x86
 // it has the same instruction set plus more instructions, as well as the ability to use more than 4GB of RAM 
 // (not just more, but basically infinite amounts of RAM theoretically)
 // so wow64 doesn't emulate the CPU, it just intercepts certain system calls and redirects them to 32 bit versions
 // stored as different dlls in SysWoW64 folder
 // This means that Windows is basically LYING to us if we are a 32 bit process running on 64 bit Windows
 // Windows will look us dead in the eye and say "Yup, you're running on a 32 bit windows!"
 // We can bypass this with this below function call
     BOOL areWeWoW64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &areWeWoW64); // check if WE are wow64
    if (!areWeWoW64) {
        // if we're not wow64, then we're genuinely 32 bit windows
        // we can run the same code as above but with 32 bit offsets
        typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
if (!queryInfo) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:functionptrs)\033[0m";
    } else {
        return "Failed to Access (wwitr:functionptrs)";
    }
}

PROCESS_BASIC_INFORMATION pbi;
if (queryInfo(hproc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {

    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:ntqueryfailed)\033[0m";
    } else {
        return "Failed to Access (wwitr:ntqueryfailed)";
    }
}

PVOID procParamPtr = nullptr;
//for wow64 processes, the offset is different
if (!ReadProcessMemory(hproc, (BYTE*)pbi.PebBaseAddress + 0x10, &procParamPtr, sizeof(PVOID), NULL)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:procParamPtrRead)\033[0m";
    } else {
        return "Failed to Access (wwitr:procParamPtrRead)";
    }
}

UNICODE_STRING cmdLStruct;
SIZE_T bytesRead2 = 0;
if (!ReadProcessMemory(hproc, (BYTE*)procParamPtr + 0x40, &cmdLStruct, sizeof(cmdLStruct), &bytesRead2)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:cmdLStructFail)\033[0m";
    } else {
        return "Failed to Access (wwitr:cmdLStructFail)";
    }
}

if (cmdLStruct.Length == 0 || (cmdLStruct.Length % sizeof(wchar_t)) != 0 || cmdLStruct.Length > 65534) {
    return "";
}

size_t wchar_count = cmdLStruct.Length / sizeof(wchar_t);
std::vector<wchar_t> buffer(wchar_count + 1, 0);
if (!ReadProcessMemory(hproc, cmdLStruct.Buffer, buffer.data(), cmdLStruct.Length, NULL))
{
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:bufferReadFail)\033[0m"; 
    } else {
        return "Failed to Access (wwitr:bufferReadFail)"; 
    }
}

std::wstring stringBuffer = buffer.data();
return WideToString(stringBuffer);
} else {
    // if we are wow64, then we are a 32 bit process running on 64 bit windows
    // so now we should check if the target process is wow64 too

    //⚠️🚨 indentation alert 
    // since literally like half this function and its different 
    // branches for compilation is copy pasted code,
    // my indents got mangled :(
    // and rn im too lazy to fix them so screw indentations 


    BOOL targetIsWow64 = FALSE;
    
    // if the target process is WoW64 too, then we can use the same code as above!
    // easy peasy

    IsWow64Process(hproc, &targetIsWow64);
    if (targetIsWow64) {

   typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
if (!queryInfo) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:functionptrs)\033[0m";
    } else {
        return "Failed to Access (wwitr:functionptrs)";
    }
}

PROCESS_BASIC_INFORMATION pbi;
if (queryInfo(hproc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {

    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:ntqueryfailed)\033[0m";
    } else {
        return "Failed to Access (wwitr:ntqueryfailed)";
    }
}

PVOID procParamPtr = nullptr;
//for wow64 processes, the offset is different
if (!ReadProcessMemory(hproc, (BYTE*)pbi.PebBaseAddress + 0x10, &procParamPtr, sizeof(PVOID), NULL)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:procParamPtrRead)\033[0m";
    } else {
        return "Failed to Access (wwitr:procParamPtrRead)";
    }
}

UNICODE_STRING cmdLStruct;
SIZE_T bytesRead2 = 0;
if (!ReadProcessMemory(hproc, (BYTE*)procParamPtr + 0x40, &cmdLStruct, sizeof(cmdLStruct), &bytesRead2)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:cmdLStructFail)\033[0m";
    } else {
        return "Failed to Access (wwitr:cmdLStructFail)";
    }
}

if (cmdLStruct.Length == 0 || (cmdLStruct.Length % sizeof(wchar_t)) != 0 || cmdLStruct.Length > 65534) {
    return "";
}

size_t wchar_count = cmdLStruct.Length / sizeof(wchar_t);
std::vector<wchar_t> buffer(wchar_count + 1, 0);
if (!ReadProcessMemory(hproc, cmdLStruct.Buffer, buffer.data(), cmdLStruct.Length, NULL))
{
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:bufferReadFail)\033[0m"; 
    } else {
        return "Failed to Access (wwitr:bufferReadFail)"; 
    }
}

std::wstring stringBuffer = buffer.data();
return WideToString(stringBuffer);

    } else {
        // if the target process is NOT WoW64, that means
        // we're a 32 bit process trying to read a 64 bit process
        // which we will support
        // but why??? 😭😭😭✌️
        // why would people do this??? if you have a x64 OS just download the x64 version of win-witr???

        // that's right, I did this to MYSELF!!

        
        // these are the least sketchiest links bro trust
        // https://guidedhacking.com/threads/how-to-read-x64-memory-from-x86-using-ntwow64readvirtualmemory64.13789/
        // https://stackoverflow.com/questions/7446887/get-command-line-string-of-64-bit-process-from-32-bit-process#:~:text=%23include%20%22stdafx.h%22,=%20si.wProcessorArchitecture%20==%20PROCESSOR_ARCHITECTURE_AMD64%20?
        // thanks google!!! 
        
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        auto queryInfo64 = (pNtWow64QueryInformationProcess64)GetProcAddress(ntdll, "NtWow64QueryInformationProcess64");
        auto readMem64 = (pNtWow64ReadVirtualMemory64)GetProcAddress(ntdll, "NtWow64ReadVirtualMemory64");

        if (!queryInfo64 || !readMem64) {
            if (virtualTerminalEnabled) {
                return "\033[31mFailed to Access (wwitr:functionptrs)\033[0m";
            } else {
                return "Failed to Access (wwitr:functionptrs)";
            }
        }

        HANDLE targetHandle = hproc;
        HANDLE openedHandle = NULL;
        DWORD targetPid = 0;
        if (hproc != NULL) {
            targetPid = GetProcessId(hproc);
        }
        if (targetPid != 0) {
            openedHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetPid);
            if (openedHandle) targetHandle = openedHandle;
        }

        PROCESS_BASIC_INFORMATION64 pbi64{};
        ULONG returnLen = 0;
        NTSTATUS status = queryInfo64(targetHandle, ProcessBasicInformation, &pbi64, sizeof(pbi64), &returnLen);
        ULONG64 peb64Address = pbi64.PebBaseAddress;
        if (status != 0 || peb64Address == 0) {
            if (openedHandle) CloseHandle(openedHandle);
            if (virtualTerminalEnabled) {
                return "\033[31mFailed to Access (wwitr:ntqueryfailed)\033[0m";
            } else {
                return "Failed to Access (wwitr:ntqueryfailed)";
            }
        }

        ULONG64 procParamPtr64 = 0;
        status = readMem64(targetHandle, peb64Address + 0x20, &procParamPtr64, sizeof(procParamPtr64), NULL);
        if (status != 0) {
            if (openedHandle) CloseHandle(openedHandle);
            if (virtualTerminalEnabled) {
                return "\033[31mFailed to Access (wwitr:procParamPtrRead)\033[0m";
            } else {
                return "Failed to Access (wwitr:procParamPtrRead)";
            }
        }

        UNICODE_STRING64 cmdLStruct64;
        status = readMem64(targetHandle, procParamPtr64 + 0x70, &cmdLStruct64, sizeof(cmdLStruct64), NULL);
        if (status != 0) {
            if (openedHandle) CloseHandle(openedHandle);
            if (virtualTerminalEnabled) {
                return "\033[31mFailed to Access (wwitr:cmdLStructFail)\033[0m";
            } else {
                return "Failed to Access (wwitr:cmdLStructFail)";
            }
        }

        if (cmdLStruct64.Length == 0 || (cmdLStruct64.Length % sizeof(wchar_t)) != 0 || cmdLStruct64.Length > 65534) {
            if (openedHandle) CloseHandle(openedHandle);
            return "";
        }

        size_t wchar_count = cmdLStruct64.Length / sizeof(wchar_t);
        std::vector<wchar_t> buffer(wchar_count + 1, 0);
        status = readMem64(targetHandle, cmdLStruct64.Buffer, buffer.data(), cmdLStruct64.Length, NULL);
        if (status != 0) {
            if (openedHandle) CloseHandle(openedHandle);
            if (virtualTerminalEnabled) {
                return "\033[31mFailed to Access (wwitr:bufferReadFail)\033[0m";
            } else {
                return "Failed to Access (wwitr:bufferReadFail)";
            }
        }

        if (openedHandle) CloseHandle(openedHandle);
        std::wstring wstr(buffer.data());
        return WideToString(wstr);
    

        
    }

}
 #elif defined(_M_ARM64) 


// this is just the same code apparently
//idk i don't use no surface laptops
BOOL isWow64 = FALSE;
if (!IsWow64Process(hproc, &isWow64)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:wow64checkfail)\033[0m";
    } else {
        return "Failed to Access (wwitr:wow64checkfail)";
    }
}
bool isWoW64 = isWow64;

if (!isWoW64) {

typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

if (!queryInfo) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:functionptrs)\033[0m";
    } else {
        return "Failed to Access (wwitr:functionptrs)";
    }
}

PROCESS_BASIC_INFORMATION pbi;
if (queryInfo(hproc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {

    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:ntqueryfailed)\033[0m";
    } else {
        return "Failed to Access (wwitr:ntqueryfailed)";
    }
}

PVOID procParamPtr = nullptr;
if (!ReadProcessMemory(hproc, (BYTE*)pbi.PebBaseAddress + 0x20, &procParamPtr, sizeof(PVOID), NULL)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:procParamPtrRead)\033[0m";
    } else {
        return "Failed to Access (wwitr:procParamPtrRead)";
    }
}

UNICODE_STRING cmdLStruct;
SIZE_T bytesRead2 = 0;
if (!ReadProcessMemory(hproc, (BYTE*)procParamPtr + 0x70, &cmdLStruct, sizeof(cmdLStruct), &bytesRead2)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:cmdLStructFail)\033[0m";
    } else {
        return "Failed to Access (wwitr:cmdLStructFail)";
    }
}

if (cmdLStruct.Length == 0 || (cmdLStruct.Length % sizeof(wchar_t)) != 0 || cmdLStruct.Length > 65534) {
    return "";
}

size_t wchar_count = cmdLStruct.Length / sizeof(wchar_t);
std::vector<wchar_t> buffer(wchar_count + 1, 0);
if (!ReadProcessMemory(hproc, cmdLStruct.Buffer, buffer.data(), cmdLStruct.Length, NULL))
{
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:bufferReadFail)\033[0m"; 
    } else {
        return "Failed to Access (wwitr:bufferReadFail)"; 
    }
}

std::wstring stringBuffer = buffer.data();
return WideToString(stringBuffer);


} else {
    // no clue if this works

    auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!queryInfo) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:functionptrs)\033[0m";
        } else {
            return "Failed to Access (wwitr:functionptrs)";
        }
    }

    ULONG_PTR peb32Address = 0;
    NTSTATUS status = queryInfo(hproc, ProcessWow64Information, &peb32Address, sizeof(peb32Address), NULL);
    if (status != 0 || peb32Address == 0) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:ntqueryfailed)\033[0m";
        } else {
            return "Failed to Access (wwitr:ntqueryfailed)";
        }
    }

    ULONG procParamPtr32 = 0;
    if (!ReadProcessMemory(hproc, (BYTE*)peb32Address + 0x10, &procParamPtr32, sizeof(procParamPtr32), NULL)) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:procParamPtrRead)\033[0m";
        } else {
            return "Failed to Access (wwitr:procParamPtrRead)";
        }
    }

    UNICODE_STRING32 cmdLStruct32{};
    if (!ReadProcessMemory(hproc, (BYTE*)(ULONG_PTR)procParamPtr32 + 0x40, &cmdLStruct32, sizeof(cmdLStruct32), NULL)) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:cmdLStructFail)\033[0m";
        } else {
            return "Failed to Access (wwitr:cmdLStructFail)";
        }
    }

    if (cmdLStruct32.Length == 0 || (cmdLStruct32.Length % sizeof(wchar_t)) != 0 || cmdLStruct32.Length > 65534) {
        return "";
    }

    size_t wchar_count = cmdLStruct32.Length / sizeof(wchar_t);
    std::vector<wchar_t> buffer(wchar_count + 1, 0);
    if (!ReadProcessMemory(hproc, (PVOID)(ULONG_PTR)cmdLStruct32.Buffer, buffer.data(), cmdLStruct32.Length, NULL))
    {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:bufferReadFail)\033[0m";
        } else {
            return "Failed to Access (wwitr:bufferReadFail)";
        }
    }

    std::wstring stringBuffer = buffer.data();
    return WideToString(stringBuffer);
}
#else 
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:unknownarch)\033[0m";
    } else {
        return "Failed to Access (wwitr:unknownarch)";
    }
#endif
}

/* oooooooooooooooooooooooooooooooooooooooooooooooohhhhhhhh
big giant block comment to let me know when the massive getcommand line function ends and the get working dir starts
|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
676767676767676767676767676767676767
|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||
|||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||*/

std::string GetWorkingDir(HANDLE hproc) {
#ifdef _M_X64


BOOL isWow64 = FALSE;
if (!IsWow64Process(hproc, &isWow64)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:wow64checkfail)\033[0m";
    } else {
        return "Failed to Access (wwitr:wow64checkfail)";
    }
}
bool isWoW64 = isWow64;

if (!isWoW64) {

typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
if (!queryInfo) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:functionptrs)\033[0m";
    } else {
        return "Failed to Access (wwitr:functionptrs)";
    }
}

PROCESS_BASIC_INFORMATION pbi;
if (queryInfo(hproc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {

    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:ntqueryfailed)\033[0m";
    } else {
        return "Failed to Access (wwitr:ntqueryfailed)";
    }
}

PVOID procParamPtr = nullptr;
if (!ReadProcessMemory(hproc, (BYTE*)pbi.PebBaseAddress + 0x20, &procParamPtr, sizeof(PVOID), NULL)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:procParamPtrRead)\033[0m";
    } else {
        return "Failed to Access (wwitr:procParamPtrRead)";
    }
}

UNICODE_STRING cmdLStruct;
SIZE_T bytesRead2 = 0;
if (!ReadProcessMemory(hproc, (BYTE*)procParamPtr + 0x38, &cmdLStruct, sizeof(cmdLStruct), &bytesRead2)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:cmdLStructFail)\033[0m";
    } else {
        return "Failed to Access (wwitr:cmdLStructFail)";
    }
}

if (cmdLStruct.Length == 0 || (cmdLStruct.Length % sizeof(wchar_t)) != 0 || cmdLStruct.Length > 65534) {
    return "";
}

size_t wchar_count = cmdLStruct.Length / sizeof(wchar_t);
std::vector<wchar_t> buffer(wchar_count + 1, 0);
if (!ReadProcessMemory(hproc, cmdLStruct.Buffer, buffer.data(), cmdLStruct.Length, NULL))
{
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:bufferReadFail)\033[0m"; 
    } else {
        return "Failed to Access (wwitr:bufferReadFail)"; 
    }
}

std::wstring stringBuffer = buffer.data();
return WideToString(stringBuffer);


} else {
    auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!queryInfo) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:functionptrs)\033[0m";
        } else {
            return "Failed to Access (wwitr:functionptrs)";
        }
    }

    ULONG_PTR peb32Address = 0;
    NTSTATUS status = queryInfo(hproc, ProcessWow64Information, &peb32Address, sizeof(peb32Address), NULL);
    if (status != 0 || peb32Address == 0) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:ntqueryfailed)\033[0m";
        } else {
            return "Failed to Access (wwitr:ntqueryfailed)";
        }
    }

    ULONG procParamPtr32 = 0;
    if (!ReadProcessMemory(hproc, (BYTE*)peb32Address + 0x10, &procParamPtr32, sizeof(procParamPtr32), NULL)) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:procParamPtrRead)\033[0m";
        } else {
            return "Failed to Access (wwitr:procParamPtrRead)";
        }
    }

    UNICODE_STRING32 cmdLStruct32{};
    if (!ReadProcessMemory(hproc, (BYTE*)(ULONG_PTR)procParamPtr32 + 0x24, &cmdLStruct32, sizeof(cmdLStruct32), NULL)) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:cmdLStructFail)\033[0m";
        } else {
            return "Failed to Access (wwitr:cmdLStructFail)";
        }
    }

    if (cmdLStruct32.Length == 0 || (cmdLStruct32.Length % sizeof(wchar_t)) != 0 || cmdLStruct32.Length > 65534) {
        return "";
    }

    size_t wchar_count = cmdLStruct32.Length / sizeof(wchar_t);
    std::vector<wchar_t> buffer(wchar_count + 1, 0);
    if (!ReadProcessMemory(hproc, (PVOID)(ULONG_PTR)cmdLStruct32.Buffer, buffer.data(), cmdLStruct32.Length, NULL))
    {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:bufferReadFail)\033[0m";
        } else {
            return "Failed to Access (wwitr:bufferReadFail)";
        }
    }

    std::wstring stringBuffer = buffer.data();
    return WideToString(stringBuffer);
}
 #elif defined(_M_IX86) 
     BOOL areWeWoW64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &areWeWoW64);
    if (!areWeWoW64) {
        typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
if (!queryInfo) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:functionptrs)\033[0m";
    } else {
        return "Failed to Access (wwitr:functionptrs)";
    }
}

PROCESS_BASIC_INFORMATION pbi;
if (queryInfo(hproc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {

    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:ntqueryfailed)\033[0m";
    } else {
        return "Failed to Access (wwitr:ntqueryfailed)";
    }
}

PVOID procParamPtr = nullptr;
if (!ReadProcessMemory(hproc, (BYTE*)pbi.PebBaseAddress + 0x10, &procParamPtr, sizeof(PVOID), NULL)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:procParamPtrRead)\033[0m";
    } else {
        return "Failed to Access (wwitr:procParamPtrRead)";
    }
}

UNICODE_STRING cmdLStruct;
SIZE_T bytesRead2 = 0;
if (!ReadProcessMemory(hproc, (BYTE*)procParamPtr + 0x24, &cmdLStruct, sizeof(cmdLStruct), &bytesRead2)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:cmdLStructFail)\033[0m";
    } else {
        return "Failed to Access (wwitr:cmdLStructFail)";
    }
}

if (cmdLStruct.Length == 0 || (cmdLStruct.Length % sizeof(wchar_t)) != 0 || cmdLStruct.Length > 65534) {
    return "";
}

size_t wchar_count = cmdLStruct.Length / sizeof(wchar_t);
std::vector<wchar_t> buffer(wchar_count + 1, 0);
if (!ReadProcessMemory(hproc, cmdLStruct.Buffer, buffer.data(), cmdLStruct.Length, NULL))
{
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:bufferReadFail)\033[0m"; 
    } else {
        return "Failed to Access (wwitr:bufferReadFail)"; 
    }
}

std::wstring stringBuffer = buffer.data();
return WideToString(stringBuffer);
} else {

    BOOL targetIsWow64 = FALSE;
    
    IsWow64Process(hproc, &targetIsWow64);
    if (targetIsWow64) {

   typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
if (!queryInfo) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:functionptrs)\033[0m";
    } else {
        return "Failed to Access (wwitr:functionptrs)";
    }
}

PROCESS_BASIC_INFORMATION pbi;
if (queryInfo(hproc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {

    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:ntqueryfailed)\033[0m";
    } else {
        return "Failed to Access (wwitr:ntqueryfailed)";
    }
}

PVOID procParamPtr = nullptr;
if (!ReadProcessMemory(hproc, (BYTE*)pbi.PebBaseAddress + 0x10, &procParamPtr, sizeof(PVOID), NULL)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:procParamPtrRead)\033[0m";
    } else {
        return "Failed to Access (wwitr:procParamPtrRead)";
    }
}

UNICODE_STRING cmdLStruct;
SIZE_T bytesRead2 = 0;
if (!ReadProcessMemory(hproc, (BYTE*)procParamPtr + 0x24, &cmdLStruct, sizeof(cmdLStruct), &bytesRead2)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:cmdLStructFail)\033[0m";
    } else {
        return "Failed to Access (wwitr:cmdLStructFail)";
    }
}

if (cmdLStruct.Length == 0 || (cmdLStruct.Length % sizeof(wchar_t)) != 0 || cmdLStruct.Length > 65534) {
    return "";
}

size_t wchar_count = cmdLStruct.Length / sizeof(wchar_t);
std::vector<wchar_t> buffer(wchar_count + 1, 0);
if (!ReadProcessMemory(hproc, cmdLStruct.Buffer, buffer.data(), cmdLStruct.Length, NULL))
{
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:bufferReadFail)\033[0m"; 
    } else {
        return "Failed to Access (wwitr:bufferReadFail)"; 
    }
}

std::wstring stringBuffer = buffer.data();
return WideToString(stringBuffer);

    } else {
        
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        auto queryInfo64 = (pNtWow64QueryInformationProcess64)GetProcAddress(ntdll, "NtWow64QueryInformationProcess64");
        auto readMem64 = (pNtWow64ReadVirtualMemory64)GetProcAddress(ntdll, "NtWow64ReadVirtualMemory64");

        if (!queryInfo64 || !readMem64) {
            if (virtualTerminalEnabled) {
                return "\033[31mFailed to Access (wwitr:functionptrs)\033[0m";
            } else {
                return "Failed to Access (wwitr:functionptrs)";
            }
        }

        HANDLE targetHandle = hproc;
        HANDLE openedHandle = NULL;
        DWORD targetPid = 0;
        if (hproc != NULL) {
            targetPid = GetProcessId(hproc);
        }
        if (targetPid != 0) {
            openedHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetPid);
            if (openedHandle) targetHandle = openedHandle;
        }

        PROCESS_BASIC_INFORMATION64 pbi64{};
        ULONG returnLen = 0;
        NTSTATUS status = queryInfo64(targetHandle, ProcessBasicInformation, &pbi64, sizeof(pbi64), &returnLen);
        ULONG64 peb64Address = pbi64.PebBaseAddress;
        if (status != 0 || peb64Address == 0) {
            if (openedHandle) CloseHandle(openedHandle);
            if (virtualTerminalEnabled) {
                return "\033[31mFailed to Access (wwitr:ntqueryfailed)\033[0m";
            } else {
                return "Failed to Access (wwitr:ntqueryfailed)";
            }
        }

        ULONG64 procParamPtr64 = 0;
        status = readMem64(targetHandle, peb64Address + 0x20, &procParamPtr64, sizeof(procParamPtr64), NULL);
        if (status != 0) {
            if (openedHandle) CloseHandle(openedHandle);
            if (virtualTerminalEnabled) {
                return "\033[31mFailed to Access (wwitr:procParamPtrRead)\033[0m";
            } else {
                return "Failed to Access (wwitr:procParamPtrRead)";
            }
        }

        UNICODE_STRING64 cmdLStruct64;
        status = readMem64(targetHandle, procParamPtr64 + 0x38, &cmdLStruct64, sizeof(cmdLStruct64), NULL);
        if (status != 0) {
            if (openedHandle) CloseHandle(openedHandle);
            if (virtualTerminalEnabled) {
                return "\033[31mFailed to Access (wwitr:cmdLStructFail)\033[0m";
            } else {
                return "Failed to Access (wwitr:cmdLStructFail)";
            }
        }

        if (cmdLStruct64.Length == 0 || (cmdLStruct64.Length % sizeof(wchar_t)) != 0 || cmdLStruct64.Length > 65534) {
            if (openedHandle) CloseHandle(openedHandle);
            return "";
        }

        size_t wchar_count = cmdLStruct64.Length / sizeof(wchar_t);
        std::vector<wchar_t> buffer(wchar_count + 1, 0);
        status = readMem64(targetHandle, cmdLStruct64.Buffer, buffer.data(), cmdLStruct64.Length, NULL);
        if (status != 0) {
            if (openedHandle) CloseHandle(openedHandle);
            if (virtualTerminalEnabled) {
                return "\033[31mFailed to Access (wwitr:bufferReadFail)\033[0m";
            } else {
                return "Failed to Access (wwitr:bufferReadFail)";
            }
        }

        if (openedHandle) CloseHandle(openedHandle);
        std::wstring wstr(buffer.data());
        return WideToString(wstr);
    

        
    }

}
 #elif defined(_M_ARM64) 


BOOL isWow64 = FALSE;
if (!IsWow64Process(hproc, &isWow64)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:wow64checkfail)\033[0m";
    } else {
        return "Failed to Access (wwitr:wow64checkfail)";
    }
}
bool isWoW64 = isWow64;

if (!isWoW64) {

typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

if (!queryInfo) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:functionptrs)\033[0m";
    } else {
        return "Failed to Access (wwitr:functionptrs)";
    }
}

PROCESS_BASIC_INFORMATION pbi;
if (queryInfo(hproc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {

    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:ntqueryfailed)\033[0m";
    } else {
        return "Failed to Access (wwitr:ntqueryfailed)";
    }
}

PVOID procParamPtr = nullptr;
if (!ReadProcessMemory(hproc, (BYTE*)pbi.PebBaseAddress + 0x20, &procParamPtr, sizeof(PVOID), NULL)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:procParamPtrRead)\033[0m";
    } else {
        return "Failed to Access (wwitr:procParamPtrRead)";
    }
}

UNICODE_STRING cmdLStruct;
SIZE_T bytesRead2 = 0;
if (!ReadProcessMemory(hproc, (BYTE*)procParamPtr + 0x38, &cmdLStruct, sizeof(cmdLStruct), &bytesRead2)) {
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:cmdLStructFail)\033[0m";
    } else {
        return "Failed to Access (wwitr:cmdLStructFail)";
    }
}

if (cmdLStruct.Length == 0 || (cmdLStruct.Length % sizeof(wchar_t)) != 0 || cmdLStruct.Length > 65534) {
    return "";
}

size_t wchar_count = cmdLStruct.Length / sizeof(wchar_t);
std::vector<wchar_t> buffer(wchar_count + 1, 0);
if (!ReadProcessMemory(hproc, cmdLStruct.Buffer, buffer.data(), cmdLStruct.Length, NULL))
{
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:bufferReadFail)\033[0m"; 
    } else {
        return "Failed to Access (wwitr:bufferReadFail)"; 
    }
}

std::wstring stringBuffer = buffer.data();
return WideToString(stringBuffer);


} else {

    auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!queryInfo) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:functionptrs)\033[0m";
        } else {
            return "Failed to Access (wwitr:functionptrs)";
        }
    }

    ULONG_PTR peb32Address = 0;
    NTSTATUS status = queryInfo(hproc, ProcessWow64Information, &peb32Address, sizeof(peb32Address), NULL);
    if (status != 0 || peb32Address == 0) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:ntqueryfailed)\033[0m";
        } else {
            return "Failed to Access (wwitr:ntqueryfailed)";
        }
    }

    ULONG procParamPtr32 = 0;
    if (!ReadProcessMemory(hproc, (BYTE*)peb32Address + 0x10, &procParamPtr32, sizeof(procParamPtr32), NULL)) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:procParamPtrRead)\033[0m";
        } else {
            return "Failed to Access (wwitr:procParamPtrRead)";
        }
    }

    UNICODE_STRING32 cmdLStruct32{};
    if (!ReadProcessMemory(hproc, (BYTE*)(ULONG_PTR)procParamPtr32 + 0x24, &cmdLStruct32, sizeof(cmdLStruct32), NULL)) {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:cmdLStructFail)\033[0m";
        } else {
            return "Failed to Access (wwitr:cmdLStructFail)";
        }
    }

    if (cmdLStruct32.Length == 0 || (cmdLStruct32.Length % sizeof(wchar_t)) != 0 || cmdLStruct32.Length > 65534) {
        return "";
    }

    size_t wchar_count = cmdLStruct32.Length / sizeof(wchar_t);
    std::vector<wchar_t> buffer(wchar_count + 1, 0);
    if (!ReadProcessMemory(hproc, (PVOID)(ULONG_PTR)cmdLStruct32.Buffer, buffer.data(), cmdLStruct32.Length, NULL))
    {
        if (virtualTerminalEnabled) {
            return "\033[31mFailed to Access (wwitr:bufferReadFail)\033[0m";
        } else {
            return "Failed to Access (wwitr:bufferReadFail)";
        }
    }

    std::wstring stringBuffer = buffer.data();
    return WideToString(stringBuffer);
}
#else 
    if (virtualTerminalEnabled) {
        return "\033[31mFailed to Access (wwitr:unknownarch)\033[0m";
    } else {
        return "Failed to Access (wwitr:unknownarch)";
    }
#endif
}

/* another massive block
2453128674613097462347362402316408372462317652378652397816478164234
4237842134623140236403264236492173643219462193487621394612983746973424
242347623947623987462378462398746239187463298746987462398764728936428379462
248764923864698723498237698327649823764879264928736482379642713642]

33424234234
234234234
231423423
4234234
*/

std::string GetWindowTitle(HANDLE hproc) {
	// in this function, we will get the window title of the program
	// by once again readding the peb
	// it will replace the "Process" entry because 
	// currently its a bit redundant
	// this will be a bit more helpful while still being basically instant
	// and if its a headless program it doesn't matter much since its going to be the .exe name either way
	// which would be the same as not reading the PEB so better to try than nothing 
#ifdef _M_X64


BOOL isWow64 = FALSE;
if (!IsWow64Process(hproc, &isWow64)) {
    return ""; // in this case, we don't need to return an error code if it fails, we just silently fall back
	// to the existing target name we already had so it doesn't matter much
}
bool isWoW64 = isWow64;

if (!isWoW64) {

typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
if (!queryInfo) {
    return "";
}

PROCESS_BASIC_INFORMATION pbi;
if (queryInfo(hproc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {

    return "";
}

PVOID procParamPtr = nullptr;
if (!ReadProcessMemory(hproc, (BYTE*)pbi.PebBaseAddress + 0x20, &procParamPtr, sizeof(PVOID), NULL)) {
    return "";
}

UNICODE_STRING cmdLStruct;
SIZE_T bytesRead2 = 0;
if (!ReadProcessMemory(hproc, (BYTE*)procParamPtr + 0x38, &cmdLStruct, sizeof(cmdLStruct), &bytesRead2)) {
    return "";
}

if (cmdLStruct.Length == 0 || (cmdLStruct.Length % sizeof(wchar_t)) != 0 || cmdLStruct.Length > 65534) {
    return "";
}

size_t wchar_count = cmdLStruct.Length / sizeof(wchar_t);
std::vector<wchar_t> buffer(wchar_count + 1, 0);
if (!ReadProcessMemory(hproc, cmdLStruct.Buffer, buffer.data(), cmdLStruct.Length, NULL))
{
    return "";
}

std::wstring stringBuffer = buffer.data();
return WideToString(stringBuffer);


} else {
    auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!queryInfo) {
        return "";
    }

    ULONG_PTR peb32Address = 0;
    NTSTATUS status = queryInfo(hproc, ProcessWow64Information, &peb32Address, sizeof(peb32Address), NULL);
    if (status != 0 || peb32Address == 0) {
        return "";
    }

    ULONG procParamPtr32 = 0;
    if (!ReadProcessMemory(hproc, (BYTE*)peb32Address + 0x10, &procParamPtr32, sizeof(procParamPtr32), NULL)) {
        return "";
    }

    UNICODE_STRING32 cmdLStruct32{};
    if (!ReadProcessMemory(hproc, (BYTE*)(ULONG_PTR)procParamPtr32 + 0x24, &cmdLStruct32, sizeof(cmdLStruct32), NULL)) {
       return "";
    }

    if (cmdLStruct32.Length == 0 || (cmdLStruct32.Length % sizeof(wchar_t)) != 0 || cmdLStruct32.Length > 65534) {
        return "";
    }

    size_t wchar_count = cmdLStruct32.Length / sizeof(wchar_t);
    std::vector<wchar_t> buffer(wchar_count + 1, 0);
    if (!ReadProcessMemory(hproc, (PVOID)(ULONG_PTR)cmdLStruct32.Buffer, buffer.data(), cmdLStruct32.Length, NULL))
    {
        return "";
    }

    std::wstring stringBuffer = buffer.data();
    return WideToString(stringBuffer);
}
 #elif defined(_M_IX86) 
     BOOL areWeWoW64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &areWeWoW64);
    if (!areWeWoW64) {
        typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
if (!queryInfo) {
    return "";
}

PROCESS_BASIC_INFORMATION pbi;
if (queryInfo(hproc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {

    return "";
}

PVOID procParamPtr = nullptr;
if (!ReadProcessMemory(hproc, (BYTE*)pbi.PebBaseAddress + 0x10, &procParamPtr, sizeof(PVOID), NULL)) {
   return "";
}

UNICODE_STRING cmdLStruct;
SIZE_T bytesRead2 = 0;
if (!ReadProcessMemory(hproc, (BYTE*)procParamPtr + 0x24, &cmdLStruct, sizeof(cmdLStruct), &bytesRead2)) {
    return "";
}

if (cmdLStruct.Length == 0 || (cmdLStruct.Length % sizeof(wchar_t)) != 0 || cmdLStruct.Length > 65534) {
    return "";
}

size_t wchar_count = cmdLStruct.Length / sizeof(wchar_t);
std::vector<wchar_t> buffer(wchar_count + 1, 0);
if (!ReadProcessMemory(hproc, cmdLStruct.Buffer, buffer.data(), cmdLStruct.Length, NULL))
{
    return "";
}

std::wstring stringBuffer = buffer.data();
return WideToString(stringBuffer);
} else {

    BOOL targetIsWow64 = FALSE;
    
    IsWow64Process(hproc, &targetIsWow64);
    if (targetIsWow64) {

   typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
if (!queryInfo) {
    return "";
}

PROCESS_BASIC_INFORMATION pbi;
if (queryInfo(hproc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {

    return "";
}

PVOID procParamPtr = nullptr;
if (!ReadProcessMemory(hproc, (BYTE*)pbi.PebBaseAddress + 0x10, &procParamPtr, sizeof(PVOID), NULL)) {
    return "";
}

UNICODE_STRING cmdLStruct;
SIZE_T bytesRead2 = 0;
if (!ReadProcessMemory(hproc, (BYTE*)procParamPtr + 0x24, &cmdLStruct, sizeof(cmdLStruct), &bytesRead2)) {
    return "";
}

if (cmdLStruct.Length == 0 || (cmdLStruct.Length % sizeof(wchar_t)) != 0 || cmdLStruct.Length > 65534) {
    return "";
}

size_t wchar_count = cmdLStruct.Length / sizeof(wchar_t);
std::vector<wchar_t> buffer(wchar_count + 1, 0);
if (!ReadProcessMemory(hproc, cmdLStruct.Buffer, buffer.data(), cmdLStruct.Length, NULL))
{
    return "";
}

std::wstring stringBuffer = buffer.data();
return WideToString(stringBuffer);

    } else {
        
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        auto queryInfo64 = (pNtWow64QueryInformationProcess64)GetProcAddress(ntdll, "NtWow64QueryInformationProcess64");
        auto readMem64 = (pNtWow64ReadVirtualMemory64)GetProcAddress(ntdll, "NtWow64ReadVirtualMemory64");

        if (!queryInfo64 || !readMem64) {
            return "";
        }

        HANDLE targetHandle = hproc;
        HANDLE openedHandle = NULL;
        DWORD targetPid = 0;
        if (hproc != NULL) {
            targetPid = GetProcessId(hproc);
        }
        if (targetPid != 0) {
            openedHandle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, targetPid);
            if (openedHandle) targetHandle = openedHandle;
        }

        PROCESS_BASIC_INFORMATION64 pbi64{};
        ULONG returnLen = 0;
        NTSTATUS status = queryInfo64(targetHandle, ProcessBasicInformation, &pbi64, sizeof(pbi64), &returnLen);
        ULONG64 peb64Address = pbi64.PebBaseAddress;
        if (status != 0 || peb64Address == 0) {
            if (openedHandle) CloseHandle(openedHandle);
           return "";
        }

        ULONG64 procParamPtr64 = 0;
        status = readMem64(targetHandle, peb64Address + 0x20, &procParamPtr64, sizeof(procParamPtr64), NULL);
        if (status != 0) {
            if (openedHandle) CloseHandle(openedHandle);
           return "";
        }

        UNICODE_STRING64 cmdLStruct64;
        status = readMem64(targetHandle, procParamPtr64 + 0x38, &cmdLStruct64, sizeof(cmdLStruct64), NULL);
        if (status != 0) {
            if (openedHandle) CloseHandle(openedHandle);
           return "";
        }

        if (cmdLStruct64.Length == 0 || (cmdLStruct64.Length % sizeof(wchar_t)) != 0 || cmdLStruct64.Length > 65534) {
            if (openedHandle) CloseHandle(openedHandle);
            return "";
        }

        size_t wchar_count = cmdLStruct64.Length / sizeof(wchar_t);
        std::vector<wchar_t> buffer(wchar_count + 1, 0);
        status = readMem64(targetHandle, cmdLStruct64.Buffer, buffer.data(), cmdLStruct64.Length, NULL);
        if (status != 0) {
            if (openedHandle) CloseHandle(openedHandle);
            return "";
        }

        if (openedHandle) CloseHandle(openedHandle);
        std::wstring wstr(buffer.data());
        return WideToString(wstr);
    

        
    }

}
 #elif defined(_M_ARM64) 


BOOL isWow64 = FALSE;
if (!IsWow64Process(hproc, &isWow64)) {
    return "";
}
bool isWoW64 = isWow64;

if (!isWoW64) {

typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");

if (!queryInfo) {
    return "";
}

PROCESS_BASIC_INFORMATION pbi;
if (queryInfo(hproc, ProcessBasicInformation, &pbi, sizeof(pbi), NULL) != 0) {

    return "";
}

PVOID procParamPtr = nullptr;
if (!ReadProcessMemory(hproc, (BYTE*)pbi.PebBaseAddress + 0x20, &procParamPtr, sizeof(PVOID), NULL)) {
    return "";
}

UNICODE_STRING cmdLStruct;
SIZE_T bytesRead2 = 0;
if (!ReadProcessMemory(hproc, (BYTE*)procParamPtr + 0x38, &cmdLStruct, sizeof(cmdLStruct), &bytesRead2)) {
   return "";
}

if (cmdLStruct.Length == 0 || (cmdLStruct.Length % sizeof(wchar_t)) != 0 || cmdLStruct.Length > 65534) {
    return "";
}

size_t wchar_count = cmdLStruct.Length / sizeof(wchar_t);
std::vector<wchar_t> buffer(wchar_count + 1, 0);
if (!ReadProcessMemory(hproc, cmdLStruct.Buffer, buffer.data(), cmdLStruct.Length, NULL))
{
    return "";
}

std::wstring stringBuffer = buffer.data();
return WideToString(stringBuffer);


} else {

    auto queryInfo = (pNtQueryInformationProcess)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (!queryInfo) {
        return "";
    }

    ULONG_PTR peb32Address = 0;
    NTSTATUS status = queryInfo(hproc, ProcessWow64Information, &peb32Address, sizeof(peb32Address), NULL);
    if (status != 0 || peb32Address == 0) {
        return "";
    }

    ULONG procParamPtr32 = 0;
    if (!ReadProcessMemory(hproc, (BYTE*)peb32Address + 0x10, &procParamPtr32, sizeof(procParamPtr32), NULL)) {
       return "";
    }

    UNICODE_STRING32 cmdLStruct32{};
    if (!ReadProcessMemory(hproc, (BYTE*)(ULONG_PTR)procParamPtr32 + 0x24, &cmdLStruct32, sizeof(cmdLStruct32), NULL)) {
       return "";
    }

    if (cmdLStruct32.Length == 0 || (cmdLStruct32.Length % sizeof(wchar_t)) != 0 || cmdLStruct32.Length > 65534) {
        return "";
    }

    size_t wchar_count = cmdLStruct32.Length / sizeof(wchar_t);
    std::vector<wchar_t> buffer(wchar_count + 1, 0);
    if (!ReadProcessMemory(hproc, (PVOID)(ULONG_PTR)cmdLStruct32.Buffer, buffer.data(), cmdLStruct32.Length, NULL))
    {
      return "";
    }

    std::wstring stringBuffer = buffer.data();
    return WideToString(stringBuffer);
}
#else 
   return "";
#endif
}

void PrintAncestry(DWORD pid, HANDLE hSnapshot, const std::unordered_map<DWORD, PROCESSENTRY32>& pidMap) {
	// now we're geting the name
// we're making it slower by adding a bunch of snapshots 
// but again, we'll optimize and refactor later, i need this to work first


/*
~~~~~~~~~~~~~TODO: This tree is flipped. The output should be like this, as shown in the original witr:
systemd (pid 1)
  └─ PM2 v5.3.1: God (pid 1481580)
    └─ python (pid 1482060)

UPDATE: This is done now!!

*/

    
    
    // Build a PID→process map ONCE instead of walking 3 times
    std::unordered_map<DWORD, PROCESSENTRY32> localPidMap;
    const std::unordered_map<DWORD, PROCESSENTRY32>* pidMapPtr = &pidMap;
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (pidMapPtr->empty()) {
        if (Process32First(hSnapshot, &pe32)) {
            do {
                localPidMap.emplace(pe32.th32ProcessID, pe32);
            } while (Process32Next(hSnapshot, &pe32));
        }
        pidMapPtr = &localPidMap;
    }

    DWORD parentPid = 0;
    
   
    
    DWORD currentProcessId = GetCurrentProcessId(); // checking our own process
    DWORD currentParentPid = 0;

    // here, we're gonna use the existing snapshot so it doesn't use another
    // it shouldn't harm performance, but even if it does, I want to get 
    // the features done first before optimizing anything
    auto currentIt = pidMapPtr->find(currentProcessId);
    if (currentIt != pidMapPtr->end()) {
        pe32 = currentIt->second;
    }
    
    DWORD targetpid = pid; // the function already passes pid into us, but 
                          // just to be safe that pid doesn't get overwritten in the loop below
    std::string exeName = "Unknown/Dead Process";
    std::vector<std::string> exeNames; // sorry for the crap code but idk how to make multidimensional arrays yet 😭😭😭
    std::vector<DWORD> pidNames;     // hopefully the compiler can fix it
    std::vector<DWORD> parentPids;
	ULONGLONG creationTime = GetProcessCreationTime(pid, *pidMapPtr);
    bool found = false;
    while (pid != 0 && pid != 4) {
    found = false; 
    auto it = pidMapPtr->find(pid);
    if (it != pidMapPtr->end()) {
        const PROCESSENTRY32& entry = it->second;
        // Without comments, this literally looks like alien gibberish so lemme explain
      	
        exeName = WideToString(entry.szExeFile); //this stores the NAME of the current pid, converted to something that the terminal won't choke and die on
        exeNames.emplace_back(exeName); // this adds the above to the name list
        pidNames.emplace_back(pid); // this adds the current pid (no need to store in var as already passed into if)
        
        parentPid = entry.th32ParentProcessID; // this gets the pid of the PARENT pid (if there hopefully is one)
        parentPids.emplace_back(entry.th32ParentProcessID); // adds above to list
    	ULONGLONG parentTime = GetProcessCreationTime(entry.th32ParentProcessID, *pidMapPtr);

        if (parentPid == 0 || parentPid == 4 || parentTime == 0 || parentTime >= creationTime) {
            // we can't be sure if the parent actually exists and windows isn't lying to us,
            // so always double check
                pid = 0; 
        } else {

            pid = parentPid;
        }
        found = true;
    }
     
    if (!found) break;
    }
    // we're close... but not done yet. we need to find the CHILDREN of the process now. 
    // We can create another loop, but this time going downwards, checking if a process
    // tells us that our target pid is it's parent. This time, we don't have to worry about
    // Checking if the parent is alive, because, well, since the target IS the parent, 
    // it must be alive.
	    // now we need to reverse all the vector lists we made so
    // that the ancestry tree is correctly diisplayed from root to children like witr
    // in c++20 there is a new way to reverse called ranges or smth but i won't use that
    std::reverse(exeNames.begin(), exeNames.end()); 
    std::reverse(pidNames.begin(), pidNames.end());  
    std::reverse(parentPids.begin(), parentPids.end());  
    int children = 0; // i wonder what would happen if you could set an emoji as var name
    for (const auto& pair : *pidMapPtr) {
        const PROCESSENTRY32& entry = pair.second;
            
               // this time, our target pid is already stored at the very top of our list.
               // this means we don't have to add target pid stuff.
               // TODO: (for future optimization) we should probably move this before the 
               // the previous loop, since emplacing to the front requires shifting the entire list
               // and therefore is inefficient, robbing us of a couple milliseconds of precious cpu time :(

                if (entry.th32ParentProcessID == targetpid) {
                    exeName = WideToString(entry.szExeFile); // this stores the name of our pid we're looking at in a var
                    exeNames.emplace_back(exeName); 
                    pidNames.emplace_back(entry.th32ProcessID);
                    parentPids.emplace_back(entry.th32ProcessID); // just fill it up, we aren't using it
                    children++; // keeps track of how many children we have (that sounds wrong when you say it)

                }
                

                
            
    }

    


    // now get the size of one of the lists to know how many we got (they should all be the same length)
    size_t nameSize = exeNames.size();
    

    for (size_t i = 0; i < nameSize; i++ ){ // size_t is an unsigned integer designed to be ridiculously big to handle monstrosities,
                                          // idk just in case some psycho has a gazillion nested procs
        
        // surprise we have nested for loops 
        for (size_t j = 0; j < i; j++) {
            size_t targetIndex = nameSize - children - 1;
        if (i < nameSize - children || j < targetIndex) {
                std::cout << "  "; // this adds indentation
            }
        }
        if (i > 0) {
            
            std::cout << "  "; // add one indentation att start so it looks cleaner
        if (virtualTerminalEnabled) {
            std::cout << "\033[35m└─\033[0m ";  // it's the little thingy thing └─ unicode from witr 
        } else {
            std::cout << "└─ ";  
        }}
           
        if (virtualTerminalEnabled) {
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
    }

void FindProcessPorts(DWORD targetPid) {
	// this function gets the ports that a process is listening to 
	// unfortunately, according to microsoft docs, this only works starting from windows xp sp2 :(
	// so sorry for those of you using vanilla xp
	// the docs in question: https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getextendedtcptable
	
    MIB_TCPTABLE_OWNER_PID* pTcpTable;
    DWORD dwSize = 0;
    DWORD dwRetVal = 0;
    
    dwRetVal = GetExtendedTcpTable(NULL, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

    if (dwRetVal == ERROR_INSUFFICIENT_BUFFER) {
        pTcpTable = (MIB_TCPTABLE_OWNER_PID*)malloc(dwSize);
        if (pTcpTable == NULL) {
            return;
        }

        dwRetVal = GetExtendedTcpTable(pTcpTable, &dwSize, FALSE, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

        if (dwRetVal == NO_ERROR) {
            // Collect all listening IP:port pairs first
            std::vector<std::string> listening;
            for (DWORD i = 0; i < pTcpTable->dwNumEntries; i++) {
                if (pTcpTable->table[i].dwOwningPid == targetPid && 
                    pTcpTable->table[i].dwState == MIB_TCP_STATE_LISTEN) {
                    struct in_addr addr;
                    addr.S_un.S_addr = pTcpTable->table[i].dwLocalAddr;
                    std::string ip = inet_ntoa(addr);
                    u_short port = ntohs(pTcpTable->table[i].dwLocalPort);
                    listening.push_back(ip + ":" + std::to_string(port));
                }
            }

            if (!listening.empty()) {
                if (virtualTerminalEnabled) {
                    std::cout << "\033[1;32mListening\033[0m: \n";
                } else {
                    std::cout << "Listening: \n";
                }
                
                
                for (size_t i = 0; i < listening.size(); i++) {
                    std::cout << "\t\t" <<  listening[i];
                    if (i < listening.size() - 1) {
                        std::cout << ",\n";
                    }
                }
                std::cout << std::endl;
            }
        }

        free(pTcpTable);
    }
}



void PIDinspect(const std::vector<DWORD>& pids, const std::vector<std::string>& names, HANDLE hshot) { // ooh guys look i'm in the void
    DWORD pid = pids[0];
    std::unordered_map<DWORD, PROCESSENTRY32> pidMap;
    PROCESSENTRY32 pe32{};
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hshot, &pe32)) {
        do {
            pidMap.emplace(pe32.th32ProcessID, pe32);
        } while (Process32Next(hshot, &pe32));
    }
	std::string procName = GetProcessNameFromPid(pid, hshot);
	std::string process = GetWindowTitle(hshot);
	
	
	if (virtualTerminalEnabled) {
		if (!(process == "")) { 
		std::cout << "\033[34mTarget:\033[0m " << procName << "\033[0m" << std::endl;
		std::cout << "\033[34mProcess:\033[0m " << process << "\033[90m (pid " << std::to_string(pid) << ")\033[0m" << std::endl;
		} else {
		if (procName == ""){
			std::cout << "\033[34mTarget:\033[0m N/A\n\033[34mProcess:\033[0m N/A\n";
		} else {
		std::cout << "\033[34mTarget:\033[0m " << procName << "\033[0m" << std::endl;
		std::cout << "\033[34mProcess:\033[0m " << procName << "\033[90m (pid " << std::to_string(pid) << ")\033[0m" << std::endl;
		}
	} else {
			if (!process == "") { 
		std::cout << "Target: " << procName << std::endl;
		std::cout << "Process: " << process << " (pid " << std::to_string(pid) << ")" << std::endl;
		} else {
		if (procName == ""){
			std::cout << "Target: N/A\nProcess: N/A\n";
				} else {
		std::cout << "Target: " << procName << std::endl;
		std::cout << "Process: " << procName << " (pid " << std::to_string(pid) << ")" << std::endl;
		}
		}
	}
	

	
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
         // But of course, you need to be running as admin for this to work.
    }
    int errorCode = 0;
    bool queryError = false;
    if (!hProcess) {
        errorCode = GetLastError();
	
        
        if (virtualTerminalEnabled) {
            
            queryError = true;
            std::cerr << "\033[1;31mError:\033[0m Could not open process with PID " 
                      << pid << ". Error code: " << errorCode 
                      << "\nMaybe it doesn't exist or access is denied." << std::endl;

        } else {
            queryError = true;
            std::cerr << "Error: Could not open process with PID " 
                      << pid << ". Error code: " << errorCode 
                      << "\nMaybe it doesn't exist or access is denied." << std::endl;
                
        }
        if (queryError) {
        PrintErrorHints(errorCode, hshot);
    }
        
        
    }

     
    char exePath[MAX_PATH] = {0};
    DWORD size = MAX_PATH;
        
    if (QueryFullProcessImageNameA(hProcess, 0, exePath, &size)) {
        if (virtualTerminalEnabled) {
            std::cout << "\033[34mExecutable Path:\033[0m " << exePath << std::endl;
        } else {
            std::cout << "Executable Path: " << exePath << std::endl;
        }
    } else {
        
        errorCode = GetLastError();
        if (virtualTerminalEnabled) {
            queryError = true;
            std::cerr << "\033[1;31mError:\033[0m Unable to query executable path. Error code: " 
                      << errorCode 
                      << "\n Maybe Access is Denied or the process is running entirely in RAM." << std::endl;
        } else {
            queryError = true;
            std::cerr << "Error: Unable to query executable path. Error code: " 
                      << errorCode 
                      << "\n Maybe Access is Denied or the process is running entirely in RAM." << std::endl;
        }
        if (queryError) {
        PrintErrorHints(errorCode, hshot);
        // it might seem like overkill to call the function every time there's an error,
        // but if you remember we have a fallback for opening processes, so there are multiple
        // places where an error can occur.
        // for example, when testing this, the hint for error 5 (access denied) didn't show up
        // since immediately after it was overwritten by error code 6 (valid but insufficient permissions) created by the fallback
        // with the limited process info
    }

            
        }

        // Use our little lookup table to give hints for specific errors
        auto user = GetUserNameFromProcess(pid); // dang it dude it feels like such a war crime using auto in c++ 😭✌️
        if (user.has_value()) {
            if (virtualTerminalEnabled) {
             std::cout << "\033[34mUser\033[0m: " << WideToString(user.value()) << std::endl;
            } else {
                std::cout << "User: " << WideToString(user.value()) << std::endl;
            }
            
        } else {
           if (virtualTerminalEnabled) {
            std::cout << "\033[1;34mUser\033[0m: \033[1;31mN/A (Failed to access info)\033[0m" << std::endl; 
        } else {
            std::cout << "User: N/A (Failed to access info)" << std::endl;
        }
        }

        std::string command = GetCommandLine(hProcess);

        
            if (virtualTerminalEnabled) {
                 std::cout << "\033[1;32mCommand\033[0m: " << command << std::endl;
            } else {
                    std::cout << "Command: " << command << std::endl;
                }
        std::string workdir = GetWorkingDir(hProcess);
	

        
            if (virtualTerminalEnabled) {
                 std::cout << "\033[1;32mWorking Directory\033[0m: " << workdir << std::endl;
            } else {
                    std::cout << "Working Directory: " << workdir << std::endl;
                }

			// to get memory usage,
	// we have to use psapi.h
	// the metric we want is WorkingSetSize because the api spits out a bunch of other metrics we don't need
	// hopefully this doesn't tank performance for yet another api call
	// the command and working dir don't affect it because PEB walks take like 5 ms idk
	// reference: https://learn.microsoft.com/en-us/windows/win32/psapi/collecting-memory-usage-information-for-a-process

	PROCESS_MEMORY_COUNTERS pmc;
	if ( GetProcessMemoryInfo( hProcess, &pmc, sizeof(pmc)) ) {
		// in the original snippet from windows
		// THE BRACKET IS AFTER THE IF IN THE LINE DOWN
		// i can't be talking about code organization but MICROSOFT WHAT
	size_t RAM = pmc.WorkingSetSize; //should be fine for this, unless you have like 10 exabytes of RAM for a single process somehow
									
std::string FRAM = ""; // fram means formatted ram, i'm so creative at var naming
		if (RAM < 1000) {
			// if less than 1000 bytes (which is a kilobyte) then just return bytes
			FRAM = std::to_string(RAM) + " B";
				}
		else if (RAM < 1000ULL * 1000) { 
			
			FRAM = std::to_string(RAM / 1000) + " KB";
		}
		else if (RAM < 1000ULL * 1000 * 1000) { 
			
			FRAM = std::to_string(RAM /( 1000ULL * 1000)) + " MB";
		}
		else if (RAM < 1000ULL * 1000 * 1000 * 1000) {
			FRAM = std::to_string(RAM /( 1000ULL * 1000 * 1000)) + " GB";
		}
		else {
			FRAM = std::to_string(RAM /( 1000ULL * 1000 * 1000 * 1000)) + " TB";
			// if someone actually reaches this i'm concerned
		}
			
			
			
		
		if (virtualTerminalEnabled) {
                 std::cout << "\033[1;32mRAM Usage\033[0m: " << FRAM << std::endl;
			// I know RAM is technically a "nerdy tech term" or whatever and it'd be more logical
		// to say "memory" but I feel like at this point everyone knows what RAM means
		// especially with the RAM shortage, it should be ingrained in their brains
		
            } else {
                    std::cout << "RAM Usage: " << FRAM << std::endl;
                }
	}
		
    
                
        
        
        
        
        

         
         // TODO: add color text
         
        if (virtualTerminalEnabled) {
            std::cout << "\n\033[1;35mWhy It Exists:\033[0m\n";
        } else {
            std::cout << "\nWhy It Exists:\n";
        }
        PrintAncestry(pid, hshot, pidMap);

		FindProcessPorts(pid);
	

		
		

        if (virtualTerminalEnabled) {
            std::cout << "\n\033[1;35mStarted:\033[0m " << GetReadableFileTime(pid, pidMap) << std::endl;
        } else {
            std::cout << "\nStarted: " << GetReadableFileTime(pid, pidMap) << std::endl;
        }

        if (pids.size() > 1) {
            if (virtualTerminalEnabled) {
                std::cout << "\033[1;35mRelated Processes:\033[0m\n";
            } else {
                std::cout << "Related Processes:\n";
            }
            
            for (size_t i = 1; i < pids.size(); i++) {
                std::string relatedProcName = names[i];
                if (virtualTerminalEnabled) {
                    std::cout << "\t\033[36m" << relatedProcName << "\033[90m (PID " << pids[i] << ")\033[0m\n";
                } else {
                    std::cout << "\t" << relatedProcName << " (PID " << pids[i] << ")\n";
                }
                
            }
        }
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

struct ProcInfos {
    std::vector<std::string> names;
    std::vector<int>         pids;
};

ProcInfos findMyProc(const char *procname, HANDLE hSnapshot) {

  
  PROCESSENTRY32 pe;
  ProcInfos result;
  BOOL hResult;
  

 

  // initializing size: needed for using Process32First
  pe.dwSize = sizeof(PROCESSENTRY32);

  // info about first process encountered in a system snapshot
  hResult = Process32First(hSnapshot, &pe);
  std::string procstr = procname;
  // retrieve information about the processes
  // and exit if unsuccessful
	// if we find the process: return process ID
	
	  
	  std::transform(procstr.begin(), procstr.end(), procstr.begin(), [](unsigned char c){ return std::tolower(c); });// same lowercasing as the otther
	  std::string ex = procstr;
	  if (!procstr.ends_with(".exe")) {// no joke i almost typed endsWith here, the J*vaScript mind virus is spreading
		  ex += ".exe";
	  }
  while (hResult) {
    
	  
	  std::string exeName = WideToString(pe.szExeFile);
	std::transform(exeName.begin(), exeName.end(), exeName.begin(), [](unsigned char c){ return std::tolower(c); });
	  // for the comparison make it lowercase so that it does the thingy mammombbers insensitiviityness case
			// this is only for the compariason either way
		  
	  
    if (exeName == ex || exeName == procstr) { 
	  result.names.push_back(WideToString(pe.szExeFile)); // let me cook
		// while you might think its less performant to waste all this
		// on storing related names for no reason
		// its crucial for the related processes since
		// otherwise we'd have to call the get process name for every related process
		// and slow us down significantly so storing it on the fly is better
      result.pids.push_back(pe.th32ProcessID);
    }
    hResult = Process32Next(hSnapshot, &pe);
  }

 
  return result;
}
// The above function is taken from https://cocomelonc.github.io/pentest/2021/09/29/findmyprocess.html, modified simply to use WideToString for the process name comparison among other things.
// Thanks!
 

int main(int argc, char* argv[]) {
    SetConsoleOutputCP(CP_UTF8);
    virtualTerminalEnabled = IsVirtualTerminalModeEnabled();
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
            
            if (virtualTerminalEnabled) {
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
                     if (virtualTerminalEnabled) {
                         std::cerr << "\033[1;31mError:\033[0m PID argument is not a valid number." << std::endl;
                     } else {
                         std::cerr << "Error: PID argument is not a valid number." << std::endl;
                     }
                     return 1; // someday we should probably have proper error codes instead of just 1 for everything
                            
                } catch (const std::out_of_range& oor) {
                     if (virtualTerminalEnabled) {
                         std::cerr << "\033[1;31mError:\033[0m PID argument is out of range." << std::endl;
                     } else {
                         std::cerr << "Error: PID argument is out of range." << std::endl;
                     }
                     return 1;
                }
                

                std::vector<DWORD> pids;
				std::vector<std::string> trash;
				trash.push_back("");
				pids.push_back(static_cast<DWORD>(pid));// function requires it to be a list even if only 1 is passed
				 // snapshot of all processes in the system first so we can pass it to every function from there on
			
			  HANDLE hshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			  if (INVALID_HANDLE_VALUE == hshot) {return 1;}
                PIDinspect(pids, trash, hshot);
				CloseHandle(hshot);
            } else {
                if (virtualTerminalEnabled) { // ugh i have to do this EVERY SINGLE TIME
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
			HANDLE hshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
			  if (INVALID_HANDLE_VALUE == hshot) {return 1;}
            ProcInfos r = findMyProc(procName.c_str(), hshot);
            if (!r.pids.empty()) {
                std::vector<DWORD> dwPids(r.pids.begin(), r.pids.end());
                PIDinspect(dwPids, r.names, hshot);
				CloseHandle(hshot);
            } else {
                if (virtualTerminalEnabled) {
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
