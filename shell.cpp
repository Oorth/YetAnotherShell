#include <windows.h>
#include <iostream>
#include <winternl.h>
#include <string>
#include <map>
#include <vector>
#include <sstream>

#pragma comment(lib, "ntdll.lib")

typedef struct _MY_SYSTEM_PROCESS_INFORMATION 
{
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER WorkingSetPrivateSize;
    ULONG HardFaultCount;
    ULONG NumberOfThreadsHighWatermark;
    ULONGLONG CycleTime;
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE UniqueProcessId;
    HANDLE InheritedFromUniqueProcessId;
} MY_SYSTEM_PROCESS_INFORMATION, *PMY_SYSTEM_PROCESS_INFORMATION;


typedef std::string (*CommandRoutine)(const std::string& args);
std::map<std::string, CommandRoutine> g_CommandMap;


std::string static ExecuteMicroShell(std::string input_command);

// --------------------------------------------------------------------------------------------

#pragma region I/O

std::string static GetCommand()
{
	std::string inputBuffer = "";
	std::getline(std::cin, inputBuffer);

	return inputBuffer;
}


void static send_output(std::string output)
{

	std::cout << output << std::endl;
}

#pragma endregion

// --------------------------------------------------------------------------------------------

#pragma region Commands

std::string static InternalCommand_LS(const std::string& args)
{

    // Default to the current directory if no path is provided
    std::string searchPath = args.empty() ? ".\\*" : args;
    
    // Format the search string correctly for the Win32 API (requires trailing wildcard)
    if(!args.empty() && args.back() != '*' && args.back() != '\\') searchPath += "\\*";
    else if(!args.empty() && args.back() == '\\') searchPath += "*";
    
    WIN32_FIND_DATAA findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    hFind = FindFirstFileA(searchPath.c_str(), &findData);

    if(hFind == INVALID_HANDLE_VALUE) return "ls: cannot access '" + args + "': No such file or directory\n";

    std::stringstream output;
    output << "\nType\tSize\t\tName\n";
    output << "------------------------------------------------\n";

    do
    {
        // Skip the current and parent directory markers to reduce noise
        std::string fileName = findData.cFileName;
        if(fileName == "." || fileName == "..") continue;

        std::string type = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "[DIR]" : "[FILE]";
        
        // Calculate exact file size (HighPart * MAXDWORD + LowPart)
        ULARGE_INTEGER fileSize;
        fileSize.LowPart = findData.nFileSizeLow;
        fileSize.HighPart = findData.nFileSizeHigh;
        
        std::string sizeStr = (findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? "<DIR>" : std::to_string(fileSize.QuadPart);

        output << type << "\t" << sizeStr << "\t\t" << fileName << "\n";
        
    } while(FindNextFileA(hFind, &findData));

    FindClose(hFind);
    return output.str();
}

std::string static InternalCommand_CD(const std::string& args)
{

    if(args == "") return "cd requires arguments.";

    BOOL status = SetCurrentDirectoryA(args.c_str());
    if(status != TRUE) return "Error: Failed to change directory to '" + args + "'.\n";

    return "";
}

std::string static InternalCommand_WHOAMI(const std::string& args)
{
    HANDLE hToken = NULL;
    
    // Open the access token associated with the current process
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return "Error: Failed to open process token.\n";

    // To get the required buffer size
    // This will intentionally fail with ERROR_INSUFFICIENT_BUFFER, but populate dwSize
    DWORD dwSize = 0;
    GetTokenInformation(hToken, TokenUser, NULL, 0, &dwSize);

    // Allocate a dynamic buffer based on the size requested by the OS
    std::vector<BYTE> tokenBuffer(dwSize);
    PTOKEN_USER pTokenUser = (PTOKEN_USER)tokenBuffer.data();

    // Call GetTokenInformation again, this time with the properly sized buffer
    if(!GetTokenInformation(hToken, TokenUser, pTokenUser, dwSize, &dwSize))
    {
        CloseHandle(hToken);
        return "Error: Failed to extract TokenUser information.\n";
    }

    // We now have the SID. We need to translate it to Domain\User
    char userName[256];
    DWORD userNameSize = sizeof(userName);
    
    char domainName[256];
    DWORD domainNameSize = sizeof(domainName);
    
    SID_NAME_USE sidType;

    // LookupAccountSidA contacts the local SAM database or Domain Controller to resolve the SID
    if(!LookupAccountSidA(NULL, pTokenUser->User.Sid, userName, &userNameSize, domainName, &domainNameSize, &sidType))
    {
        CloseHandle(hToken);
        return "Error: Failed to resolve SID to account name.\n";
    }

    CloseHandle(hToken);
    return std::string(domainName) + "\\" + std::string(userName) + "\n";
}

std::string static InternalCommand_PS(const std::string& args)
{

    std::stringstream output;

    ULONG bufferSize = 1024 * 1024; 
    PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if(buffer == NULL)
    {
        return "Error: Initial VirtualAlloc failed.\n";
    }

    NTSTATUS status;
    while(true)
    {
        status = NtQuerySystemInformation(SystemProcessInformation, buffer, bufferSize, &bufferSize);
        
        if(status == 0xC0000004)
        {
            VirtualFree(buffer, 0, MEM_RELEASE);
            bufferSize += (1024 * 1024); // Add another 1MB and try again
            buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
            if(buffer == NULL)
            {
                return "Error: Reallocation VirtualAlloc failed.\n";
            }
        }

        else break;
    }

    if(!NT_SUCCESS(status))
    {
        output << "Error: NtQuerySystemInformation failed with status " << std::hex << status << "\n";

        if(buffer != NULL) VirtualFree(buffer, 0, MEM_RELEASE);
        return output.str();
    }


    PMY_SYSTEM_PROCESS_INFORMATION pInfo = (PMY_SYSTEM_PROCESS_INFORMATION)buffer;
        
    output << "PID\tPPID\tName\n";
    output << "----------------------------------------\n";

    while(true)
    {
        DWORD pid = (DWORD)(ULONG_PTR)pInfo->UniqueProcessId;
        DWORD ppid = (DWORD)(ULONG_PTR)pInfo->InheritedFromUniqueProcessId;
            
        std::string procName = "[System or Unknown]";
        
        if(pInfo->ImageName.Buffer != NULL)
        {
            int size_needed = WideCharToMultiByte(CP_UTF8, 0, pInfo->ImageName.Buffer, (int)(pInfo->ImageName.Length / sizeof(WCHAR)), NULL, 0, NULL, NULL);
            std::string convertedName(size_needed, 0);
            WideCharToMultiByte(CP_UTF8, 0, pInfo->ImageName.Buffer, (int)(pInfo->ImageName.Length / sizeof(WCHAR)), &convertedName[0], size_needed, NULL, NULL);
            
            procName = convertedName;
        }

        output << pid << "\t" << ppid << "\t" << procName << "\n";

        if(pInfo->NextEntryOffset == 0)
        {
            break;
        }
            
        pInfo = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
    }


    VirtualFree(buffer, 0, MEM_RELEASE);
    return output.str();

}

std::string static InternalCommand_MKDIR(const std::string& args)
{
    if(args.empty()) return "Error: mkdir requires a directory name.\n";

    if(CreateDirectoryA(args.c_str(), nullptr)) return "Directory created: " + args + "\n";
    
    return "Error: Failed to create directory. Code: " + std::to_string(GetLastError()) + "\n";
}

std::string static InternalCommand_RM(const std::string& args)
{
    if(args.empty()) return "Error: rm requires a file name.\n";

    if(DeleteFileA(args.c_str())) return "File deleted: " + args + "\n";
    
    return "Error: Failed to delete file. Code: " + std::to_string(GetLastError()) + "\n";
}

std::string InternalCommand_EXEC(const std::string& args)
{
    if(args.empty()) return "Error: exec requires a target executable.\n";

    std::string command = args;
    DWORD targetPid = 0;

    // Parse arguments to see if a PID was provided at the end
    size_t lastSpace = args.find_last_of(' ');
    if(lastSpace != std::string::npos)
    {
        std::string possiblePid = args.substr(lastSpace + 1);
        bool isNumeric = true;
        
        // Verify every character in the last token is a digit
        for(char c : possiblePid)
        {
            if(!isdigit(c))
            {
                isNumeric = false;
                break;
            }
        }

        if(isNumeric && !possiblePid.empty())
        {
            targetPid = std::stoul(possiblePid);
            command = args.substr(0, lastSpace);
            
            // Clean up any trailing whitespace from the command string
            command.erase(command.find_last_not_of(" \n\r\t") + 1);
        }
    }

    // Safely copy the command string into a writable buffer for the Windows API
    std::vector<char> cmdline(command.begin(), command.end());
    cmdline.push_back('\0');

    if(targetPid == 0)
    {
        // --- NORMAL CREATION ---
        STARTUPINFOA si;
        PROCESS_INFORMATION pi;
        
        ZeroMemory(&si, sizeof(si));
        si.cb = sizeof(si);
        ZeroMemory(&pi, sizeof(pi));

        if(CreateProcessA(NULL, cmdline.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return "[+] Process started normally: '" + command + "'\n";
        }
        else return "[-] Error: Normal execution failed. Code: " + std::to_string(GetLastError()) + "\n";
    }
    else
    {
        // --- SPOOFED CREATION (PID provided) ---
        HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, targetPid);
        if(hParent == NULL) return "[-] Error: Failed to open Parent PID " + std::to_string(targetPid) + ". Code: " + std::to_string(GetLastError()) + "\n";

        SIZE_T attributeSize = 0;
        InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);

        PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
        if(pAttributeList == NULL)
        {
            CloseHandle(hParent);
            return "[-] Error: Failed to allocate Attribute List.\n";
        }

        if(!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &attributeSize))
        {
            HeapFree(GetProcessHeap(), 0, pAttributeList);
            CloseHandle(hParent);
            return "[-] Error: Failed to initialize Attribute List.\n";
        }

        if(!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL))
        {
            DeleteProcThreadAttributeList(pAttributeList);
            HeapFree(GetProcessHeap(), 0, pAttributeList);
            CloseHandle(hParent);
            return "[-] Error: Failed to update Attribute List.\n";
        }

        STARTUPINFOEXA siex;
        PROCESS_INFORMATION pi;
        
        ZeroMemory(&siex, sizeof(siex));
        siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);
        siex.lpAttributeList = pAttributeList;
        ZeroMemory(&pi, sizeof(pi));

        BOOL success = CreateProcessA(NULL, cmdline.data(), NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, NULL, NULL, &siex.StartupInfo, &pi);

        DeleteProcThreadAttributeList(pAttributeList);
        HeapFree(GetProcessHeap(), 0, pAttributeList);
        CloseHandle(hParent);

        if(success)
        {
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return "[+] Process spoofed successfully: '" + command + "' as child of PID " + std::to_string(targetPid) + "\n";
        }
        else return "[-] Error: Spoofed execution failed. Code: " + std::to_string(GetLastError()) + "\n";
    }
}

std::string static InternalCommand_RMDIR(const std::string& args)
{
    if(args.empty()) return "Error: rmdir requires a directory name.\n";

    if(RemoveDirectoryA(args.c_str())) return "Directory removed: " + args + "\n";
    
    return "Error: Failed to remove directory. Code: " + std::to_string(GetLastError()) + "\n";
}


void static InitializeMicroShell()
{
    g_CommandMap["ls"] = InternalCommand_LS;
    g_CommandMap["dir"] = InternalCommand_LS;
    g_CommandMap["cd"] = InternalCommand_CD;
    g_CommandMap["ps"] = InternalCommand_PS;
    g_CommandMap["whoami"] = InternalCommand_WHOAMI;
    g_CommandMap["mkdir"] = InternalCommand_MKDIR;
    g_CommandMap["rmdir"] = InternalCommand_RMDIR;
    g_CommandMap["rm"] = InternalCommand_RM;
    g_CommandMap["run"] = InternalCommand_EXEC;
    // to add: run exes, etc.. something to send and get raw data
}

#pragma endregion

// --------------------------------------------------------------------------------------------



int main()
{
    InitializeMicroShell();

	while(true)
	{
		char currentPath[MAX_PATH];
        if(GetCurrentDirectoryA(MAX_PATH, currentPath) > 0) std::cout << "[YetAnotherShell] " << currentPath << "> ";
        else std::cout << "[YetAnotherShell]> ";



		std::string recieved_command = GetCommand();
		if(recieved_command.empty()) continue;
        
		
		if(recieved_command == "exit" || recieved_command == "quit") break;

		std::string output = ExecuteMicroShell(recieved_command);
		send_output(output);
	}

	return 0;
}


std::string static ExecuteMicroShell(std::string input_command)
{
    if(input_command.empty()) return "";

    size_t spacePos = input_command.find(' ');
    std::string command = input_command.substr(0, spacePos);
    std::string args = "";
    
    if(spacePos != std::string::npos) args = input_command.substr(spacePos + 1);

    // Strip trailing whitespace, newlines, and carriage returns
    command.erase(command.find_last_not_of(" \n\r\t") + 1);
    if(!args.empty()) args.erase(args.find_last_not_of(" \n\r\t") + 1);

    // Dispatch execution
    if(g_CommandMap.find(command) != g_CommandMap.end()) return g_CommandMap[command](args);
    else return "YetAnotherShell Error: Unrecognized internal command '" + command + "'.\n";
}