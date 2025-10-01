#ifndef MANUALINJECT_H
#define MANUALINJECT_H

#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);

typedef struct _MANUAL_INJECT
{
    PVOID ImageBase;
    PIMAGE_NT_HEADERS NtHeaders;
    PIMAGE_BASE_RELOCATION BaseRelocation;
    PIMAGE_IMPORT_DESCRIPTOR ImportDirectory;
    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;
} MANUAL_INJECT, * PMANUAL_INJECT;

class ManualInjector
{
private:
    static char shellcode[];

    // Internal helper methods
    static DWORD WINAPI LoadDll(PVOID p);
    static BOOL ValidateDll(PVOID buffer);
    static BOOL CopyDllToProcess(HANDLE hProcess, PVOID buffer, PVOID& image);
    static BOOL SetupLoader(HANDLE hProcess, PVOID image, PVOID buffer, PVOID& mem1);
    static BOOL HijackThread(HANDLE hProcess, DWORD processId, PVOID mem1);

    // Wait functions
    static BOOL WaitForProcessInitialization(HANDLE hProcess, DWORD timeoutMs = 10000);
    static BOOL WaitForProcessResponsive(HANDLE hProcess, DWORD timeoutMs = 10000);

public:
    // Main injection method
    static BOOL InjectDll(HANDLE hProcess, const char* DllPath);

    // Process creation method
    static BOOL CreateAndInject(const char* processPath, const char* dllPath,
        PROCESS_INFORMATION* pi = nullptr);
};

#endif