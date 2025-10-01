#ifndef MANUALINJECT_H
#define MANUALINJECT_H

#include <Windows.h>
#include <TlHelp32.h>
#include <psapi.h>

// For WOW64 context in x64 builds
#ifdef _WIN64
#include <winternl.h>
#endif

typedef HMODULE(WINAPI* pLoadLibraryA)(LPCSTR);
typedef FARPROC(WINAPI* pGetProcAddress)(HMODULE, LPCSTR);
typedef BOOL(WINAPI* PDLL_MAIN)(HMODULE, DWORD, PVOID);

typedef struct _MANUAL_INJECT
{
    PVOID ImageBase;
    PVOID NtHeaders;
    PVOID BaseRelocation;
    PVOID ImportDirectory;
    pLoadLibraryA fnLoadLibraryA;
    pGetProcAddress fnGetProcAddress;
} MANUAL_INJECT, * PMANUAL_INJECT;

class ManualInjector
{
private:
    static char shellcode_x86[];
    static char shellcode_x64[];

    // Internal helper methods
    static DWORD WINAPI LoadDll(PVOID p);
    static DWORD WINAPI LoadDllEnd();
    static BOOL ValidateDll(PVOID buffer);
    static BOOL CopyDllToProcess(HANDLE hProcess, PVOID buffer, PVOID& image, BOOL isTarget64);
    static BOOL SetupLoader(HANDLE hProcess, PVOID image, PVOID buffer, PVOID& mem1, BOOL isTarget64);
    static BOOL HijackThread(HANDLE hProcess, DWORD processId, PVOID mem1, BOOL isTarget64);

    // Architecture detection
    static BOOL IsProcess64Bit(HANDLE hProcess);
    static BOOL IsDll64Bit(PVOID buffer);

    // WOW64 context functions for x64 builds
#ifdef _WIN64
    static BOOL GetThreadContextWow64(HANDLE hThread, PWOW64_CONTEXT ctx);
    static BOOL SetThreadContextWow64(HANDLE hThread, PWOW64_CONTEXT ctx);
#endif

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

#endif // MANUALINJECT_H