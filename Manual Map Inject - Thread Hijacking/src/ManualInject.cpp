/*
MIT License

Copyright (c) 2017 Bill Demirkapi

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
*/

#include "ManualInject.h"
#include <stdio.h>
#include <iostream>

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"psapi.lib")

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

// x86 Shellcode
char ManualInjector::shellcode_x86[] =
{
    0x60,                               // pushad
    0xE8, 0x00, 0x00, 0x00, 0x00,       // call $+5
    0x5B,                               // pop ebx
    0x81, 0xEB, 0x06, 0x00, 0x00, 0x00, // sub ebx, 6
    0xB8, 0xCC, 0xCC, 0xCC, 0xCC,       // mov eax, LoadDll function
    0xBA, 0xCC, 0xCC, 0xCC, 0xCC,       // mov edx, MANUAL_INJECT structure
    0x52,                               // push edx
    0xFF, 0xD0,                         // call eax
    0x61,                               // popad
    0x68, 0xCC, 0xCC, 0xCC, 0xCC,       // push original EIP
    0xC3                                // ret
};

// x64 Shellcode - CORRECTED VERSION
char ManualInjector::shellcode_x64[] =
{
  0x48, 0xB8, 0xF0, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // mov -16 to rax
  0x48, 0x21, 0xC4,                                             // and rsp, rax
  0x48, 0x83, 0xEC, 0x20,                                       // subtract 32 from rsp
  0x48, 0x8b, 0xEC,                                             // mov rbp, rsp
  0x90, 0x90,                                                   // nop nop
  0x48, 0xB9, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC,   // mov rcx,CCCCCCCCCCCCCCCC
  0x48, 0xB8, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA, 0xAA,   // mov rax,AAAAAAAAAAAAAAAA
  0xFF, 0xD0,                                                   // call rax
  0x90,                                                         // nop
  0x90,                                                         // nop
  0xEB, 0xFC                                                    // JMP to nop
};

BOOL ManualInjector::IsProcess64Bit(HANDLE hProcess)
{
    BOOL isWow64 = FALSE;

    typedef BOOL(WINAPI* LPFN_ISWOW64PROCESS)(HANDLE, PBOOL);
    LPFN_ISWOW64PROCESS fnIsWow64Process = (LPFN_ISWOW64PROCESS)GetProcAddress(GetModuleHandleA("kernel32"), "IsWow64Process");

    if (fnIsWow64Process != NULL)
    {
        if (!fnIsWow64Process(hProcess, &isWow64))
        {
            return FALSE;
        }

        SYSTEM_INFO systemInfo;
        GetNativeSystemInfo(&systemInfo);

        if (systemInfo.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
        {
            return !isWow64;
        }
    }

    return FALSE;
}

BOOL ManualInjector::IsDll64Bit(PVOID buffer)
{
    PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)buffer;
    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
        return FALSE;

    PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);
    if (pINH->Signature != IMAGE_NT_SIGNATURE)
        return FALSE;

    return pINH->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64;
}

BOOL ManualInjector::WaitForProcessInitialization(HANDLE hProcess, DWORD timeoutMs)
{
    DWORD startTime = GetTickCount();

    while (GetTickCount() - startTime < timeoutMs) {
        DWORD exitCode;
        if (GetExitCodeProcess(hProcess, &exitCode)) {
            if (exitCode == STILL_ACTIVE) {
                HMODULE hMod;
                DWORD cbNeeded;
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                    if (hMod != NULL) {
                        return true;
                    }
                }
            }
        }
        Sleep(100);
    }
    return false;
}

BOOL ManualInjector::WaitForProcessResponsive(HANDLE hProcess, DWORD timeoutMs)
{
    DWORD startTime = GetTickCount();

    while (GetTickCount() - startTime < timeoutMs) {
        // Try to wait for input idle (process is waiting for input)
        DWORD waitResult = WaitForInputIdle(hProcess, 100);
        if (waitResult == 0) {
            std::wcout << L"Process is responsive." << std::endl;
            return true;
        }
        else if (waitResult != WAIT_TIMEOUT) {
            // If it's not timeout, it might be an error or the process doesn't have a message queue
            break;
        }
        Sleep(100);
    }

    // Fallback: wait for process to have some modules loaded
    return WaitForProcessInitialization(hProcess, timeoutMs - (GetTickCount() - startTime));
}

DWORD WINAPI ManualInjector::LoadDll(PVOID p)
{
    PMANUAL_INJECT ManualInject = (PMANUAL_INJECT)p;

    HMODULE hModule;
    DWORD i, count;
    ULONG_PTR delta;

    PDWORD ptr;
    PWORD list;

    PIMAGE_BASE_RELOCATION pIBR;
    PIMAGE_IMPORT_DESCRIPTOR pIID;
    PIMAGE_IMPORT_BY_NAME pIBN;
    PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;

    PDLL_MAIN EntryPoint;

#ifdef _WIN64
    PIMAGE_NT_HEADERS64 pINH = (PIMAGE_NT_HEADERS64)ManualInject->NtHeaders;
#else
    PIMAGE_NT_HEADERS32 pINH = (PIMAGE_NT_HEADERS32)ManualInject->NtHeaders;
#endif

    pIBR = (PIMAGE_BASE_RELOCATION)ManualInject->BaseRelocation;
    delta = (ULONG_PTR)((LPBYTE)ManualInject->ImageBase - pINH->OptionalHeader.ImageBase);

    // Relocate the image
    if (pIBR && delta) {
        while (pIBR->VirtualAddress) {
            if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
                count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
                list = (PWORD)(pIBR + 1);

                for (i = 0; i < count; i++) {
                    if (list[i]) {
                        ptr = (PDWORD)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
#ifdef _WIN64
                        // For x64, we need to handle 64-bit relocations
                        ULONG_PTR* ptr64 = (ULONG_PTR*)ptr;
                        *ptr64 += delta;
#else
                        * ptr += (DWORD)delta;
#endif
                    }
                }
            }
            pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
        }
    }

    pIID = (PIMAGE_IMPORT_DESCRIPTOR)ManualInject->ImportDirectory;

    // Resolve DLL imports
    if (pIID) {
        while (pIID->Characteristics) {
            OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
            FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

            hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);

            if (!hModule) {
                return FALSE;
            }

            while (OrigFirstThunk->u1.AddressOfData) {
                ULONG_PTR Function;

                if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) {
                    // Import by ordinal
                    Function = (ULONG_PTR)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

                    if (!Function) {
                        return FALSE;
                    }

                    FirstThunk->u1.Function = Function;
                }
                else {
                    // Import by name
                    pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
                    Function = (ULONG_PTR)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

                    if (!Function) {
                        return FALSE;
                    }

                    FirstThunk->u1.Function = Function;
                }

                OrigFirstThunk++;
                FirstThunk++;
            }
            pIID++;
        }
    }

    if (pINH->OptionalHeader.AddressOfEntryPoint) {
        EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + pINH->OptionalHeader.AddressOfEntryPoint);
        return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
    }

    return TRUE;
}

DWORD WINAPI ManualInjector::LoadDllEnd()
{
    return 0;
}

BOOL ManualInjector::ValidateDll(PVOID buffer)
{
    PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)buffer;
    if (pIDH->e_magic != IMAGE_DOS_SIGNATURE)
    {
        printf("\nError: Invalid executable image.\n");
        return FALSE;
    }

    PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);
    if (pINH->Signature != IMAGE_NT_SIGNATURE)
    {
        printf("\nError: Invalid PE header.\n");
        return FALSE;
    }

    if (!(pINH->FileHeader.Characteristics & IMAGE_FILE_DLL))
    {
        printf("\nError: The image is not DLL.\n");
        return FALSE;
    }

    return TRUE;
}

BOOL ManualInjector::CopyDllToProcess(HANDLE hProcess, PVOID buffer, PVOID& image, BOOL isTarget64)
{
    PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)buffer;

    SIZE_T imageSize;
    if (isTarget64)
    {
        PIMAGE_NT_HEADERS64 pINH = (PIMAGE_NT_HEADERS64)((LPBYTE)buffer + pIDH->e_lfanew);
        imageSize = pINH->OptionalHeader.SizeOfImage;
    }
    else
    {
        PIMAGE_NT_HEADERS32 pINH = (PIMAGE_NT_HEADERS32)((LPBYTE)buffer + pIDH->e_lfanew);
        imageSize = pINH->OptionalHeader.SizeOfImage;
    }

    printf("\nAllocating memory for the DLL.\n");
    image = VirtualAllocEx(hProcess, NULL, imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!image)
    {
        printf("\nError: Unable to allocate memory for the DLL (%d)\n", GetLastError());
        return FALSE;
    }

    SIZE_T headersSize;
    if (isTarget64)
    {
        PIMAGE_NT_HEADERS64 pINH = (PIMAGE_NT_HEADERS64)((LPBYTE)buffer + pIDH->e_lfanew);
        headersSize = pINH->OptionalHeader.SizeOfHeaders;
    }
    else
    {
        PIMAGE_NT_HEADERS32 pINH = (PIMAGE_NT_HEADERS32)((LPBYTE)buffer + pIDH->e_lfanew);
        headersSize = pINH->OptionalHeader.SizeOfHeaders;
    }

    if (!WriteProcessMemory(hProcess, image, buffer, headersSize, NULL))
    {
        printf("\nError: Unable to copy headers to target process (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        return FALSE;
    }

    PIMAGE_SECTION_HEADER pISH = (PIMAGE_SECTION_HEADER)((LPBYTE)buffer + pIDH->e_lfanew + sizeof(IMAGE_NT_HEADERS));

    DWORD numberOfSections;
    if (isTarget64)
    {
        PIMAGE_NT_HEADERS64 pINH = (PIMAGE_NT_HEADERS64)((LPBYTE)buffer + pIDH->e_lfanew);
        numberOfSections = pINH->FileHeader.NumberOfSections;
    }
    else
    {
        PIMAGE_NT_HEADERS32 pINH = (PIMAGE_NT_HEADERS32)((LPBYTE)buffer + pIDH->e_lfanew);
        numberOfSections = pINH->FileHeader.NumberOfSections;
    }

    printf("\nCopying sections to target process.\n");
    for (DWORD i = 0; i < numberOfSections; i++)
    {
        WriteProcessMemory(hProcess, (PVOID)((LPBYTE)image + pISH[i].VirtualAddress),
            (PVOID)((LPBYTE)buffer + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, NULL);
    }

    return TRUE;
}

BOOL ManualInjector::SetupLoader(HANDLE hProcess, PVOID image, PVOID buffer, PVOID& mem1, BOOL isTarget64)
{
    PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)buffer;

    printf("\nAllocating memory for the loader code.\n");
    // Allocate more memory for x64 to accommodate larger structures and code
    SIZE_T loaderSize = isTarget64 ? 16384 : 8192;
    mem1 = VirtualAllocEx(hProcess, NULL, loaderSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!mem1)
    {
        printf("\nError: Unable to allocate memory for the loader code (%d)\n", GetLastError());
        return FALSE;
    }

    printf("\nLoader code allocated at %#p\n", mem1);

    MANUAL_INJECT ManualInject;
    memset(&ManualInject, 0, sizeof(MANUAL_INJECT));

    ManualInject.ImageBase = image;
    ManualInject.NtHeaders = (PVOID)((LPBYTE)image + pIDH->e_lfanew);

    if (isTarget64)
    {
        PIMAGE_NT_HEADERS64 pINH = (PIMAGE_NT_HEADERS64)((LPBYTE)buffer + pIDH->e_lfanew);
        ManualInject.BaseRelocation = (PVOID)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        ManualInject.ImportDirectory = (PVOID)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    }
    else
    {
        PIMAGE_NT_HEADERS32 pINH = (PIMAGE_NT_HEADERS32)((LPBYTE)buffer + pIDH->e_lfanew);
        ManualInject.BaseRelocation = (PVOID)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        ManualInject.ImportDirectory = (PVOID)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    }

    // IMPORTANT: These function pointers need to be resolved in the target process
    // For now, we'll write them as-is but they need proper resolution
    ManualInject.fnLoadLibraryA = LoadLibraryA;
    ManualInject.fnGetProcAddress = GetProcAddress;

    printf("\nWriting loader code to target process.\n");

    // Write ManualInject structure
    if (!WriteProcessMemory(hProcess, mem1, &ManualInject, sizeof(MANUAL_INJECT), NULL))
    {
        printf("\nError: Unable to write ManualInject structure (%d)\n", GetLastError());
        return FALSE;
    }

    // Write LoadDll function right after the structure
    PVOID loadDllAddr = (PVOID)((ULONG_PTR)mem1 + sizeof(MANUAL_INJECT));
    SIZE_T loadDllSize = (ULONG_PTR)LoadDllEnd - (ULONG_PTR)LoadDll;

    if (!WriteProcessMemory(hProcess, loadDllAddr, (PVOID)LoadDll, loadDllSize, NULL))
    {
        printf("\nError: Unable to write LoadDll function (%d)\n", GetLastError());
        return FALSE;
    }

    return TRUE;
}

BOOL ManualInjector::HijackThread(HANDLE hProcess, DWORD processId, PVOID mem1, BOOL isTarget64)
{
    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (!Thread32First(hSnap, &te32)) {
        CloseHandle(hSnap);
        return FALSE;
    }

    DWORD threadId = 0;
    do {
        if (te32.th32OwnerProcessID == processId) {
            threadId = te32.th32ThreadID;
            break;
        }
    } while (Thread32Next(hSnap, &te32));

    CloseHandle(hSnap);

    if (threadId == 0) {
        return FALSE;
    }

    printf("\nAllocating memory in target process.\n");
    PVOID mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!mem)
    {
        printf("\nError: Unable to allocate memory in target process (%d)", GetLastError());
        return FALSE;
    }

    printf("\nMemory allocated at %#p\n", mem);
    printf("\nOpening target thread handle.\n");

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, threadId);

    if (!hThread)
    {
        printf("\nError: Unable to open target thread handle (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("\nSuspending target thread.\n");
    SuspendThread(hThread);

    // Get thread context - IMPORTANT: Use CONTEXT_ALL for x64
    CONTEXT ctx = { 0 };
#ifdef _WIN64
    ctx.ContextFlags = CONTEXT_ALL;
#else
    ctx.ContextFlags = CONTEXT_FULL;
#endif

    if (!GetThreadContext(hThread, &ctx)) {
        printf("\nError: Unable to get thread context (%d)\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        return FALSE;
    }

    // Prepare shellcode - use larger buffer for x64
    char shellcode[1000];
    SIZE_T shellcodeSize = isTarget64 ? sizeof(shellcode_x64) : sizeof(shellcode_x86);
    memcpy(shellcode, isTarget64 ? shellcode_x64 : shellcode_x86, shellcodeSize);

    // Patch shellcode
#ifdef _WIN64
    constexpr DWORD64 PATTERN_RCX = 0xCCCCCCCCCCCCCCCC;
    constexpr DWORD64 PATTERN_RAX = 0xAAAAAAAAAAAAAAAA;
    const BYTE* const searchEnd = (LPBYTE)shellcode + 300;

    for (BYTE* ptr = (LPBYTE)shellcode; ptr < searchEnd; ptr++) {
        DWORD64 address = *(DWORD64*)ptr;

        if (address == PATTERN_RCX) {
            std::cout << "Writing param 1 (rcx)" << std::endl;
            *(DWORD64*)ptr = (DWORD64)mem1;
        }
        else if (address == PATTERN_RAX) {
            std::cout << "Writing function address (rax)" << std::endl;
            *(DWORD64*)ptr = (DWORD64)((PMANUAL_INJECT)mem1 + 1);
        }
    }
#else 
    constexpr BYTE OP_MOV_EAX = 0xb8;
    constexpr BYTE OP_PUSH = 0x68;
    constexpr BYTE OP_MOV_EDX = 0xba;
    constexpr BYTE OP_RET = 0xc3;
    constexpr DWORD PATTERN_CCCC = 0xCCCCCCCC;

    LPBYTE ptr = (LPBYTE)shellcode;
    while (1) {
        if (*ptr == OP_MOV_EAX && *(PDWORD)(ptr + 1) == PATTERN_CCCC) {
            *(PDWORD)(ptr + 1) = (DWORD)((PMANUAL_INJECT)mem1 + 1);
        }
        else if (*ptr == OP_PUSH && *(PDWORD)(ptr + 1) == PATTERN_CCCC) {
            *(PDWORD)(ptr + 1) = ctx.Eip;
        }
        else if (*ptr == OP_MOV_EDX && *(PDWORD)(ptr + 1) == PATTERN_CCCC) {
            *(PDWORD)(ptr + 1) = (DWORD)(mem1);
        }
        else if (*ptr == OP_RET) {
            ptr++;
            break;
        }
        ptr++;
    }
#endif

    printf("\nWriting shellcode into target process.\n");
    if (!WriteProcessMemory(hProcess, mem, shellcode, shellcodeSize, NULL)) {
        printf("\nError: Unable to write shellcode (%d)\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        return FALSE;
    }

    // Set new instruction pointer
#ifdef _WIN64
        ctx.Rip = (ULONG_PTR)mem;
#else
    ctx.Eip = (DWORD)mem;
#endif

    printf("\nHijacking target thread.\n");
    if (!SetThreadContext(hThread, &ctx)) {
        printf("\nError: Unable to hijack target thread (%d)\n", GetLastError());
        ResumeThread(hThread);
        CloseHandle(hThread);
        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("\nResuming target thread.\n");
    ResumeThread(hThread);
    CloseHandle(hThread);

    return TRUE;
}

BOOL ManualInjector::InjectDll(HANDLE hProcess, const char* DllPath)
{
    printf("\nOpening the DLL.\n");
    HANDLE hFile = CreateFileA(DllPath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    if (hFile == INVALID_HANDLE_VALUE)
    {
        printf("\nError: Unable to open the DLL (%d)\n", GetLastError());
        return FALSE;
    }

    DWORD FileSize = GetFileSize(hFile, NULL);
    PVOID buffer = VirtualAlloc(NULL, FileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

    if (!buffer)
    {
        printf("\nError: Unable to allocate memory for DLL data (%d)\n", GetLastError());
        CloseHandle(hFile);
        return FALSE;
    }

    DWORD read;
    if (!ReadFile(hFile, buffer, FileSize, &read, NULL))
    {
        printf("\nError: Unable to read the DLL (%d)\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(hFile);
        return FALSE;
    }
    CloseHandle(hFile);

    if (!ValidateDll(buffer))
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }

    BOOL isTarget64 = IsProcess64Bit(hProcess);
    BOOL isDll64 = IsDll64Bit(buffer);

    printf("\nArchitecture Detection:\n");
    printf("  Target Process: %s\n", isTarget64 ? "x64" : "x86");
    printf("  DLL: %s\n", isDll64 ? "x64" : "x86");

    if (isTarget64 != isDll64)
    {
        printf("\nError: Architecture mismatch! Cannot inject %s DLL into %s process.\n",
            isDll64 ? "x64" : "x86", isTarget64 ? "x64" : "x86");
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }

#ifndef _WIN64
    if (isTarget64)
    {
        printf("\nError: x86 injector cannot inject into x64 processes. Use x64 injector.\n");
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }
#endif

    BOOLEAN bl;
    RtlAdjustPrivilege(20, TRUE, FALSE, &bl);

    DWORD ProcessId = GetProcessId(hProcess);
    if (ProcessId == 0)
    {
        printf("\nError: Unable to get process ID from handle (%d)\n", GetLastError());
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("\nTarget process handle validated. Process ID: %d\n", ProcessId);

    PVOID image = nullptr;
    if (!CopyDllToProcess(hProcess, buffer, image, isTarget64))
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }

    PVOID mem1 = nullptr;
    if (!SetupLoader(hProcess, image, buffer, mem1, isTarget64))
    {
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }

    BOOL result = HijackThread(hProcess, ProcessId, mem1, isTarget64);

    VirtualFree(buffer, 0, MEM_RELEASE);

    if (result)
    {
        printf("\nInjection completed successfully!\n");
    }

    return result;
}

BOOL ManualInjector::CreateAndInject(const char* processPath, const char* dllPath, PROCESS_INFORMATION* pi)
{
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION localPi = { 0 };

    std::cout << "[+] Launching process: " << processPath << std::endl;

    if (!CreateProcessA(
        processPath,   // Application path
        NULL,          // Command line
        NULL,          // Process handle not inheritable
        NULL,          // Thread handle not inheritable
        FALSE,         // Set handle inheritance to FALSE
        0, // Create suspended
        NULL,          // Use parent's environment block
        NULL,          // Use parent's starting directory
        &si,           // Pointer to STARTUPINFO structure
        &localPi       // Pointer to PROCESS_INFORMATION structure
    ))
    {
        std::cout << "[-] Failed to launch process (" << GetLastError() << ")" << std::endl;
        return FALSE;
    }

    std::cout << "[+] Process launched successfully!" << std::endl;
    std::cout << "[+] Process ID: " << localPi.dwProcessId << std::endl;
    std::cout << "[+] Thread ID: " << localPi.dwThreadId << std::endl;

    std::cout << "[+] Waiting for process initialization..." << std::endl;
   if (!ManualInjector::WaitForProcessResponsive(localPi.hProcess, 2000))
    {
        std::cout << "[-] Process initialization timeout or failed" << std::endl;
        TerminateProcess(localPi.hProcess, 1);
        CloseHandle(localPi.hThread);
        CloseHandle(localPi.hProcess);
        return FALSE;
    }

    std::cout << "[+] Injecting " << dllPath << std::endl;

    BOOL injectionResult = InjectDll(localPi.hProcess, dllPath);

    if (injectionResult)
    {
        std::cout << "[+] Injection successful!" << std::endl;
        std::cout << "[+] Resuming process..." << std::endl;
        ResumeThread(localPi.hThread);
    }
    else
    {
        std::cout << "[-] Injection failed!" << std::endl;
        std::cout << "[-] Terminating process..." << std::endl;
        TerminateProcess(localPi.hProcess, 1);
    }

    if (pi)
    {
        *pi = localPi;
    }
    else
    {
        CloseHandle(localPi.hThread);
        CloseHandle(localPi.hProcess);
    }

    return injectionResult;
}