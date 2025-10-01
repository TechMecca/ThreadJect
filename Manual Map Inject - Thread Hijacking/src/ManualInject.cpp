#include "ManualInject.h"
#include <stdio.h>
#include <iostream>

#pragma comment(lib,"ntdll.lib")
#pragma comment(lib,"psapi.lib")

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

char ManualInjector::shellcode[] =
{
    0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x81, 0xEB, 0x06, 0x00, 0x00, 0x00, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC,
    0xBA, 0xCC, 0xCC, 0xCC, 0xCC, 0x52, 0xFF, 0xD0, 0x61, 0x68, 0xCC, 0xCC, 0xCC, 0xCC, 0xC3
}; // x86 ONLY shellcode - will need to change for x64

// Wait for the main thread to start executing (process initialization)
BOOL ManualInjector::WaitForProcessInitialization(HANDLE hProcess, DWORD timeoutMs)
{
    DWORD startTime = GetTickCount();

    while (GetTickCount() - startTime < timeoutMs) {
        DWORD exitCode;
        if (GetExitCodeProcess(hProcess, &exitCode)) {
            if (exitCode == STILL_ACTIVE) {
                // Check if the process has loaded its main module
                HMODULE hMod;
                DWORD cbNeeded;
                if (EnumProcessModules(hProcess, &hMod, sizeof(hMod), &cbNeeded)) {
                    if (hMod != NULL) {
                        std::cout << "Process initialized successfully." << std::endl;
                        return true;
                    }
                }
            }
        }
        Sleep(100);
    }
    std::cerr << "Timeout waiting for process initialization." << std::endl;
    return false;
}

// Wait for the process to become responsive
BOOL ManualInjector::WaitForProcessResponsive(HANDLE hProcess, DWORD timeoutMs)
{
    DWORD startTime = GetTickCount();

    while (GetTickCount() - startTime < timeoutMs) {
        // Try to wait for input idle (process is waiting for input)
        DWORD waitResult = WaitForInputIdle(hProcess, 100);
        if (waitResult == 0) {
            std::cout << "Process is responsive." << std::endl;
            return true;
        }
        else if (waitResult != WAIT_TIMEOUT) {
            // If it's not timeout, it might be an error or the process doesn't have a message queue
            break;
        }
        Sleep(100);
    }

    // Fallback: wait for process to have some modules loaded
    DWORD remainingTime = timeoutMs - (GetTickCount() - startTime);
    if (remainingTime > 0) {
        return WaitForProcessInitialization(hProcess, remainingTime);
    }

    return false;
}

DWORD WINAPI ManualInjector::LoadDll(PVOID p)
{
    PMANUAL_INJECT ManualInject = (PMANUAL_INJECT)p;

    HMODULE hModule;
    DWORD i, Function, count, delta;

    PDWORD ptr;
    PWORD list;

    PIMAGE_BASE_RELOCATION pIBR;
    PIMAGE_IMPORT_DESCRIPTOR pIID;
    PIMAGE_IMPORT_BY_NAME pIBN;
    PIMAGE_THUNK_DATA FirstThunk, OrigFirstThunk;

    PDLL_MAIN EntryPoint;

    pIBR = ManualInject->BaseRelocation;
    delta = (DWORD)((LPBYTE)ManualInject->ImageBase - ManualInject->NtHeaders->OptionalHeader.ImageBase);

    // Relocate the image
    while (pIBR->VirtualAddress)
    {
        if (pIBR->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION))
        {
            count = (pIBR->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            list = (PWORD)(pIBR + 1);

            for (i = 0; i < count; i++)
            {
                if (list[i])
                {
                    ptr = (PDWORD)((LPBYTE)ManualInject->ImageBase + (pIBR->VirtualAddress + (list[i] & 0xFFF)));
                    *ptr += delta;
                }
            }
        }
        pIBR = (PIMAGE_BASE_RELOCATION)((LPBYTE)pIBR + pIBR->SizeOfBlock);
    }

    pIID = ManualInject->ImportDirectory;

    // Resolve DLL imports
    while (pIID->Characteristics)
    {
        OrigFirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->OriginalFirstThunk);
        FirstThunk = (PIMAGE_THUNK_DATA)((LPBYTE)ManualInject->ImageBase + pIID->FirstThunk);

        hModule = ManualInject->fnLoadLibraryA((LPCSTR)ManualInject->ImageBase + pIID->Name);

        if (!hModule)
        {
            return FALSE;
        }

        while (OrigFirstThunk->u1.AddressOfData)
        {
            if (OrigFirstThunk->u1.Ordinal & IMAGE_ORDINAL_FLAG)
            {
                // Import by ordinal
                Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)(OrigFirstThunk->u1.Ordinal & 0xFFFF));

                if (!Function)
                {
                    return FALSE;
                }

                FirstThunk->u1.Function = Function;
            }
            else
            {
                // Import by name
                pIBN = (PIMAGE_IMPORT_BY_NAME)((LPBYTE)ManualInject->ImageBase + OrigFirstThunk->u1.AddressOfData);
                Function = (DWORD)ManualInject->fnGetProcAddress(hModule, (LPCSTR)pIBN->Name);

                if (!Function)
                {
                    return FALSE;
                }

                FirstThunk->u1.Function = Function;
            }

            OrigFirstThunk++;
            FirstThunk++;
        }
        pIID++;
    }

    if (ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint)
    {
        EntryPoint = (PDLL_MAIN)((LPBYTE)ManualInject->ImageBase + ManualInject->NtHeaders->OptionalHeader.AddressOfEntryPoint);
        return EntryPoint((HMODULE)ManualInject->ImageBase, DLL_PROCESS_ATTACH, NULL);
    }

    return TRUE;
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

BOOL ManualInjector::CopyDllToProcess(HANDLE hProcess, PVOID buffer, PVOID& image)
{
    PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);

    printf("\nAllocating memory for the DLL.\n");
    image = VirtualAllocEx(hProcess, NULL, pINH->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!image)
    {
        printf("\nError: Unable to allocate memory for the DLL (%d)\n", GetLastError());
        return FALSE;
    }

    // Copy the header to target process
    printf("\nCopying headers into target process.\n");
    if (!WriteProcessMemory(hProcess, image, buffer, pINH->OptionalHeader.SizeOfHeaders, NULL))
    {
        printf("\nError: Unable to copy headers to target process (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        return FALSE;
    }

    PIMAGE_SECTION_HEADER pISH = (PIMAGE_SECTION_HEADER)(pINH + 1);

    // Copy the DLL to target process
    printf("\nCopying sections to target process.\n");
    for (DWORD i = 0; i < pINH->FileHeader.NumberOfSections; i++)
    {
        WriteProcessMemory(hProcess, (PVOID)((LPBYTE)image + pISH[i].VirtualAddress),
            (PVOID)((LPBYTE)buffer + pISH[i].PointerToRawData), pISH[i].SizeOfRawData, NULL);
    }

    return TRUE;
}

BOOL ManualInjector::SetupLoader(HANDLE hProcess, PVOID image, PVOID buffer, PVOID& mem1)
{
    PIMAGE_DOS_HEADER pIDH = (PIMAGE_DOS_HEADER)buffer;
    PIMAGE_NT_HEADERS pINH = (PIMAGE_NT_HEADERS)((LPBYTE)buffer + pIDH->e_lfanew);

    printf("\nAllocating memory for the loader code.\n");
    mem1 = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!mem1)
    {
        printf("\nError: Unable to allocate memory for the loader code (%d)\n", GetLastError());
        return FALSE;
    }

    printf("\nLoader code allocated at %#x\n", mem1);

    MANUAL_INJECT ManualInject;
    memset(&ManualInject, 0, sizeof(MANUAL_INJECT));

    ManualInject.ImageBase = image;
    ManualInject.NtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)image + pIDH->e_lfanew);
    ManualInject.BaseRelocation = (PIMAGE_BASE_RELOCATION)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
    ManualInject.ImportDirectory = (PIMAGE_IMPORT_DESCRIPTOR)((LPBYTE)image + pINH->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    ManualInject.fnLoadLibraryA = LoadLibraryA;
    ManualInject.fnGetProcAddress = GetProcAddress;

    printf("\nWriting loader code to target process.\n");
    WriteProcessMemory(hProcess, mem1, &ManualInject, sizeof(MANUAL_INJECT), NULL);
    WriteProcessMemory(hProcess, (PVOID)((PMANUAL_INJECT)mem1 + 1), LoadDll, (DWORD)LoadDll, NULL);

    return TRUE;
}

BOOL ManualInjector::HijackThread(HANDLE hProcess, DWORD processId, PVOID mem1)
{
    THREADENTRY32 te32;
    te32.dwSize = sizeof(te32);

    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;

    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    Thread32First(hSnap, &te32);
    printf("\nFinding a thread to hijack.\n");

    while (Thread32Next(hSnap, &te32))
    {
        if (te32.th32OwnerProcessID == processId)
        {
            printf("\nTarget thread found. Thread ID: %d\n", te32.th32ThreadID);
            break;
        }
    }
    CloseHandle(hSnap);

    printf("\nAllocating memory in target process.\n");
    PVOID mem = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

    if (!mem)
    {
        printf("\nError: Unable to allocate memory in target process (%d)", GetLastError());
        return FALSE;
    }

    printf("\nMemory allocated at %#x\n", mem);
    printf("\nOpening target thread handle.\n");

    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);

    if (!hThread)
    {
        printf("\nError: Unable to open target thread handle (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("\nSuspending target thread.\n");
    SuspendThread(hThread);
    GetThreadContext(hThread, &ctx);

    PVOID shellcodeBuffer = VirtualAlloc(NULL, 65536, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    LPBYTE ptr = (LPBYTE)shellcodeBuffer;

    memcpy(shellcodeBuffer, shellcode, sizeof(shellcode));

    while (1)
    {
        if (*ptr == 0xb8 && *(PDWORD)(ptr + 1) == 0xCCCCCCCC)
        {
            *(PDWORD)(ptr + 1) = (DWORD)((PMANUAL_INJECT)mem1 + 1);
        }

        if (*ptr == 0x68 && *(PDWORD)(ptr + 1) == 0xCCCCCCCC)
        {
            *(PDWORD)(ptr + 1) = ctx.Eip;
        }

        if (*ptr == 0xba && *(PDWORD)(ptr + 1) == 0xCCCCCCCC)
        {
            *(PDWORD)(ptr + 1) = (DWORD)(mem1);
        }

        if (*ptr == 0xc3)
        {
            ptr++;
            break;
        }
        ptr++;
    }

    printf("\nWriting shellcode into target process.\n");
    if (!WriteProcessMemory(hProcess, mem, shellcodeBuffer, sizeof(shellcode), NULL))
    {
        printf("\nError: Unable to write shellcode into target process (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        VirtualFree(shellcodeBuffer, 0, MEM_RELEASE);
        return FALSE;
    }

    ctx.Eip = (DWORD)mem;

    printf("\nHijacking target thread.\n");
    if (!SetThreadContext(hThread, &ctx))
    {
        printf("\nError: Unable to hijack target thread (%d)\n", GetLastError());
        VirtualFreeEx(hProcess, mem, 0, MEM_RELEASE);
        ResumeThread(hThread);
        CloseHandle(hThread);
        VirtualFree(shellcodeBuffer, 0, MEM_RELEASE);
        return FALSE;
    }

    printf("\nResuming target thread.\n");
    ResumeThread(hThread);

    CloseHandle(hThread);
    VirtualFree(shellcodeBuffer, 0, MEM_RELEASE);

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
    if (!CopyDllToProcess(hProcess, buffer, image))
    {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }

    PVOID mem1 = nullptr;
    if (!SetupLoader(hProcess, image, buffer, mem1))
    {
        VirtualFreeEx(hProcess, image, 0, MEM_RELEASE);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }

    BOOL result = HijackThread(hProcess, ProcessId, mem1);

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
        0, 
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

    // Wait for process to initialize before injection
    std::cout << "[+] Waiting for process initialization..." << std::endl;
    if (!WaitForProcessResponsive(localPi.hProcess))
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

        // Wait for process to become responsive before resuming
        std::cout << "[+] Waiting for process to become responsive..." << std::endl;
        WaitForProcessResponsive(localPi.hProcess, 3000);

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