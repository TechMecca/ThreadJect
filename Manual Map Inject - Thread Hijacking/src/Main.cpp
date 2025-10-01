#include <iostream>
#include <string>
#include <windows.h>
#include <ManualInject.h>

int main(int argc, char* argv[])
{
    if (argc != 3)
    {
        std::cout << "Usage: ThreadJect [Process Path] [DLL path]" << std::endl;
        return 1;
    }

    const char* processPath = argv[1];
    const char* dllPath = argv[2];

    if (ManualInjector::CreateAndInject(processPath, dllPath))
    {
        std::cout << "[+] Process launched and injected successfully!" << std::endl;
        return 0;
    }
    else
    {
        std::cout << "[-] Failed to launch and inject process!" << std::endl;
        return 1;
    }
}