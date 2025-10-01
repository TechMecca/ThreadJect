# ThreadJect

A professional manual DLL injection tool that uses thread hijacking to inject DLLs into target processes.

## Features

- **Manual DLL Injection**: Uses manual mapping to load DLLs without `LoadLibrary`
- **Thread Hijacking**: Hijacks existing threads for code execution
- **Process Creation**: Can launch processes in suspended state and inject DLLs
- **Process Initialization Waits**: Ensures target process is properly initialized before injection
- **x86 Support**: Currently supports 32-bit processes (x86 shellcode)
- **Clean C++ Interface**: Object-oriented design with static methods

## How It Works

1. **Process Creation**: Launches the target process in suspended state
2. **DLL Loading**: Reads and validates the DLL file
3. **Memory Allocation**: Allocates memory in the target process for the DLL and loader
4. **Manual Mapping**: Copies DLL sections and performs relocations/import resolution
5. **Thread Hijacking**: Finds a thread in the target process and hijacks it to execute the loader
6. **Process Resumption**: Resumes the process after successful injection

## Building

### Requirements
- Visual Studio 2019 or later
- CMake 3.12 or later
- Windows SDK

### Build Steps
```bash
mkdir build
cd build
cmake ..
cmake --build . --config Release
```

## Usage

### Basic Injection
```powershell
# Inject into existing process by PID
.\ThreadJect.exe 1234 "C:\path\to\your.dll"

# Launch process and inject DLL
.\ThreadJect.exe "C:\Windows\System32\notepad.exe" "C:\path\to\your.dll"
```

### Programmatic Usage
```cpp
#include "ManualInject.h"

// Inject into existing process
HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
ManualInjector::InjectDll(hProcess, "C:\\path\\to\\dll.dll");
CloseHandle(hProcess);

// Or create process and inject
ManualInjector::CreateAndInject("target.exe", "inject.dll");
```

## API Reference

### ManualInjector Class

#### Static Methods

- `BOOL InjectDll(HANDLE hProcess, const char* DllPath)`
  - Injects DLL into an existing process
  - `hProcess`: Handle to target process with appropriate access rights
  - `DllPath`: Full path to the DLL file
  - Returns: `TRUE` on success, `FALSE` on failure

- `BOOL CreateAndInject(const char* processPath, const char* dllPath, PROCESS_INFORMATION* pi = nullptr)`
  - Launches a process and injects DLL
  - `processPath`: Full path to the executable
  - `dllPath`: Full path to the DLL file
  - `pi`: Optional pointer to receive PROCESS_INFORMATION
  - Returns: `TRUE` on success, `FALSE` on failure

## Technical Details

### Manual Mapping Process
1. **PE Header Validation**: Verifies DOS and NT headers
2. **Memory Allocation**: Allocates memory in target process for DLL image
3. **Section Copying**: Copies all DLL sections to target process
4. **Base Relocation**: Performs image base relocations
5. **Import Resolution**: Resolves all imported functions
6. **TLS Callbacks**: Executes TLS callbacks (if any)
7. **DLL Entry Point**: Calls `DllMain` with `DLL_PROCESS_ATTACH`

### Thread Hijacking
- Suspends a target thread
- Saves original thread context
- Injects shellcode to call the manual mapper
- Restores execution with modified context
- Resumes the thread

### Process Initialization
The injector includes two wait mechanisms:
- **WaitForProcessInitialization**: Waits for the process to load its main module
- **WaitForProcessResponsive**: Waits for the process to become responsive (message queue)

## Limitations

- **x86 Only**: Current shellcode implementation is for 32-bit processes only
- **Administrator Rights**: May require elevated privileges for some processes
- **Anti-Cheat Software**: May be detected by anti-cheat systems
- **Process Compatibility**: Some protected processes may not be injectable

## Security Notes

⚠️ **This tool is for educational and legitimate purposes only**

- Use only on processes you own or have permission to modify
- May be detected as malware by antivirus software
- Not recommended for use with games protected by anti-cheat systems
- Use responsibly and ethically

## Legal Disclaimer

This software is provided for educational purposes only. The authors are not responsible for any misuse of this tool. Users are solely responsible for ensuring they have proper authorization before injecting code into any process.

## License

MIT License - See LICENSE file for details

## Contributing

Contributions are welcome! Please feel free to submit pull requests for:
- x64 support
- Bug fixes
- Additional features
- Documentation improvements

## Support

For issues and questions:
1. Check existing GitHub issues
2. Create a new issue with detailed description
3. Include error messages and system information

---

**Note**: Always test in controlled environments and ensure you comply with all applicable laws and terms of service.
