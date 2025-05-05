# Simple Shellcode Loader Project

A modular and stealthy shellcode loader for Windows platforms. This project demonstrates various techniques used for shellcode delivery, anti-analysis, and process injection.

## Features

- **Modular Design**: Code is organized into separate modules for better maintainability
- **Multiple Injection Methods**:
  - Standard CreateRemoteThread method
  - NtCreateThreadEx method (stealthier)
  - QueueUserAPC method (most stealthy)
- **Anti-Analysis Techniques**:
  - Debugger detection
  - Virtual Machine detection
  - Timing-based analysis evasion
  - Memory pollution
  - PEB flags detection
- **Dynamic API Resolution**: Avoids static API imports for better evasion
- **XOR Encryption**: Simple shellcode encryption to evade static detection

## Project Structure

```
shellcode_loader/
├── include/           # Header files
│   ├── dynamic_api.h
│   ├── anti_analysis.h
│   ├── process_injection.h
│   ├── encryption.h
│   └── shellcode.h
├── src/               # Source files
│   ├── main.c
│   ├── dynamic_api.c
│   ├── anti_analysis.c
│   ├── process_injection.c
│   ├── encryption.c
│   └── shellcode.c
└── bin/               # Compiled binaries
```

## Building

This project requires:
- GCC or compatible compiler
- Windows development environment
- IPHelper API (for network adapter checks)

To build the project:

```bash
make
```

## Configuration

You can modify the following settings in `src/main.c`:

```c
// Configuration settings
#define USE_XOR_ENCRYPTION 1
#define USE_DYNAMIC_SYSCALLS 1
#define PROCESS_INJECTION_METHOD 2 // 1=CreateRemoteThread, 2=NtCreateThreadEx, 3=QueueUserAPC
```

## Usage

1. Replace the shellcode in `src/shellcode.c` with your own
2. Build the project
3. Run the resulting executable in `bin/` directory

## Disclaimer

This project is provided for **educational purposes only**. Use of this code for attacking targets without prior mutual consent is illegal. It is the end user's responsibility to obey all applicable laws. The developers assume no liability and are not responsible for any misuse or damage caused by this program.

## License

This project is licensed under the MIT License - see the LICENSE file for details. 