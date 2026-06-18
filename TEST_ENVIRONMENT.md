# IntentKernel Test Environment

This repository contains the IntentKernel capability-secure execution architecture, a reference implementation designed to replace traditional permission models with event-scoped authority.

## Project Overview

IntentKernel is a security architecture that eliminates ambient authority across all device classes. Instead of persistent permissions granted at install time, IntentKernel uses Event-Scoped Authority where power is granted only at the moment of verified user intent and expires automatically when the task completes.

## Quick Start

To build and run the IntentKernel reference implementation:

### Windows with Visual Studio

```batch
build_vs.bat
test_harness.exe
```

### Windows with MinGW

```batch
build_mingw.bat
test_harness.exe
```

### Debug Build

For debugging with symbols:

```batch
build_vs.bat debug
```

or

```batch
build_mingw.bat debug
```

## VS Code Integration

This project includes VS Code configuration for building and debugging:

1. Open the project in VS Code
2. Go to Run and Debug (Ctrl+Shift+D)
3. Select "IntentKernel (MSVC)" or "IntentKernel (MinGW)" from the dropdown
4. Press F5 to build and debug

## Testing in a Virtual Environment

To test IntentKernel in a virtual environment:

```batch
setup_test_env.bat
```

This script will:
1. Build the project locally
2. Check for VirtualBox installation
3. Provide instructions for setting up a test VM

## Project Structure

- `src/reference/capability_core.c` - Original reference implementation
- `src/reference/capability_core_modified.c` - Modified implementation for testing
- `src/reference/capability_core.h` - Header file with capability definitions
- `src/test_harness.c` - Test program demonstrating the capability system
- `build_vs.bat` - Build script for Visual Studio
- `build_mingw.bat` - Build script for MinGW
- `setup_test_env.bat` - Script to set up testing environment

## What the Test Harness Demonstrates

The test harness demonstrates the core capability security model:

1. **Capability Creation**: Creates file and network capabilities with different TTLs and use counts
2. **Capability Validation**: Shows how capabilities are validated and consumed
3. **Single-Use Capabilities**: Demonstrates how capabilities automatically expire after use
4. **Capability Revocation**: Shows how capabilities can be manually revoked

## System Requirements

- Windows 10/11
- Either Visual Studio or MinGW (GCC for Windows)
- VS Code (optional, for IDE integration)
- VirtualBox (optional, for virtual environment testing)

## Architecture Overview

IntentKernel follows a layered architecture:

1. **IntentKernel (Execution Model)** - Core capability rules (this reference implementation)
2. **UCCS (Universal Capability Computing Substrate)** - Hardware abstraction layer
3. **IKRL (IntentKernel Relief Layer)** - Compatibility layer for existing OSes
4. **IBPS (Intent Broker Protocol Specification)** - Communication standard

The reference implementation focuses on the core capability system, demonstrating how authority is granted, validated, and revoked in a capability-secure system.