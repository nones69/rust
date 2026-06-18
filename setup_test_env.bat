@echo off
echo Setting up IntentKernel Virtual Test Environment

:: Check if we have VirtualBox or another virtualization tool
where VBoxManage >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo VirtualBox not found. Please install VirtualBox to create a virtual test environment.
    echo Continuing with local build only...
    goto :build_local
)

echo VirtualBox found. Setting up virtual environment...

:: Create a virtual environment for testing
echo This script will create a minimal virtual machine to test IntentKernel.
echo Press any key to continue or Ctrl+C to cancel...
pause >nul

:: Build the project first
:build_local
echo Building IntentKernel locally first...

:: Try to detect which compiler is available
where cl >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo Visual Studio compiler found, using MSVC build...
    call build_vs.bat
    goto :build_complete
)

where gcc >nul 2>&1
if %ERRORLEVEL% equ 0 (
    echo GCC compiler found, using MinGW build...
    call build_mingw.bat
    goto :build_complete
)

echo No compatible compiler found. Please install Visual Studio or MinGW.
exit /b 1

:build_complete
echo Local build completed.

:: Check if VirtualBox is available for VM testing
where VBoxManage >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Skipping virtual environment setup as VirtualBox is not installed.
    echo You can run the test harness locally with: test_harness.exe
    exit /b 0
)

:: Set up VM for testing
echo Setting up virtual machine for IntentKernel testing...
echo This will create a minimal Linux VM to test the capability system.

:: VM setup would go here - this is a placeholder
echo Virtual machine setup requires manual intervention.
echo Please follow these steps:
echo 1. Create a minimal Linux VM in VirtualBox
echo 2. Share this folder with the VM
echo 3. Inside the VM, navigate to the shared folder
echo 4. Compile the project with: gcc -o test_harness src/test_harness.c src/reference/capability_core_modified.c -Isrc
echo 5. Run the test harness with: ./test_harness

echo For now, you can test locally by running: test_harness.exe