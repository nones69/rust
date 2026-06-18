@echo off
echo Building IntentKernel with MinGW...

:: Create build directory if it doesn't exist
if not exist build mkdir build

:: Add debug symbols and define DEBUG for debug builds
set EXTRA_FLAGS=
if "%1"=="debug" (
    echo Building in DEBUG mode
    set EXTRA_FLAGS=-DDEBUG -g
)

:: Compile capability_core_modified.c
echo Compiling capability_core_modified.c...
gcc -Wall -Wextra -pedantic -std=c11 -Isrc %EXTRA_FLAGS% -c -o build\capability_core.o src\reference\capability_core_modified.c
if %ERRORLEVEL% neq 0 (
    echo Failed to compile capability_core_modified.c
    exit /b 1
)

:: Compile test_harness.c
echo Compiling test_harness.c...
gcc -Wall -Wextra -pedantic -std=c11 -Isrc %EXTRA_FLAGS% -c -o build\test_harness.o src\test_harness.c
if %ERRORLEVEL% neq 0 (
    echo Failed to compile test_harness.c
    exit /b 1
)

:: Link everything
echo Linking...
gcc -o test_harness.exe %EXTRA_FLAGS% build\test_harness.o build\capability_core.o
if %ERRORLEVEL% neq 0 (
    echo Failed to link
    exit /b 1
)

echo Build complete. Run test_harness.exe to test the capability system.