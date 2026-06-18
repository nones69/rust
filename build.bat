@echo off
echo Building IntentKernel...

:: Create build directory if it doesn't exist
if not exist build mkdir build

:: Compile capability_core.c
echo Compiling capability_core_modified.c...
cl /c /Wall /Isrc /Fosrc\reference\capability_core_modified.obj src\reference\capability_core_modified.c
if %ERRORLEVEL% neq 0 (
    echo Failed to compile capability_core_modified.c
    exit /b 1
)

:: Compile test_harness.c
echo Compiling test_harness.c...
cl /c /Wall /Isrc /Fosrc\test_harness.obj src\test_harness.c
if %ERRORLEVEL% neq 0 (
    echo Failed to compile test_harness.c
    exit /b 1
)

:: Link everything
echo Linking...
cl /Fetest_harness.exe src\test_harness.obj src\reference\capability_core_modified.obj
if %ERRORLEVEL% neq 0 (
    echo Failed to link
    exit /b 1
)

echo Build complete. Run test_harness.exe to test the capability system.