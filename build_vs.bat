@echo off
echo Building IntentKernel with Visual Studio...

:: Create build directory if it doesn't exist
if not exist build mkdir build

:: Set up Visual Studio environment if needed
:: Uncomment and modify the line below if the Visual Studio environment is not set up
:: call "C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"

:: Add debug symbols and define DEBUG for debug builds
set EXTRA_FLAGS=
if "%1"=="debug" (
    echo Building in DEBUG mode
    set EXTRA_FLAGS=/DDEBUG /Zi
)

:: Compile capability_core_modified.c
echo Compiling capability_core_modified.c...
cl /c /W4 /Isrc %EXTRA_FLAGS% /Fobuild\capability_core.obj src\reference\capability_core_modified.c
if %ERRORLEVEL% neq 0 (
    echo Failed to compile capability_core_modified.c
    exit /b 1
)

:: Compile test_harness.c
echo Compiling test_harness.c...
cl /c /W4 /Isrc %EXTRA_FLAGS% /Fobuild\test_harness.obj src\test_harness.c
if %ERRORLEVEL% neq 0 (
    echo Failed to compile test_harness.c
    exit /b 1
)

:: Link everything
echo Linking...
cl /Fetest_harness.exe %EXTRA_FLAGS% build\test_harness.obj build\capability_core.obj
if %ERRORLEVEL% neq 0 (
    echo Failed to link
    exit /b 1
)

echo Build complete. Run test_harness.exe to test the capability system.