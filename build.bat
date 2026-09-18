@echo off
setlocal enabledelayedexpansion

set MSBUILD=
if exist "D:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=D:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
if "%MSBUILD%"=="" if exist "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
if "%MSBUILD%"=="" if exist "C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe" set "MSBUILD=C:\Program Files\Microsoft Visual Studio\2022\Community\MSBuild\Current\Bin\MSBuild.exe"
if "%MSBUILD%"=="" if exist "C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe" set "MSBUILD=C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"

if "%MSBUILD%"=="" (
    echo [ERROR] MSBuild.exe not found!
    exit /b 1
)

echo [1/3] Using compiler:
echo %MSBUILD%
echo.

echo [2/3] Compiling AngelMineChecker.csproj (Release)...
"%MSBUILD%" AngelMineChecker.csproj /p:Configuration=Release /nologo /v:m
if errorlevel 1 (
    echo [ERROR] Compilation failed!
    exit /b 1
)

echo.
echo [3/3] Copying tools and icons to bin\Release...
if exist "tools" (
    if not exist "bin\Release\tools" mkdir "bin\Release\tools"
    xcopy "tools" "bin\Release\tools\" /E /I /Y /Q > nul
)
if exist "icons" (
    if not exist "bin\Release\icons" mkdir "bin\Release\icons"
    xcopy "icons" "bin\Release\icons\" /E /I /Y /Q > nul
)

echo.
echo ====================================================
echo [SUCCESS] Build finished!
echo Output: bin\Release\AngelMineChecker.exe
echo ====================================================