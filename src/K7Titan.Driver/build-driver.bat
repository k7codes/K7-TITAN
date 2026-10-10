@echo off
setlocal
set "VCVARS=C:\Program Files\Microsoft Visual Studio\2022\Community\VC\Auxiliary\Build\vcvars64.bat"
set "KIT=C:\Program Files (x86)\Windows Kits\10"
set "KM=%KIT%\Include\10.0.28000.0\km"
set "SHARED=%KIT%\Include\10.0.28000.0\shared"
set "KMLIB=%KIT%\Lib\10.0.28000.0\km\x64"
cd /d "%~dp0"

call "%VCVARS%" >nul 2>&1
if not exist obj mkdir obj

cl /c /nologo /kernel /W4 /wd4324 /D_AMD64_ /DAMD64 /D_WIN64 /DNT_PROCESSOR_GROUPS ^
   /I"%KM%" /I"%SHARED%" /Foobj\ k7titan_filter.c
if errorlevel 1 goto :fail

link /nologo /driver /subsystem:native /entry:DriverEntry /out:k7titan_filter.sys ^
     obj\k7titan_filter.obj ^
     "%KMLIB%\fltMgr.lib" "%KMLIB%\ntoskrnl.lib" "%KMLIB%\hal.lib" ^
     "%KMLIB%\wmilib.lib" "%KMLIB%\BufferOverflowK.lib"
if errorlevel 1 goto :fail

echo DRIVER BUILD OK
exit /b 0

:fail
echo DRIVER BUILD FAILED
exit /b 1
