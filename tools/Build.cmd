@ECHO OFF

WHERE /Q "dotnet.exe"
IF %ERRORLEVEL% GEQ 1 (
    ECHO [DecodeWheaRecord] Unable to build as dotnet was not found.
    EXIT /B 1
)

@REM Switch to repository root directory
PUSHD "%~dp0\.."

@REM Default MSBuild arguments (via dotnet build)
SET MSBuildSln=DecodeWheaRecord.sln
SET MSBuildArgs=-noLogo -verbosity:minimal -maxCpuCount
SET MSBuildTarget=Build

@REM Optional first arg is build target
IF NOT "%1" == "" SET MSBuildTarget=%1

@REM MSBuild swallows the first new-line
dotnet.exe build -version
ECHO.
ECHO.

ECHO [DecodeWheaRecord] Running target "%MSBuildTarget%" for Debug ...
dotnet build %MSBuildSln% %MSBuildArgs% -t:%MSBuildTarget% -p:Configuration=Debug
IF %ERRORLEVEL% GEQ 1 GOTO End
ECHO.

ECHO [DecodeWheaRecord] Running target "%MSBuildTarget%" for Release ...
dotnet build %MSBuildSln% %MSBuildArgs% -t:%MSBuildTarget% -p:Configuration=Release
IF %ERRORLEVEL% GEQ 1 GOTO End
ECHO.

:End
@REM Clean-up script variables
SET MSBuildSln=
SET MSBuildArgs=
SET MSBuildTarget=

@REM Restore original directory
POPD
