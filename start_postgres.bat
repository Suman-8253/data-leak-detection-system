@echo off
echo Starting local PostgreSQL server...
"%~dp0pgsql\bin\pg_ctl.exe" -D "%~dp0pgsql\data" -l "%~dp0pgsql\logfile" start
if %ERRORLEVEL% equ 0 (
    echo PostgreSQL server is running on localhost:5433!
) else (
    echo Note: If PostgreSQL is already running, you can proceed directly.
)
pause
