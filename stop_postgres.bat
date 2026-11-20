@echo off
echo Stopping local PostgreSQL server...
"%~dp0pgsql\bin\pg_ctl.exe" -D "%~dp0pgsql\data" stop
echo PostgreSQL server stopped.
pause
