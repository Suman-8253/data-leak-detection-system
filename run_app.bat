@echo off
echo Starting Data Leak Detection & SQL Injection Prevention System...
cd /d "%~dp0data_leak_detection"
python app.py
pause
