
@echo off
cd /d "C:\Users\kadava\Desktop\tindahan-pos"
if not exist "server.js" (
    echo ERROR: server.js was not found.
    pause
    exit /b 1
)
"C:\Program Files\nodejs\node.exe" server.js
pause
