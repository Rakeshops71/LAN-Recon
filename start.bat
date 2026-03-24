@echo off
title LAN Recon Launcher
color 0B
echo ===================================================
echo             LAN RECON COMBINED LAUNCHER
echo ===================================================
echo.
echo [1/3] Ensuring Java packet sniffer is compiled...
cd lanrecon
call mvn compile
cd ..

echo.
echo [2/3] Starting React Frontend (UI)...
cd lanrecon-ui
start "LAN Recon UI" cmd /k "npm start"
cd ..

echo.
echo [3/3] Starting Node Server and Java Sniffer...
echo       (This requires Administrator Privileges for network packet capture)
cd lanrecon-server
powershell -Command "Start-Process node -ArgumentList 'server.js' -WorkingDirectory '%cd%' -Verb RunAs"
cd ..

echo.
echo ===================================================
echo ALL SYSTEMS FIRING! 
echo ===================================================
echo 1. The React app is spinning up in a new window and will open your browser at localhost:3000.
echo 2. The Node Server is opening in a blue Administrator window to capture live packets.
echo.
echo You can safely close this launcher window now!
pause
