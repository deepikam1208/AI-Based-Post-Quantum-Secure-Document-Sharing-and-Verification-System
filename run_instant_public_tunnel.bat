@echo off
title Instant Public HTTPS Tunnel
echo =================================================================
echo  Creating Instant Free Public HTTPS URL for your PQC System
echo =================================================================
echo.
echo Make sure 'server.py' is running in another window!
echo.
echo Attempting to launch free Cloudflare Quick Tunnel...
echo (If you do not have cloudflared installed, you can also use localtunnel or ngrok)
echo.
where cloudflared >nul 2>nul
if %ERRORLEVEL% equ 0 (
    echo Running Cloudflare Tunnel on port 5000...
    cloudflared tunnel --url http://localhost:5000
) else (
    echo cloudflared not found in PATH.
    echo Launching with npx localtunnel (requires Node.js)...
    call npx localtunnel --port 5000
)
pause
