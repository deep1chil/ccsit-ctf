@echo off
REM ============================================================
REM  CCSIT CTF — run platform + challenge, each in its own window
REM  Requires: python (flask installed).  pip install flask
REM ============================================================

echo [1/2] Starting the CHALLENGE  (http://localhost:8001) ...
start "ccsit-challenge" cmd /k python "%~dp0challenge_roleup.py" 8001

timeout /t 2 >nul

echo [2/2] Starting the PLATFORM   (http://localhost:5000) ...
start "ccsit-platform" cmd /k python "%~dp0app.py"

echo.
echo Done. Two windows opened:
echo   Platform  -^> http://localhost:5000   (register, submit, scoreboard)
echo   Challenge -^> http://localhost:8001   (the vulnerable app)
echo.
echo For LAN testing use your 192.168.x.x IP instead of localhost.
echo For a public game, see README.md (section: Online with tunnels).
pause
