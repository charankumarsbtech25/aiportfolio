@echo off
title Portfolio AI Server
cd /d "%~dp0"
set "PYTHONPATH=%~dp0portfolio_ai\portfolio_ai;%PYTHONPATH%"
echo ========================================================
echo  Portfolio AI - Starting Quantitative Platform & Backend
echo ========================================================
echo Server URL: http://127.0.0.1:8000/login.html
echo.
start "" "http://127.0.0.1:8000/login.html"
python run.py
pause
