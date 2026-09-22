@echo off
rem Abre o agente-vulnerabilidades: PowerShell na pasta correta + iniciar.ps1.
rem Roda na propria janela (sem abrir janela extra). Lida com espacos/acentos.
cd /d "%~dp0"
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0iniciar.ps1" %*
