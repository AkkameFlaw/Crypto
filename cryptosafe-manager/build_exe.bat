@echo off
set PYTHONPATH=.
pyinstaller --noconfirm --clean --onedir --windowed --name CryptoSafeManager run.py
pause