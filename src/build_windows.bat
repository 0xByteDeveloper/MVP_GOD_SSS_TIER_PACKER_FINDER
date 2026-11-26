@echo off
rem v8 GOD STATE - Windows derlemesi (MinGW-w64)
x86_64-w64-mingw32-g++ -O2 -std=c++17 -static -o ..\bin\vmpdet8_windows.exe vmpdet5.cpp -lpsapi
