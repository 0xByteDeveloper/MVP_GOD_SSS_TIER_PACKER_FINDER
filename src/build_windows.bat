@echo off
REM vmpdet4 Windows derlemesi (MinGW-w64 ya da MSVC)
REM MinGW: g++ -O2 -o vmpdet4_windows.exe vmpdet4.cpp -std=c++17 -static -lpsapi
g++ -O2 -o vmpdet4_windows.exe vmpdet4.cpp -std=c++17 -static -lpsapi
