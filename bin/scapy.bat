@echo off
REM Use Python to run the Scapy script from the current directory, passing all parameters
title scapy
python "%~dp0\scapy" %*
