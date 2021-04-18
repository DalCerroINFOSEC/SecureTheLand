

-gobuster dir -u http://<ip>:80 -w <wordlist>
 
-accesschk64.exe -wvu "<file location>"
  
-#Registry PrivEsc-AlwaysInstallElevated

--reg query HKLM\Software\Policies\Microsoft\Windows\Installer

--reg query HKCU\Software\Policies\Microsoft\Windows\Installer

-hashcat -m 1000 <hash> <wordlist>
