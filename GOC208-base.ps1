Set-VMHost -EnableEnhancedSessionMode $true

# Do not prompt user for confirmations
Set-Variable -Name 'ConfirmPreference' -Value 'None' -Scope Global

# Install PackageManagement
Write-Output "Installing PackageManagement"
Install-Package -Name PackageManagement -MinimumVersion 1.4.7 -Force -Confirm:$false -Source PSGallery

# Install PowershellGet
Write-Output "Installing PowershellGet"
Install-Package -Name PowershellGet -Force

Write-Host "Install package provider NuGet" -ForegroundColor Green
if (Get-PackageProvider -Name NuGet) { Write-Host "Nuget package provider already installed" -ForegroundColor Yellow
} else {
    Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force    
} 

Write-Host "Install module Pester" -ForegroundColor Green
Install-Module pester -Force -SkipPublisherCheck

Write-Host "Install module AutomatedLab" -ForegroundColor Green
if (Get-Module -ListAvailable -Name AutomatedLab) { Write-Host "Module AutomatedLab already installed" -ForegroundColor Yellow
} else {
    Install-Module AutomatedLab -Confirm:$false -Force -AllowClobber    
}

Write-Host "Disable AutomatedLab telemetry" -ForegroundColor Green
[Environment]::SetEnvironmentVariable('AUTOMATEDLAB_TELEMETRY_OPTIN', 'false', 'Machine')
$env:AUTOMATEDLAB_TELEMETRY_OPTIN = 'false'

Write-Host "New Lab sources folder" -ForegroundColor Green
New-LabSourcesFolder -DriveLetter E -Branch master -Force -Verbose

## Adding Internet networking
Write-Host "Creating new internal Hyper-V switch that will be used with NAT for LAB" -ForegroundColor Green
    if (Get-VMSwitch -Name "Default Switch" -ErrorAction SilentlyContinue) {
        Write-Host "Default Switch already created" -ForegroundColor Yellow
    } else {
        New-VMSwitch -SwitchName "Default Switch" -SwitchType Internal
    } 
$inet = (Get-NetAdapter | Where-Object Name -EQ "vEthernet (Default Switch)").ifIndex
New-NetIPAddress -IPAddress 10.208.255.254 -PrefixLength 16 -InterfaceIndex $inet
New-NetNat -Name Internet -InternalIPInterfaceAddressPrefix 10.208.0.0/16
##

## Relaxing security
Write-Host "Enable LabHostRemoting" -ForegroundColor Green
Enable-LabHostRemoting -Force
Write-Host "Enable Windows Defender Antivirus folder exception for LabSources" -ForegroundColor Green
Add-MpPreference -ExclusionPath E:\LabSources\
#/ end of relaxing

#correct wrong CM version detection
Write-Host "Downloading fixed Invoke-UpdateCM.ps1 script" -ForegroundColor Green
Invoke-WebRequest -Uri https://raw.githubusercontent.com/KamilRT/AutomatedLab/develop/LabSources/CustomRoles/CM-2103/Invoke-UpdateCM.ps1 -OutFile E:\LabSources\CustomRoles\CM-2103\Invoke-UpdateCM.ps1 -ErrorAction Stop
Unblock-File E:\LabSources\CustomRoles\CM-2103\Invoke-UpdateCM.ps1

# copy current develop script
Write-Host "Downloading Mastering Deployment script" -ForegroundColor Green
Invoke-WebRequest -Uri https://raw.githubusercontent.com/KamilRT/AutomatedLab/develop/LabSources/SampleScripts/Scenarios/MD-2021.ps1 -OutFile E:\LabSources\GOC208.ps1 -ErrorAction Stop
Unblock-File E:\LabSources\GOC208.ps1

Copy-Item -Path E:\GOC208\Sources\ISOs\* -Destination E:\LabSources\ISOs\ -Verbose
Get-LabAvailableOperatingSystem -Path E:\LabSources -NoDisplay

## preparing VMs
#E:\LabSources\SampleScripts\Scenarios\CM-2103.ps1 -LabName GOC208 -Domain goc208.local -AdminUser Admin -AdminPass "Pa55w.rd" -ExternalVMSwitchName "Default Switch" -SiteCode GOC -SiteName GOC208 -CMVersion 2103 -Branch CB -OSVersion 'Windows Server 2019 Datacenter (Desktop Experience)' -DCHostname DC1 -DCCPU 2 -DCMemory 4GB -CMHostname CM1 -CMCPU 4 -CMMemory 8GB -LogViewer OneTrace -AutoLogon -Verbose -ExcludePostInstallations
E:\LabSources\GOC208.ps1 -LabName GOC208 -ExternalVMSwitchName "Default Switch" -SiteCode GOC -SiteName GOC208 -OSVersion 'Windows Server 2019 Datacenter (Desktop Experience)' -AutoLogon -Verbose -ExcludePostInstallations -Clients -PC2OlderOS

## setting DC IP address for internet
# Define clear text string for username and password
[string]$VMuser = 'goc208\admin'
[string]$VMuserPass = 'Pa55w.rd'
# Convert to SecureString
[securestring]$secStringPassword = ConvertTo-SecureString $VMuserPass -AsPlainText -Force
[pscredential]$VMcred = New-Object System.Management.Automation.PSCredential ($VMuser, $secStringPassword)

Invoke-Command -VMName "GOC208DC01" -Credential $VMcred -ScriptBlock {(Get-NetAdapter | Where-Object Name -eq "Default switch 0") | New-NetIPAddress -IPAddress 10.208.255.253 -DefaultGateway 10.208.255.254 -PrefixLength 16 | Set-DnsClientServerAddress -ServerAddresses 10.208.255.254}
##

## Finishing MECM instalation
#E:\LabSources\SampleScripts\Scenarios\CM-2103.ps1 -LabName GOC208 -Domain goc208.local -AdminUser Admin -AdminPass "Pa55w.rd" -ExternalVMSwitchName "Default Switch" -SiteCode GOC -SiteName GOC208 -CMVersion 2103 -Branch CB -OSVersion 'Windows Server 2019 Datacenter (Desktop Experience)' -DCHostname DC1 -DCCPU 2 -DCMemory 4GB -CMHostname CM1 -CMCPU 4 -CMMemory 8GB -LogViewer OneTrace -AutoLogon -Verbose -PostInstallations
E:\LabSources\GOC208.ps1 -LabName GOC208 -ExternalVMSwitchName "Default Switch" -SiteCode GOC -SiteName GOC208 -OSVersion 'Windows Server 2019 Datacenter (Desktop Experience)' -AutoLogon -Verbose -PostInstallations -Clients -PC2OlderOS

cmd /c choco install microsoft-edge -y

cmd /c code --install-extension ms-vscode.powershell 