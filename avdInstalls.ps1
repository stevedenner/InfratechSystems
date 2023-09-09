New-Item -ItemType Directory -Path C:\Build
Start-Transcript -Path c:\Build\installs.txt

Write-Host Enable secure WinRM
$cert = New-SelfSignedCertificate -DnsName "winrm" -CertStoreLocation Cert:\LocalMachine\My
$winrmhttps = "@{Hostname=`"winrm`"; CertificateThumbprint=`"" + $cert.Thumbprint + "`"}"
winrm create winrm/config/Listener?Address=*+Transport=HTTPS $winrmhttps

Write-Host "Set Basic Auth in WinRM"
$WinRmBasic = "@{Basic=`"true`"}"
winrm set winrm/config/service/Auth $WinRmBasic

Write-Host "Open WinRM"
New-NetFirewallRule -DisplayName "WinRM" -Direction Inbound -Action Allow -EdgeTraversalPolicy Allow -Protocol TCP -LocalPort 5985-5986

Write-Host "Cleanup Start Menu"
Get-AppxPackage -Name "Microsoft.Getstarted" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.ZuneVideo" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.ZuneMusic" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.YourPhone" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.XboxSpeechToTextOverlay" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.XboxIdentityProvider" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.XboxGamingOverlay" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.XboxGameOverlay" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.Xbox.TCUI" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.WindowsFeedbackHub" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.People" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.GetHelp" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.GamingApp" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.BingWeather" | Remove-AppxPackage
Get-AppxPackage -Name "Microsoft.BingNews" | Remove-AppxPackage

Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.Getstarted"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.ZuneVideo"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.ZuneMusic"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.YourPhone"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.XboxSpeechToTextOverlay"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.XboxIdentityProvider"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.XboxGamingOverlay"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.XboxGameOverlay"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.Xbox.TCUI"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.WindowsFeedbackHub"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.People"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.MicrosoftSolitaireCollection"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.MicrosoftOfficeHub"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.GetHelp"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.GamingApp"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.BingWeather"}|Remove-AppxProvisionedPackage -online
Get-AppxProvisionedPackage -online |where-object {$_.DisplayName -like "Microsoft.BingNews"}|Remove-AppxProvisionedPackage -online

Write-Host "Installing Office"

#Download latest ODT and extract
$url = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=49117"
try {
    $response = Invoke-WebRequest -UseBasicParsing -Uri $url -ErrorAction SilentlyContinue
}
catch {
    Throw "Failed to connect to ODT: $url with error $_."
    Break
}
finally {
    $ODTUri = $response.links | Where-Object {$_.outerHTML -like "*click here to download manually*"}
    Write-Output $ODTUri.href
}

Write-Host "Downloading latest version of Office 365 Deployment Tool (ODT)."
Invoke-WebRequest -Uri $ODTUri.href -OutFile c:\build\officedeploymenttool.exe

sleep 20

Write-Host "Extracting ODT"
c:\build\officedeploymenttool.exe /quiet /extract:c:\Build\

Invoke-WebRequest -Uri "https://raw.githubusercontent.com/stevedenner/InfratechSystems/main/configuration-Office365-x64-inf.xml" -OutFile c:\build\configuration-Office365-x64-inf.xml

cd c:\build\
c:\build\setup.exe /download c:\build\configuration-Office365-x64-inf.xml
c:\build\setup.exe /configure c:\build\configuration-Office365-x64-inf.xml
c:\build\setup.exe /configure c:\build\configuration-Office365-x64-inf.xml

Write-host "Installing Chocolatey"
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))

Write-host "Installing Adobe Reader"
choco install adobereader -Y

Write-host "Installing Notepad++"
choco install notepadplusplus -Y

Write-host "Installing PowerBI"
choco install powerbi -Y

Write-host "Installing vscode"
choco install vscode -Y

Write-host "Installing winscp"
choco install winscp -Y

Write-host "Installing putty"
choco install putty -Y

Write-host "Installing 7zip"
choco install 7zip -Y

Write-host "Installing winscp"
choco install winscp -Y

Write-host "Installing FSLogix"
choco install fslogix -Y

Write-Host "Installing Rule Editor"
choco install fslogix-rule

Write-host "Installing Updates"
powershell -ExecutionPolicy Unrestricted Install-PackageProvider Nuget -force;Set-PSRepository PSGallery -installationPolicy Trusted;Install-Module PSWindowsUpdate -confirm:$false ;Get-WindowsUpdate -AcceptAll -Install -AutoReboot

Write-Host "Downloading finalise script"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/stevedenner/InfratechSystems/main/finalise.cmd" -OutFile c:\build\finalise.cmd

Write-Host "Copying custom files"
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/stevedenner/InfratechSystems/main/InfraTech_Wallpaper_blue1.jpg" -OutFile c:\Windows\InfraTech_Wallpaper_blue1.jpg
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/stevedenner/InfratechSystems/main/InfraTech_Wallpaper_blue1.jpg" -OutFile C:\Windows\Web\Wallpaper\Windows\img0.jpg
Invoke-WebRequest -Uri "https://raw.githubusercontent.com/stevedenner/InfratechSystems/main/LockScreen.jpg" -OutFile C:\Windows\Lockscreen.jpg

Write-Host "Setting Teams optimisation"
New-Item -Path "HKLM:\SOFTWARE\Microsoft\Teams" -Force
New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Teams" -Name IsWVDEnvironment -PropertyType DWORD -Value 1 -Force

Invoke-WebRequest -Uri "https://aka.ms/msrdcwebrtcsvc/msi" -OutFile c:\build\MsRdcWebRTCSvc_HostSetup.msi
msiexec /i c:\build\MsRdcWebRTCSvc_HostSetup.msi /qn

#Downloading Defender onboarding script
New-Item -ItemType Directory "C:\WINDOWS\System32\GroupPolicy\Machine\Scripts\Startup\"

Invoke-WebRequest -Uri "https://github.com/stevedenner/InfratechSystems/raw/main/WindowsDefenderATPOnboardingPackage.zip"  -OutFile C:\WINDOWS\System32\GroupPolicy\Machine\Scripts\Startup\WindowsDefenderATPOnboardingPackage.zip
Expand-Archive -Path C:\WINDOWS\System32\GroupPolicy\Machine\Scripts\Startup\WindowsDefenderATPOnboardingPackage.zip -DestinationPath C:\WINDOWS\System32\GroupPolicy\Machine\Scripts\Startup\

Remove-item C:\WINDOWS\System32\GroupPolicy\Machine\Scripts\Startup\WindowsDefenderATPOnboardingPackage.zip

#Install AzureAD module
Install-Module AzureAD
Stop-Transcript
