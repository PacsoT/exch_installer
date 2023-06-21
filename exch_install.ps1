Exchange install


VmWare Tools
setup.exe /s /v /qn

 
diskpart
select disk 1
online disk
attributes disk clear readonly
convert gpt
create partition primary
assign

Get-Disk | Where-Object PartitionStyle –Eq 'RAW' | Initialize-Disk  –PartitionStyle GPT

Get-Disk 1 | New-Partition -UseMaximumSize -DriveLetter E | Format-Volume -FileSystem REFS -AllocationUnitSize 65536 -NewFileSystemLabel "Local_Backup" -SetIntegrityStreams $false

Get-Certificate -Template "Web2" -DnsName "srv17exch3.pohi17.local,mail01.rakosmente.hu" -CertStoreLocation cert:\LocalMachine\My -SubjectName "CN=srv17exch3.pohi17.local, C=HU, L=Budapest, O=Rakosmente OU=IT, S=Budapest"

Set-ItemProperty -Path 'HKLM:\Software\Microsoft\Windows NT\CurrentVersion\WinLogon' -Name Shell -Value 'PowerShell.exe'

Add-Computer -DomainName hq.nador.hu -NewName srvMAIL1B -DomainCredential NR\ptadmin -OUPath "OU=Servers,OU=NR-SRV,DC=hq,DC=nador,DC=hu"

Install-WindowsFeature Server-Media-Foundation, RSAT-ADDS


wget https://download.microsoft.com/download/b/c/7/bc766694-8398-4258-8e1e-ce4ddb9b3f7d/ExchangeServer2019-x64-CU12.ISO  -outfile "ExchangeServer2019-x64-CU12.ISO"

wget "https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe" -outfile "vcredist_x64.exe"
.\vcredist_x64.exe /passive
wget 'https://download.microsoft.com/download/1/2/8/128E2E22-C1B9-44A4-BE2A-5859ED1D4592/rewrite_amd64_en-US.msi' -OutFile IIS_rewrite.msi
msiexec.exe  /passive /i IIS_rewrite.msi

wget -Uri 'https://download.visualstudio.microsoft.com/download/pr/2d6bb6b2-226a-4baa-bdec-798822606ff1/8494001c276a4b96804cde7829c04d7f/ndp48-x86-x64-allos-enu.exe' -OutFile .\NET4_8_offline_installer_x64.exe
.\NET4_8_offline_installer_x64.exe /q



Mount-DiskImage '\\strsynology01\Install\Install2\M$\exchange\2019\Exchange_2019_CU12_x64.Iso'
F:\UCMARedist\Setup.exe  /passive
F:\Setup.exe /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /PrepareAD
F:\Setup.exe /m:install /roles:m /IAcceptExchangeServerLicenseTerms_DiagnosticDataOFF /InstallWindowsComponents




Add-PSSnapin Microsoft.Exchange.Management.PowerShell.SnapIn;



$Secure_String_Pwd = ConvertTo-SecureString "VnovEmbeR24.EnadoRZ" -AsPlainText -Force
Import-PfxCertificate -FilePath B:\!Aktuális\cert\nador_2022-2023.pfx  -CertStoreLocation Cert:\LocalMachine\My -Password $Secure_String_Pwd
Enable-ExchangeCertificate -Services POP,IMAP,IIS,SMTP -Thumbprint 6768D1052CFB8C6606D21EE416572ADCB0C62C98



$internal_domain = "mail.nador.hu" #enter internal domain
$external_domain = "mail.nador.hu" #enter external domain
$servername = "srvmail1a" #enter server name

Get-ClientAccessService -Identity $servername | Set-ClientAccessService -AutoDiscoverServiceInternalUri "https://$external_domain/Autodiscover/Autodiscover.xml"
Get-EcpVirtualDirectory -Server $servername | Set-EcpVirtualDirectory -ExternalUrl "https://$external_domain/ecp" -InternalUrl "https://$internal_domain/ecp"
Get-WebServicesVirtualDirectory -Server $servername | Set-WebServicesVirtualDirectory -ExternalUrl "https://$external_domain/EWS/Exchange.asmx" -InternalUrl "https://$internal_domain/EWS/Exchange.asmx"
Get-MapiVirtualDirectory -Server $servername | Set-MapiVirtualDirectory -ExternalUrl "https://$external_domain/mapi" -InternalUrl "https://$internal_domain/mapi"
Get-ActiveSyncVirtualDirectory -Server $servername | Set-ActiveSyncVirtualDirectory -ExternalUrl "https://$external_domain/Microsoft-Server-ActiveSync" -InternalUrl "https://$internal_domain/Microsoft-Server-ActiveSync"
Get-OabVirtualDirectory -Server $servername | Set-OabVirtualDirectory -ExternalUrl "https://$external_domain/OAB" -InternalUrl "https://$internal_domain/OAB"
Get-PowerShellVirtualDirectory -Server $servername | Set-PowerShellVirtualDirectory -ExternalUrl "https://$external_domain/powershell" -InternalUrl "https://$internal_domain/powershell"
Get-OutlookAnywhere -Server $servername | Set-OutlookAnywhere -ExternalHostname "$external_domain" -InternalHostname "$internal_domain" -ExternalClientsRequireSsl $true -InternalClientsRequireSsl $true -DefaultAuthenticationMethod NTLM

netsh advfirewall firewall add rule name=”IIS Remote Management” dir=in action=allow service=WMSVC
set-service -Name WMSVC -StartupType Automatic
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WebManagement\Server -Name EnableRemoteManagement -Value 1
reStart-Service WMSVC


Set-TransportConfig -MaxReceiveSize 1024MB
Set-TransportConfig -MaxSendSize 1024MB


mkdir e:\DB

New-MailboxDatabase -Name Exc2019_DB -Server 'srvMAIL1A' -EdbFilePath E:\DB\Exc2019_db.edb -LogFolderPath E:\DB
Mount-Database Exc2019_DB

 New-DatabaseAvailabilityGroup -Name dagEXCH2019 -WitnessServer srvFILE4.hq.nador.hu -WitnessDirectory E:\DAG_witness_share -DatabaseAvailabilityGroupIPAddresses 172.27.254.40
  Add-DatabaseAvailabilityGroupServer -Identity dagEXCH2019 -MailboxServer srvMAIL1A
  Add-DatabaseAvailabilityGroupServer -Identity dagEXCH2019 -MailboxServer srvMAIL1B
  Add-MailboxDatabaseCopy -Identity Exc2019_DB -MailboxServer srvMAIL1B


powercfg.exe /s 8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c