:: Work based on a lot of good work from -
:: https://ossemproject.com/dm/mitre_attack/attack_ds_events_mappings.html
:: https://success.qualys.com/support/s/article/000003170
:: 
:: Run with local Administrator or SYSTEM privileges.
:: Log sizes converted:
:: 128 MB: 134217728kb
:: 256 MB: 268435456kb
:: 512 MB: 536870912kb
:: 1 GB: 268435456kb

:: Download and install latest version of Sysmon
mkdir C:\tools
pushd "C:\tools\"
echo [+] Downloading Sysmon
@powershell (new-object System.Net.WebClient).DownloadFile('https://live.sysinternals.com/Sysmon.exe','C:\tools\sysmon.exe')"
echo [+] Downloading Sysmon config.
:: Download and use one of the following sysmon config files:
:: Ion Storm
:: @powershell (new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/ion-storm/sysmon-config/master/sysmonconfig-export.xml','C:\tools\sysmonconfig-export.xml')"
:: SwiftOnSecurity
:: @powershell (new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml','C:\tools\sysmonconfig-export.xml')"
:: Olaf Hartong
@powershell (new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/olafhartong/sysmon-modular/master/sysmonconfig.xml','C:\tools\sysmonconfig-export.xml')"
:: Florian Roth
:: @powershell (new-object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/Neo23x0/sysmon-config/master/sysmonconfig-export.xml','C:\tools\sysmonconfig-export.xml')"
sysmon.exe -accepteula -i sysmonconfig-export.xml
sc failure Sysmon actions= restart/10000/restart/10000// reset= 120
echo [+] Sysmon Successfully Installed!

echo [+] Enabling powershell logging and transcript
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging" /v EnableModuleLogging /t REG_DWORD /d 1 /f
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging\ModuleNames" /v * /t REG_SZ /d * /f /reg:64
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 00000001 /f /reg:64
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableTranscripting /t REG_DWORD /d 00000001 /f /reg:64
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v OutputDirectory /t REG_SZ /d C:\PSTranscipts /f /reg:64
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" /v EnableInvocationHeader /t REG_DWORD /d 00000001 /f /reg:64

echo [+] Some registry house keeping activites for older systems:
reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1

:: Downloading KB3004375
:: Windows 7
:: bitsadmin /transfer PatchDownloadJob /download /priority normal https://download.microsoft.com/download/0/E/3/0E32F39B-1D5E-4B0E-804C-F736DAADDD93/Windows6.1-KB3004375-v3-x86.msu c:\Windows6.1-KB3004375-v3-x86.msu
:: wusa.exe c:\Windows6.1-KB3004375-v3-x86.msu /quiet /norestart

:: Windows 7 for x64-based Systems
:: bitsadmin /transfer PatchDownloadJob /download /priority normal https://download.microsoft.com/download/F/4/B/F4BE818D-22B9-4EF5-8E20-B9C4A605E61E/Windows6.1-KB3004375-v3-x64.msu c:\Windows6.1-KB3004375-v3-x64.msu
:: wusa.exe c:\Windows6.1-KB3004375-v3-x64.msu /quiet /norestart

Auditpol /get /category:* > AuditPol_BEFORE_%TIME%.txt
wevtutil gl System /f:xml > Systemlog_BEFORE_%TIME%.txt

:: Begin Windows Event logging improvments
wevtutil sl Security /ms:268435456
wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:268435456
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456

:: Set all other important logs to 128 MB. Increase or decrease to fit your environment.
wevtutil sl System /ms:134217728
wevtutil sl Application /ms:134217728

wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /e:true
wevtutil sl "Microsoft-Windows-TaskScheduler/Operational" /ms:134217728

wevtutil sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /e:true
wevtutil sl "Microsoft-Windows-DriverFrameworks-UserMode/Operational" /ms:134217728

wevtutil sl "Microsoft-Windows-AppLocker/EXE and DLL" /e:true
wevtutil sl "Microsoft-Windows-AppLocker/EXE and DLL" /ms:134217728

wevtutil sl "Microsoft-Windows-AppLocker/MSI and Script" /e:true
wevtutil sl "Microsoft-Windows-AppLocker/MSI and Script" /ms:134217728

wevtutil sl "Microsoft-Windows-AppLocker/Packaged app-Deployment" /e:true
wevtutil sl "Microsoft-Windows-AppLocker/Packaged app-Deployment" /ms:134217728

wevtutil sl "Microsoft-Windows-AppLocker/Packaged app-Execution" /e:true
wevtutil sl "Microsoft-Windows-AppLocker/Packaged app-Execution" /ms:134217728

wevtutil sl "Microsoft-Windows-Bits-Client/Operational" /e:true
wevtutil sl "Microsoft-Windows-Bits-Client/Operational" /ms:134217728

wevtutil sl "Microsoft-Windows-CodeIntegrity/Operational" /e:true
wevtutil sl "Microsoft-Windows-CodeIntegrity/Operational" /ms:134217728

wevtutil sl "Microsoft-Windows-Diagnosis-Scripted/Operational" /e:true
wevtutil sl "Microsoft-Windows-Diagnosis-Scripted/Operational" /ms:134217728

wevtutil sl "Microsoft-Windows-NTLM/Operational" /e:true
wevtutil sl "Microsoft-Windows-NTLM/Operational" /ms:134217728

wevtutil sl "Microsoft-Windows-PrintService/Admin" /e:true
wevtutil sl "Microsoft-Windows-PrintService/Admin" /ms:134217728

wevtutil sl "Microsoft-Windows-PrintService/Operational" /e:true
wevtutil sl "Microsoft-Windows-PrintService/Operational" /ms:134217728

wevtutil sl "Microsoft-Windows-Security-Mitigations/KernelMode" /e:true
wevtutil sl "Microsoft-Windows-Security-Mitigations/KernelMode" /ms:134217728

wevtutil sl "Microsoft-Windows-Security-Mitigations/UserMode" /e:true
wevtutil sl "Microsoft-Windows-Security-Mitigations/UserMode" /ms:134217728

wevtutil sl "Microsoft-Windows-Security-Mitigations/UserMode" /e:true
wevtutil sl "Microsoft-Windows-Security-Mitigations/UserMode" /ms:134217728

wevtutil sl "Microsoft-Windows-SmbClient/Security" /e:true
wevtutil sl "Microsoft-Windows-SmbClient/Security" /ms:134217728

wevtutil sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /e:true
wevtutil sl "Microsoft-Windows-TerminalServices-LocalSessionManager/Operational" /ms:134217728

wevtutil sl "Microsoft-Windows-WMI-Activity/Operational" /e:true
wevtutil sl "Microsoft-Windows-WMI-Activity/Operational" /ms:134217728

wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /e:true
wevtutil sl "Microsoft-Windows-Windows Defender/Operational" /ms:134217728

wevtutil sl "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" /e:true
wevtutil sl "Microsoft-Windows-Windows Firewall With Advanced Security/Firewall" /ms:134217728

:: Account Logon
:: Credential Validation
auditpol /set /subcategory:{0CCE923F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Kerberos Authentication Service (disable for clients)
auditpol /set /subcategory:{0CCE9242-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Kerberos Service Ticket Operations (disable for clients)
auditpol /set /subcategory:{0CCE9240-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Account Management
:: Computer Account Management
auditpol /set /subcategory:{0CCE9236-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Other Account Management Events
auditpol /set /subcategory:{0CCE923A-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Security Group Management
auditpol /set /subcategory:{0CCE9237-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: User Account Management
auditpol /set /subcategory:{0CCE9235-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Detailed Tracking
:: Plug and Play
auditpol /set /subcategory:{0cce9248-69ae-11d9-bed3-505054503030} /success:enable /failure:enable
:: Process Creation
auditpol /set /subcategory:{0CCE922B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Process Termination
auditpol /set /subcategory:{0CCE922C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: RPC Events
auditpol /set /subcategory:{0CCE922E-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Audit Token Right Adjustments (default: disabled)
auditpol /set /subcategory:{0CCE924A-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: DS Access
:: Directory Service Access (disable for clients)
auditpol /set /subcategory:{0CCE923B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Directory Service Changes (disable for clients)
auditpol /set /subcategory:{0CCE923C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Logon/Logoff
:: Account Lockout
auditpol /set /subcategory:{0CCE9217-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Group Membership
auditpol /set /subcategory:{0CCE9249-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Logoff
auditpol /set /subcategory:{0CCE9216-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Logon
auditpol /set /subcategory:{0CCE9215-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Network Policy Server
auditpol /set /subcategory:{0CCE9243-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Other Logon/Logoff Events
auditpol /set /subcategory:{0CCE921C-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Special Logon
auditpol /set /subcategory:{0CCE921B-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Object Access
:: Application Generated
auditpol /set /subcategory:{0CCE9222-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Certification Services
auditpol /set /subcategory:{0CCE9221-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Detailed File Share
:: auditpol /set /subcategory:{0CCE9244-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: File Share
auditpol /set /subcategory:{0CCE9224-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: File System
auditpol /set /subcategory:{0CCE921D-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Filtering Platform Connection
auditpol /set /subcategory:{0CCE9226-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Filtering Platform Packet Drop
auditpol /set /subcategory:{0CCE9225-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Kernel Object 
auditpol /set /subcategory:{0CCE921F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Other Object Access Events
auditpol /set /subcategory:{0CCE9227-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Registry
auditpol /set /subcategory:{0CCE921E-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Removable Storage
auditpol /set /subcategory:{0CCE9245-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: SAM
auditpol /set /subcategory:{0CCE9220-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Policy Change
:: Audit Policy Change
auditpol /set /subcategory:{0CCE922F-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Authentication Policy Change
auditpol /set /subcategory:{0CCE9230-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Authorization Policy Change
auditpol /set /subcategory:{0CCE9231-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Filtering Platform Policy Change
auditpol /set /subcategory:{0CCE9233-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: MPSSVC Rule-Level Policy Change
auditpol /set /subcategory:{0CCE9232-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Other Policy Change Events
auditpol /set /subcategory:{0CCE9234-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: Privilege Use
:: Sensitive Privilege Use 
auditpol /set /subcategory:{0CCE9228-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

:: System
:: Other System Events
auditpol /set /subcategory:{0CCE9214-69AE-11D9-BED3-505054503030} /success:disable /failure:enable
:: Security State Change
auditpol /set /subcategory:{0CCE9210-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: Security System Extension
auditpol /set /subcategory:{0CCE9211-69AE-11D9-BED3-505054503030} /success:enable /failure:enable
:: System Integrity
auditpol /set /subcategory:{0CCE9212-69AE-11D9-BED3-505054503030} /success:enable /failure:enable

Auditpol /get /category:* > AuditPol_AFTER_%TIME%.txt
wevtutil gl System /f:xml > Systemlog_AFTER_%TIME%.txt
