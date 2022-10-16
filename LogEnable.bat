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

:: echo [+] Some registry house keeping activites for older systems:
:: reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1

Auditpol /get /category:* > AuditPol_BEFORE_%TIME%.txt

:: Begin Windows Event logging improvments
wevtutil sl Security /ms:268435456
wevtutil sl Microsoft-Windows-PowerShell/Operational /ms:268435456
wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456

:: Set all other important logs to 128 MB. Increase or decrease to fit your environment.
wevtutil sl System /ms:134217728
wevtutil sl Application /ms:134217728