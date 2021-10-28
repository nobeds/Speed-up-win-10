sc config wuauserv start= disable
sc config bits start = disable
sc config DcomLaunch start = disable
net stop wuauserv
net stop bits
net stop DcomLaunch

reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ /v NoAutoUpdate /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU\ /v NoAutoUpdate /t REG_DWORD /d 1 /f
"%~dp0SetACL.exe" -on "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ot reg -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ot reg -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" -ot reg -actn ace -ace "n:SYSTEM;p:read"
reg add HKLM\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU\ /v NoAutoUpdate /t REG_DWORD /d 1 /f
reg add HKLM\SOFTWARE\WOW6432Node\Policies\Microsoft\Windows\WindowsUpdate\AU\ /v NoAutoUpdate /t REG_DWORD /d 1 /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AlwaysAutoRebootAtScheduledTime" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d "1" /f

rem ========================= Windows Updates =========================

rem support.microsoft.com/en-us/help/12387/windows-10-update-history
rem technet.microsoft.com/en-us/library/dd939844(v=ws.10).aspx

rem Use Windows Update MiniTool to check/download/install/hide updates
rem forums.mydigitallife.info/threads/64939-Windows-Update-MiniTool

rem Disable Windows Store Automatic App Updates
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\Automatic App Update" /Disable
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\WindowsStore\WindowsUpdate" /v "AutoDownload" /t REG_DWORD /d "2" /f

rem 1 = Disable Automatic Updates / Remove - Enable Automatic Updates (Manual checking for updates triggers automatic download of updates and ignores AUOptions)
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoUpdate" /t REG_DWORD /d "1" /f

rem Choose how updates are delivered / 0 - Get Updates from MS / 1 - get updates from MS and from/to PCs on my local network / 2 - get updates from MS and from/to PCs on my local network and PCs on the internet
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" /v "DODownloadMode" /t REG_DWORD /d "0" /f

rem 0 - Default / 1 - Defer upgrades, new Windows features won’t be downloaded or installed for several months. Deferring upgrades doesn’t affect security updates.
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "DeferUpgrade" /t REG_DWORD /d "0" /f

rem Active Hours - Windows Updates will not automatically restart your device during active hours
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursEnd" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Microsoft\WindowsUpdate\UX\Settings" /v "ActiveHoursStart" /t REG_DWORD /d "12" /f

rem 1 - Disable Malicious Software Removal Tool offered via Windows Updates (MRT)
reg add "HKLM\Software\Policies\Microsoft\MRT" /v DontOfferThroughWUAU /t REG_DWORD /d "1" /f

rem 1 - Disable driver updates in Windows Update (Better to be shown and then hidden than just completely ignored)
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate" /v "ExcludeWUDriversInQualityUpdate" /t REG_DWORD /d "1" /f

rem 1 - Restart notification allows user to initiate the restart or postpone restart. This notification does not have a countdown timer. The user must initiate the system restart.
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "AlwaysAutoRebootAtScheduledTime" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "NoAutoRebootWithLoggedOnUsers" /t REG_DWORD /d "1" /f

sc config wuauserv start= demand
schtasks /DELETE /TN "Microsoft\Windows\UpdateOrchestrator\Schedule Scan" /f
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Reboot" /Disable
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\Refresh Settings" /Disable
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_Display" /Disable
schtasks /Change /TN "Microsoft\Windows\UpdateOrchestrator\USO_UxBroker_ReadyToReboot" /Disable
schtasks /DELETE /TN "Microsoft\Windows\WindowsUpdate\Scheduled Start" /f
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\sih" /Disable
schtasks /Change /TN "Microsoft\Windows\WindowsUpdate\sihboot" /Disable
