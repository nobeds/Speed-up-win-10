

taskkill /f /IM "SearchUI.exe"
rd "%WINDIR%\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy" /s /q
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn setprot -op "dacl:p_nc;sacl:p_nc"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn setowner -ownr "n:%USERNAME%"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn ace -ace "n:%USERNAME%;p:full"
"%~dp0SetACL.exe" -on C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe -ot file -actn ace -ace "n:System;p:read"
ren "C:\Windows\SystemApps\Microsoft.Windows.Cortana_cw5n1h2txyewy\SearchUI.exe" "SearchUI.bak"

rem Disable Cortana
reg add "HKCU\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f
reg add "HKCU\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
reg add "HKCU\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f
reg add "HKLM\Software\Policies\Microsoft\Windows\Windows Search" /v "AllowCortana" /t REG_DWORD /d "0" /f
