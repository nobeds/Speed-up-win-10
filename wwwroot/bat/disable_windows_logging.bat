rem ========================= Windows Logging =========================

rem DiagLog required by Diagnostic Policy Service
rem EventLog-Application required by Windows
rem EventLog-System required by Windows
rem msdn.microsoft.com/en-us/library/windows/desktop/aa363687(v=vs.85).aspx

reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\Audio" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\AutoLogger-Diagtrack-Listener" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderApiLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\DefenderAuditLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\MpWppTracing-07202016-140038-00000003-ffffffff" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\ReadyBoot" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\SQMLogger" /v "Start" /t REG_DWORD /d "0" /f
reg add "HKLM\System\CurrentControlSet\Control\WMI\Autologger\WiFiSession" /v "Start" /t REG_DWORD /d "0" /f
