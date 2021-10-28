rem ========================= Windows Optimizations =========================

rem blogs.technet.microsoft.com/markrussinovich/2008/07/21/pushing-the-limits-of-windows-physical-memory
rem channel9.msdn.com/Blogs/Seth-Juarez/Memory-Compression-in-Windows-10-RTM

rem Determines whether user processes end automatically when the user either logs off or shuts down / 1 - Processes end automatically
reg add "HKCU\Control Panel\Desktop" /v "AutoEndTasks" /t REG_SZ /d "1" /f

rem When the time is set too low, apps like Settings will crash, system icons like Volume and Power will disappear
rem www.tenforums.com/drivers-hardware/21217-volume-icon-not-appearing-taskbar.html#post578321
rem Specifies in milliseconds how long the System waits for user processes to end after the user clicks the End Task command button in Task Manager
reg add "HKCU\Control Panel\Desktop" /v "HungAppTimeout" /t REG_SZ /d "5000" /f

rem Determines how long the System waits for user processes to end after the user attempts to log off or to shut down
reg add "HKCU\Control Panel\Desktop" /v "WaitToKillAppTimeout" /t REG_SZ /d "10000" /f

rem Determines in milliseconds how long the System waits for services to stop after notifying the service that the System is shutting down
reg add "HKLM\System\CurrentControlSet\Control" /v "WaitToKillServiceTimeout" /t REG_SZ /d "10000" /f

rem Determines in milliseconds the interval from the time the cursor is pointed at a menu until the menu items are displayed
reg add "HKCU\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "0" /f

rem  Mouse Hover Time in milliseconds before Pop-up Display
reg add "HKCU\Control Panel\Mouse" /v "MouseHoverTime" /t REG_SZ /d "0" /f

rem How long in milliseconds you want to have for a startup delay time for desktop apps that run at startup to load
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" /v "StartupDelayInMSec" /t REG_DWORD /d "0" /f

rem n - Disable Background disk defragmentation / y - EnableHow long in milliseconds you want to have for a startup delay time for desktop apps that run at startup to load
reg add "HKLM\Software\Microsoft\Dfrg\BootOptimizeFunction" /v "Enable" /t REG_SZ /d "n" /f

rem 0 - Disable Background auto-layout / Disable Optimize Hard Disk when idle
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\OptimalLayout" /v "EnableAutoLayout" /t REG_DWORD /d "0" /f

rem 1 - Disable Automatic Maintenance
reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Schedule\Maintenance" /v "MaintenanceDisabled" /t REG_DWORD /d "1" /f

rem 1 - NTFS does not create short file names
reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisable8dot3NameCreation" /t REG_DWORD /d "1" /f

rem 1 - Disable the Encrypting File System (EFS)
reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisableEncryption" /t REG_DWORD /d "1" /f

rem 1 - When listing directories, NTFS does not update the last-access timestamp, and it does not record time stamp updates in the NTFS log
reg add "HKLM\System\CurrentControlSet\Control\FileSystem" /v "NtfsDisableLastAccessUpdate" /t REG_DWORD /d "1" /f

rem 0 - Establishes a standard size file-system cache of approximately 8 MB / 1 - Establishes a large system cache working set that can expand to physical memory, minus 4 MB, if needed
rem technet.microsoft.com/en-us/library/cc784562(v=ws.10).aspx
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management" /v "LargeSystemCache" /t REG_DWORD /d "0" /f

rem 0 - Drivers and the kernel can be paged to disk as needed / 1 - Drivers and the kernel must remain in physical memory
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "DisablePagingExecutive" /t REG_DWORD /d "1" /f

rem 0 - Disable Prefetch / 1 - Enable Prefetch when the application starts / 2 - Enable Prefetch when the device starts up / 3 - Enable Prefetch when the application or device starts up
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnablePrefetcher" /t REG_DWORD /d "0" /f

rem 0 - Disable SuperFetch / 1 - Enable SuperFetch when the application starts up / 2 - Enable SuperFetch when the device starts up / 3 - Enable SuperFetch when the application or device starts up
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "EnableSuperfetch" /t REG_DWORD /d "0" /f

rem 0 - Disable It / 1 - Default
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters" /v "SfTracingState" /t REG_DWORD /d "0" /f

rem 0 - Disable Fast Startup for a Full Shutdown / 1 - Enable Fast Startup (Hybrid Boot) for a Hybrid Shutdown
reg add "HKLM\System\CurrentControlSet\Control\Session Manager\Power" /v "HiberbootEnabled" /t REG_DWORD /d "0" /f

rem Disable Hibernation / Disable Fast Startup (Hybrid Boot)
powercfg -h off