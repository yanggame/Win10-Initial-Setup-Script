# Enable some feature
Function UnpinMailTaskbar {
    Write-Output "Remove Mail from Taskbar..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -Name "MailPin" -Type DWord -Value 0
}

# Disable some feature
Function PinMailTaskbar {
    Write-Output "Add Mail to Taskbar..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Taskband\AuxilliaryPins" -Name "MailPin" -Type DWord -Value 1
}

Function DisableStartupDelay {
    Write-Output "Disable Startup Delay..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -Type DWord -Value 0
}

Function EnableStartupDelay {
	Write-Output "Enable Startup Delay..."
    Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Serialize" -Name "StartupDelayInMSec" -ErrorAction SilentlyContinue
}

Function DisableStoreAutoUpdate {
	Write-Output "Disable Microsoft Store Auto Update..."
    If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -Type DWord -Value 2
}

Function EnableStoreAutoUpdate {
	Write-Output "Enable Microsoft Store Auto Update..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsStore" -Name "AutoDownload" -ErrorAction SilentlyContinue
}

Function EnableNetworkDriveUAC {
	Write-Output "Enable Network Drive over UAC..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -Type DWord -Value 1
}

Function DisableNetworkDriveUAC {
	Write-Output "Disable Network Drive over UAC..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -Name "EnableLinkedConnections" -ErrorAction SilentlyContinue
}

Function DisableWindowsInkWorkspace {
	Write-Output "Disable Windows Ink Workspace..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -Type DWord -Value 0
}

Function EnableWindowsInkWorkspace {
	Write-Output "Enable Windows Ink Workspace..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\WindowsInkWorkspace" -Name "AllowWindowsInkWorkspace" -ErrorAction SilentlyContinue
}

Function DisableLiveTiles {
	Write-Output "Disable Live Tiles..."
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -Type DWord -Value 1
}

Function EnableLiveTiles {
	Write-Output "Enable Live Tiles..."
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "NoTileApplicationNotification" -ErrorAction SilentlyContinue
}

Function DisableLookAppFromStore {
	Write-Output "Disable Look App from Store..."
	If (!(Test-Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer")) {
        New-Item -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -Type DWord -Value 1
}

Function EnableLookAppFromStore {
	Write-Output "Enable Look App from Store..."
	Remove-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\Explorer" -Name "NoUseStoreOpenWith" -ErrorAction SilentlyContinue
}

Function DisableEdgePrelaunch {
	Write-Output "Disable Edge Prelaunch..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -Type DWord -Value 0
}

Function EnableEdgePrelaunch {
	Write-Output "Enable Edge Prelaunch..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\MicrosoftEdge\Main" -Name "AllowPrelaunch" -ErrorAction SilentlyContinue
}

Function EnableAutoRegistryBackup {
	Write-Output "Enable Auto Registry Backup..."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" -Name "EnablePeriodicBackup" -Type DWord -Value 1
}

Function DisableAutoRegistryBackup {
	Write-Output "Enable Edge Prelaunch..."
	Remove-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager" -Name "EnablePeriodicBackup" -ErrorAction SilentlyContinue
}

Function DisableFastBoot {
	Write-Output "Disable Fast Boot..."
	If (!(Test-Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power")) {
        New-Item -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 0
}

Function EnableFastBoot {
	Write-Output "Enable Fast Boot..."
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Power" -Name "HiberbootEnabled" -Type DWord -Value 1
}

Function DisableOOBE {
	Write-Output "Disable OOBE..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Type DWord -Value 1
	If (!(Test-Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\OOBE")) {
        New-Item -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -Type DWord -Value 1
}

Function EnableOOBE {
	Write-Output "Enable OOBE..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -ErrorAction
	Remove-ItemProperty -Path "HKCU:\SOFTWARE\Policies\Microsoft\Windows\OOBE" -Name "DisablePrivacyExperience" -ErrorAction
}

Function DisableNewsAndInterests {
	Write-Output "Disable News and Interests..."
	If (!(Test-Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -Type DWord -Value 0
	If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -Type DWord -Value 2
}

Function EnableNewsAndInterests {
	Write-Output "Enable News and Interests..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Feeds" -Name "EnableFeeds" -ErrorAction
	Remove-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Feeds" -Name "ShellFeedsTaskbarViewMode" -ErrorAction
}

Function DisableJavaAutoUpdate {
	Write-Output "Disable Java Auto Update..."
	If (!(Test-Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run")) {
        New-Item -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SunJavaUpdateSched" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "NotifyDownload" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EnableJavaUpdate" -Type DWord -Value 0
	If (!(Test-Path "HKLM:\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy")) {
        New-Item -Path "HKLM:\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy" -Name "SunJavaUpdateSched" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy" -Name "NotifyDownload" -Type DWord -Value 0
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy" -Name "EnableJavaUpdate" -Type DWord -Value 0
}

Function EnableJavaAutoUpdate {
	Write-Output "Enable Java Auto Update..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "SunJavaUpdateSched" -ErrorAction
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "NotifyDownload" -ErrorAction
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "EnableJavaUpdate" -ErrorAction
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy" -Name "SunJavaUpdateSched" -ErrorAction
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy" -Name "NotifyDownload" -ErrorAction
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Wow6432Node\JavaSoft\Java Update\Policy" -Name "EnableJavaUpdate" -ErrorAction
}

Function DisableAdobeAcrobatAutoUpdate {
	Write-Output "Disable Adobe Acrobat Auto Update..."
If (!(Test-Path "HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown")) {
        New-Item -Path "HKLM:\SOFTWARE\Policies\Adobe\Adobe Acrobat\DC\FeatureLockDown" -Force | Out-Null
    }
	Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bUpdater" -Type DWord -Value 0
}

Function EnableeAdobeAcrobatAutoUpdate {
	Write-Output "Enable Adobe Acrobat Auto Update..."
	Remove-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Adobe\Acrobat Reader\DC\FeatureLockDown" -Name "bUpdater" -ErrorAction
}