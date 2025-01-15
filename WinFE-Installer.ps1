 <#
    .SYNOPSIS
        This script is used to install the Windows Forensic Environment (WinFE) onto a USB
        https://github.com/digitalsleuth/
    .DESCRIPTION

    .NOTES
        Version        : 1.2a
        Author         : Corey Forman (https://github.com/digitalsleuth)
        Prerequisites  : Windows 10 1909 or later
                       : Set-ExecutionPolicy must allow for script execution
    .PARAMETER Mode
        There are two modes to choose from for the installation:
        online: Fetch the appropriate tools from online and use them to install the WinFE environment
        offline: Assumes that you already have the WinFE package, FTK Imagers, and Win 10 ADK 1803 Setup
    .PARAMETER DriveLetter <ltr>
        Choose the desired drive letter for which to configure the installation, no trailing slash
    .PARAMETER Installers <path>
        Path to the offline installers, required if choosing the offline mode.
    .PARAMETER Help
        Displays the available options and their usage
    .Example
        .\winfe.ps1 -DriveLetter F: -Online
        .\winfe.ps1 -DriveLetter E: -Offline -FilePath C:\Temp
    .TODO
        Make another TEMP directory besides Windows\Temp
    #>

param (
  [string]$DriveLetter,
  [string]$Mode = "online",
  [string]$FilePath = "C:\Temp",
  [switch]$MakeIso,
  [switch]$DownloadOnly,
  [switch]$Help,
  [string]$XUser = "",
  [string]$XPass = ""
)

[string]$VERSION = '1.2a'
[string]$FTKIMG_x86_VER="3.4.0.5"
[string]$FTKIMG_x86_SRC="https://ad-exe.s3.amazonaws.com/AccessData%20FTK%20Imager%203.4.0.5.exe"
[string]$FTKIMG_x86_FN="AccessData_FTK_Imager_3.4.0.5.exe"
[string]$FTKIMG_x86_HASH="F441D991DD1C1D31A427DF1520EC2705CC626D4A104BDD10F385ADE9E323A233"
[string]$FTKIMG_x64_VER="4.7.3.81"
[string]$FTKIMG_x64_SRC="https://d1kpmuwb7gvu1i.cloudfront.net/Imgr/4.7.3.81%20Release/Exterro_FTK_Imager_(x64)-4.7.3.81.exe"
[string]$FTKIMG_x64_FN="Exterro_FTK_Imager_(x64)-4.7.3.81.exe"
[string]$FTKIMG_x64_HASH="443843a3923a55d479d6ebb339dfbec12b5c1aabed196bf0541669abbe9b1c51"
[string]$WIN10ADK_VER="10.1.17134.1"
[string]$WIN10ADK_SRC="https://go.microsoft.com/fwlink/?linkid=873065"
[string]$WIN10ADK_FN="adksetup.exe"
[string]$WIN10ADK_HASH="DF32DF3AD55419D1B8D3536F66EA87D00C0993FDB6534552A9B274249F1C0353"
[string]$WINFE_SRC="https://www.winfe.net/files/IntelWinFE.7z"
[string]$WINFE_FN="IntelWinFE.7z"
[string]$WINFE_HASH="5F277E71AC57330017ABA534D38B09CD26EDA443BFF58F29733C005BEFD1F358"
[string]$7ZIP4PS_VER="2.1.0"
[string]$7ZIP4PS_SRC="https://psg-prod-eastus.azureedge.net/packages/7zip4powershell.2.1.0.nupkg"
[string]$7ZIP4PS_FN="7zip4powershell.2.1.0.nupkg"
[string]$7ZIP4PS_HASH="b9e82ba47e3fab78aa9ae484f3aa951938465ce29a89bebfacf0f5da9a7ec351"
[string]$NUGET_VER="2.8.5.208"
[string]$NUGET_SRC="https://onegetcdn.azureedge.net/providers/Microsoft.PackageManagement.NuGetProvider-2.8.5.208.dll"
[string]$NUGET_FN="Microsoft.PackageManagement.NuGetProvider.dll"
[string]$NUGET_HASH="de2ebfe08d13ab88efc596dcc2aa39982ebc61366a6a222789fadf8f902efc4a"
[string]$XWVERSION="212"
[string]$ADKPATH="C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit"
[string]$WPEPATH="$ADKPATH\Windows Preinstallation Environment"
[string]$DTPATH="$ADKPATH\Deployment Tools"
[string]$WINFEPATH="$FilePath\IntelWinFE"
[string]$TEMPPATH="$WINFEPATH\Temp"

$ProgressPreference = "SilentlyContinue"

function Compare-Hash($FileName, $HashName) {
    $fileHash = (Get-FileHash $FileName -Algorithm SHA256).Hash
    if ($fileHash -eq $HashName) {
        Write-Host "[+] Hashes match for $FileName, continuing..." -ForegroundColor Green
    } else {
        Write-Host "[+] Hashes do not match for $FileName, not continuing." -ForegroundColor Red
        exit
    }
}

function Copy-ADKFiles {

    # DT Files
    $DTFILES = [ordered]@{
    "amd64\BCDBoot\bootsect.exe" = @("USB\x86-x64\boot", "USB\x86-x64\x64\boot")
    "amd64\Oscdimg\efisys_noprompt.bin" = @("USB\x86-x64\efi\microsoft\boot\efisys.bin", "USB\x86-x64\x64\efi\microsoft\boot\efisys.bin")
    "amd64\Oscdimg\etfsboot.com" = @("Tools", "USB\x86-x64\boot", "USB\x86-x64\x64\boot")
    "amd64\Oscdimg\oscdimg.exe" = @("Tools")
    "x86\BCDBoot\bootsect.exe" = @("USB\x86-x64\x86\boot")
    "x86\Oscdimg" = @("USB\x86-x64\x86\boot")
    "x86\Oscdimg\efisys_noprompt.bin" = @("USB\x86-x64\x86\efi\microsoft\boot\efisys.bin")
    }
    foreach ($DTFILE in $DTFILES.Keys) { foreach ($DTDEST in $DTFILES[$DTFILE]) { Copy-Item -Path $ADKPATH\$DTFILE -Destination $WINFEPATH\$DTDEST } }

    # WPE Files
    $WPEFILES = [ordered]@{
    "amd64\en-us\winpe.wim" = @("x64")
    "amd64\Media\Boot\boot.sdi" = @("USB\x86-x64\boot", "USB\x86-x64\x64\boot")
    "amd64\Media\Boot\Fonts\*.ttf" = @("USB\x86-x64\boot\fonts", "USB\x86-x64\efi\microsoft\boot\fonts", "USB\x86-x64\x64\boot\fonts", "USB\x86-x64\x64\efi\microsoft\boot\fonts", "USB\x86-x64\x86\boot\fonts", "USB\x86-x64\x86\efi\microsoft\boot\fonts")
    "amd64\Media\Boot\memtest.exe" = @("USB\x86-x64\boot", "USB\x86-x64\x64\boot")
    "amd64\Media\bootmgr.efi" = @("USB\x86-x64", "USB\x86-x64\x64")
    "amd64\Media\EFI\Boot\bootx64.efi" = @("USB\x86-x64\efi\boot", "USB\x86-x64\x64\efi\boot")
    "amd64\Media\EFI\Microsoft\Boot\memtest.efi" = @("USB\x86-x64\efi\microsoft\boot", "USB\x86-x64\x64\efi\microsoft\boot")
    "amd64\WinPE_OCs\WinPE-EnhancedStorage.cab" = @("x64")
    "amd64\WinPE_OCs\WinPE-HTA.cab" = @("x64")
    "amd64\WinPE_OCs\WinPE-Scripting.cab" = @("x64")
    "amd64\WinPE_OCs\WinPE-SecureStartup.cab" = @("x64")
    "amd64\WinPE_OCs\WinPE-WMI.cab" = @("x64")
    "x86\en-us\winpe.wim" = @("x86")
    "x86\Media\Boot\boot.sdi" = @("USB\x86-x64\x86\boot")
    "x86\Media\Boot\memtest.exe" = @("USB\x86-x64\x86\boot")
    "x86\Media\bootmgr.efi" = @("USB\x86-x64\x86")
    "x86\Media\bootmgr" = @("USB\x86-x64", "USB\x86-x64\x64", "USB\x86-x64\x86")
    "x86\Media\EFI\Boot\bootia32.efi" = @("USB\x86-x64\efi\boot", "USB\x86-x64\x86\efi\boot")
    "x86\Media\EFI\Microsoft\Boot\memtest.efi" = @("USB\x86-x64\x86\efi\microsoft\boot")
    "x86\WinPE_OCs\WinPE-EnhancedStorage.cab" = @("x86")
    "x86\WinPE_OCs\WinPE-HTA.cab" = @("x86")
    "x86\WinPE_OCs\WinPE-Scripting.cab" = @("x86")
    "x86\WinPE_OCs\WinPE-SecureStartup.cab" = @("x86")
    "x86\WinPE_OCs\WinPE-WMI.cab" = @("x86")
    }
    foreach ($WPEFILE in $WPEFILES.Keys) { foreach ($WPEDEST in $WPEFILES[$WPEFILE]) { Copy-Item -Path $ADKPATH\$WPEFILE -Destination $WINFEPATH\$WPEDEST } }
}

function Create-TempDirs {
    if (Test-Path $TEMPPATH)
    {
        Remove-Item -Force $TEMPPATH -Recurse
    }
    New-Item -Path $TEMPPATH\sources -Force
    New-Item -Path $TEMPPATH\mount\Windows\System32\Config\systemprofile\Desktop -Force
}

function Create-DismImage {
    $Architectures = @("x64", "x86")
    foreach ($Arch in $Architectures) {
    Copy-Item $WINFEPATH\$Arch\winpe.wim $TEMPPATH\boot$Arch.wim
    $CabArray = "winpe-wmi.cab", "winpe-scripting.cab", "winpe-hta.cab", "Winpe-securestartup.cab", "Winpe-enhancedstorage.cab"
    Start-Process -Wait -FilePath "dism.exe" -ArgumentList "/Mount-Wim /WimFile:$TEMPPATH\boot$Arch.wim /index:1 /MountDir:$TEMPPATH\mount" -PassThru | Out-Null
    foreach ($Cab in $CabArray) {
        Start-Process -Wait -FilePath "dism.exe" -ArgumentList "/image:Temp\mount /Add-Package /PackagePath:$Arch\$Cab" -PassThru | Out-Null
        if ($?)
        {
            Write-Host "[+] Added packages $Cab"
        }
    }
    Copy-Item $WINFEPATH\$Arch\en-us\manage-bde.exe.mui $TEMPPATH\mount\windows\system32\en-us
    $Sys32Array = @(
        "explorer.exe",
        "explorerframe.dll",
        "menu.exe",
        "penetwork.exe",
        "penetwork.icl",
        "penetwork.ini",
        "penetwork_eng.lng",
        "penetwork_fr.lng",
        "penetwork_ger.lng",
        "penetwork_ita.lng",
        "penetwork_oldicons.icl",
        "penetwork_w10.icl",
        "penetwork_w10_gui_colored.icl",
        "protect.exe",
        "startnet.exe",
        "winpeshl.ini",
        "reset.exe",
        "advreset.exe",
        "fit.exe",
        "mfc140u.dll",
        "msvcp140.dll",
        "vcruntime140.dll",
        "avifil32.dll",
        "msacm32.dll",
        "msvfw32.dll",
        "wallpaper.jpg"
        )
    foreach ($File in $Sys32Array) {
        Copy-Item $WINFEPATH\$Arch\$File -Destination $TEMPPATH\mount\windows\system32\
        }
    }
}


function Install-ScriptRequirements {
    Write-Host "[-] Checking for Script Requirements" -ForegroundColor Yellow
    if (($Mode -eq 'offline') -and ($FilePath)) {
        if (-Not(Test-Path 'C:\Program Files\PackageManagement\ProviderAssemblies\nuget')) {
            Write-Host "[!] Missing the nuget module in your ProviderAssemblies folder. See -Help for more info" -ForegroundColor Red
            exit 1
        } else {
            Write-Host "[+] Nuget is installed, importing 7Zip4Powershell Module" -ForegroundColor Yellow
            New-Item -ItemType 'directory' -Path "C:\Temp" | Out-Null
            if (Get-Module -ListAvailable -Name 7Zip4Powershell) {
                Write-Host "[+] 7Zip4PowerShell module is already installed, continuing" -ForegroundColor Green
            } elseif (Test-Path "$FilePath\7Zip4Powershell.*") {
                Copy-Item -Path "$FilePath\7Zip4Powershell.*" -Destination "C:\Temp\"
                Register-PSRepository -Name Temp -SourceLocation "C:\Temp" -InstallationPolicy Trusted
                Install-Module -Name 7Zip4Powershell -Repository Temp
                Unregister-PSRepository -Name Temp
            } else {
                Write-Host "[!] 7Zip4Powershell module not found - check to see that it exists in $FilePath" -ForegroundColor Red
                exit 1
                }
        } 
    } elseif ($Mode -eq 'online') {
        if(-not(Test-Path $FilePath)) {
            Create-FilePath
        }
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Host "[-] Installing NuGet > v2.8.5.201" -ForegroundColor Yellow
        if (Test-Path 'C:\Program Files\PackageManagement\ProviderAssemblies\nuget') {
            Write-Host "[+] NuGet module is already available, continuing..." -ForegroundColor Green
        } else {
            Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force | Out-Null
        }
        if (Get-Module -ListAvailable -Name 7Zip4Powershell) {
            Write-Host "[+] 7Zip4PowerShell module is already installed, continuing" -ForegroundColor Green
        } else {
            Write-Host "[-] Installing 7Zip4Powershell Module > v2.1" -ForegroundColor Yellow
            Install-Module -Name 7Zip4Powershell -MinimumVersion 2.1 -Force | Out-Null
        }
    }
    Write-Host "[+] Requirements met, continuing..." -ForegroundColor Green
}

function Test-ADK {
    $InstalledADK = (Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*','HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*' | Where-Object {$_.DisplayName -clike '*Assessment and Deployment Kit*' } | Select-Object DisplayName, DisplayVersion )
    if ($null -eq $InstalledADK.DisplayName) {
        return $False
    } elseif ($InstalledADK.DisplayName -clike '*Assessment and Deployment Kit*' -and $InstalledADK.DisplayVersion -eq $WIN10ADK_VER) {
        Write-Host "[+] Windows 10 Assessment and Deployment Kit is already installed"
        return $True
    }
}

function Start-Downloads {
	if (-not(Test-Path $FilePath)) {
		Create-FilePath
	}
    Write-Host "[-] Beginning file downloads" -ForegroundColor Yellow
    $DOWNLOADS = [ordered]@{
        "$WIN10ADK_SRC" = "$WIN10ADK_FN" ;
#        "$FTKIMG_x86_SRC" = "$FTKIMG_x86_FN" ;
        "$FTKIMG_x64_SRC" = "$FTKIMG_x64_FN" ;
        "$WINFE_SRC" = "$WINFE_FN";
		"$7ZIP4PS_SRC" = "$7ZIP4PS_FN"
    }
    $SKIPADK = Test-ADK
    if ($SKIPADK) {
        $DOWNLOADS.RemoveAt(0)
    }
    foreach ($DOWNLOAD in $DOWNLOADS.GetEnumerator()) {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        Write-Host "[-] Downloading $($DOWNLOAD.Name) to $FilePath\$($DOWNLOAD.Value)" -ForegroundColor Yellow
        Start-BitsTransfer -Source $($DOWNLOAD.Name) -Destination "$FilePath\$($DOWNLOAD.Value)"
    }
    $HASHES = [ordered]@{
        "$FilePath\$WIN10ADK_FN" = "$WIN10ADK_HASH" ;
#        "$FilePath\$FTKIMG_x86_FN" = "$FTKIMG_x86_HASH" ;
        "$FilePath\$FTKIMG_x64_FN" = "$FTKIMG_x64_HASH" ;
        "$FilePath\$WINFE_FN" = "$WINFE_HASH";
		"$FilePath\$7ZIP4PS_FN" = "$7ZIP4PS_HASH"
    }
    if ($SKIPADK) {
        $HASHES.RemoveAt(0)
    }
    foreach ($HASH in $HASHES.GetEnumerator()) {
        Compare-Hash -FileName $($HASH.Name) -HashName $($HASH.Value)
    }
    if (($XUser -ne "") -and ($XPass -ne "")) {
        Download-XWays
    }

}

function Install-WinFERequirements {
    $SKIPADK = Test-ADK
    if (($Mode -eq 'offline') -and ($FilePath)) {
        $FilePath = $FilePath.TrimEnd('\')
        $HASHES = [ordered]@{
            "$FilePath\$WIN10ADK_FN" = "$WIN10ADK_HASH" ;
#            "$FilePath\$FTKIMG_x86_FN" = "$FTKIMG_x86_HASH" ;
            "$FilePath\$FTKIMG_x64_FN" = "$FTKIMG_x64_HASH" ;
            "$FilePath\$WINFE_FN" = "$WINFE_HASH"
        }
        if ($SKIPADK) {
            $HASHES.RemoveAt(0)
        }
        foreach ($HASH in $HASHES.GetEnumerator()) {
            Compare-Hash -FileName $($HASH.Name) -HashName $($HASH.Value)
        }
    } elseif ($Mode -eq 'online') {
        $FilePath = "C:\Temp"
    }
    #$PROGRAMS = [ordered]@{ "$FTKIMG_x86_FN" = '/s /v/qn /v"INSTALLDIR="C:\FTKIMGx86""' ; "$FTKIMG_x64_FN" = '/s /v/qn /v"INSTALLDIR="C:\FTKIMGx64""'; "$WIN10ADK_FN" = "/quiet"}
    $PROGRAMS = [ordered]@{ "$WIN10ADK_FN" = "/quiet"; "$FTKIMG_x64_FN" = '/s /v/qn /v"INSTALLDIR="C:\FTKIMGx64""'}
    if ($SKIPADK) {
        $PROGRAMS.RemoveAt(0)
    }
    if ($PROGRAMS.Count -eq 0) {
    Write-Host "[+] All requirements installed, continuing..."
    }
    else {
        foreach ($PROGRAM in $PROGRAMS.GetEnumerator()) {
            Write-Host "[-] Installing $($PROGRAM.Name)" -ForegroundColor Yellow
            Start-Process -Wait -FilePath "$FilePath\$($PROGRAM.Name)" -ArgumentList "$($PROGRAM.Value)" -PassThru | Out-Null
            if ($?) {
                Write-Host "[+] $($PROGRAM.Name) installed successfully" -ForegroundColor Green
                if ($($PROGRAM.Name) -like "*FTK*") { 
                    $INSTALLDIR = $($PROGRAM.Value).Split('=').Split('"')[3]
                    $DEST = $INSTALLDIR.Split('\')[1]
                    Write-Host "[-] Creating $FilePath\$DEST" -ForegroundColor Yellow
                    New-Item -ItemType "directory" -Path "$FilePath\" -Name "$DEST" -Force | Out-Null
                    Get-ChildItem -Path "$INSTALLDIR\FTK Imager\" | Copy-Item -Destination "$FilePath\$DEST" -Recurse -Container -Force
                    Write-Host "[+] $INSTALLDIR\FTK Imager\ copied to $FilePath\$DEST" -ForegroundColor Green
                    Start-Process -Wait -FilePath "$FilePath\$($PROGRAM.Name)" -ArgumentList "/x /s /v/qn" -PassThru | Out-Null 
                    if ($?) {
                        Write-Host "[+] $($PROGRAM.Name) uninstalled" -ForegroundColor Green
                    } else {
                        Write-Host "[!] $($PROGRAM.Name) could not be uninstalled" -ForegroundColor Red
                    }
                } 
            } else {
                Write-Host "[!] Installation of $($PROGRAM.Name) failed. Please re-run the installer to try again" -ForegroundColor Red
                exit 1
            }
        }
    }
} 

function Extract-WinFE {
    Write-Host "[-] Extracting WinFE to $FilePath" -ForegroundColor Yellow
    Expand-7Zip -ArchiveFileName "$FilePath\$WINFE_FN" -TargetPath "$FilePath\IntelWinFE"
}

function Extract-FTKImager8664 {
    Write-Host "[-] Extracting FTK Imager x86 to $FilePath" -ForegroundColor Yellow
    Expand-7Zip -ArchiveFileName "$FilePath\$FTKIMG_x86_FN" -TargetPath "$FilePath\FTKIMGx86"
    if ($?) {
        Write-Host "[+] FTK Imager x86 extracted successfully" -ForegroundColor Green
    }
    Write-Host "[-] Extracting FTK Imager x64 to $FilePath" -ForegroundColor Yellow
    Expand-7Zip -ArchiveFileName "$FilePath\$FTKIMG_x64_FN" -TargetPath "$FilePath\FTKIMGx64"
        if ($?) {
        Write-Host "[+] FTK Imager x64 extracted successfully" -ForegroundColor Green
    }
}

function Move-Requirements {
#    New-Item -ItemType "directory" -Path "$FilePath\IntelWinFE\USB\x86-x64\tools\x86\" -Name "FTK Imager" -Force | Out-Null
    New-Item -ItemType "directory" -Path "$FilePath\IntelWinFE\USB\x86-x64\tools\x64\" -Name "FTK Imager" -Force | Out-Null
#    Write-Host "[-] Copying FTK Imager x86 installation to $FilePath\IntelWinFE\USB\x86-x64\tools\x86\FTK Imager" -ForegroundColor Yellow
#    Get-ChildItem -Path "$FilePath\FTKIMGx86\" | Copy-Item -Destination "$FilePath\IntelWinFE\USB\x86-x64\tools\x86\FTK Imager" -Recurse -Container
    Write-Host "[-] Copying FTK Imager x64 installation to $FilePath\IntelWinFE\USB\x86-x64\tools\x64\FTK Imager" -ForegroundColor Yellow
    Get-ChildItem -Path "$FilePath\FTKIMGx64\" | Copy-Item -Destination "$FilePath\IntelWinFE\USB\x86-x64\tools\x64\FTK Imager" -Recurse -Container
    if (($XUser -ne "") -and ($XPass -ne "")){
        New-Item -ItemType "directory" -Path "$FilePath\IntelWinFE\USB\x86-x64\tools\x86\" -Name "X-Ways" -Force | Out-Null
        New-Item -ItemType "directory" -Path "$FilePath\IntelWinFE\USB\x86-x64\tools\x64\" -Name "X-Ways" -Force | Out-Null
        Write-Host "[-] Copying X-Ways installation to $FilePath\IntelWinFE\USB\x86-x64\tools\x86\X-Ways" -ForegroundColor Yellow
        Expand-7Zip -ArchiveFileName "$FilePath\xw_forensics$XWVERSION.zip" -TargetPath "$FilePath\IntelWinFE\USB\x86-x64\tools\x86\X-Ways"
        Expand-7Zip -ArchiveFileName "$FilePath\xw_viewer.zip" -TargetPath "$FilePath\IntelWinFE\USB\x86-x64\tools\x86\X-Ways"
        Write-Host "[-] Copying X-Ways installation to $FilePath\IntelWinFE\USB\x86-x64\tools\x64\X-Ways" -ForegroundColor Yellow
        Expand-7Zip -ArchiveFileName "$FilePath\xw_forensics$XWVERSION.zip" -TargetPath "$FilePath\IntelWinFE\USB\x86-x64\tools\x64\X-Ways"
        Expand-7Zip -ArchiveFileName "$FilePath\xw_iewer.zip" -TargetPath "$FilePath\IntelWinFE\USB\x86-x64\tools\x64\X-Ways"
    }
}

function Run-WinFEBatch {
    Set-Location -Path "$FilePath\IntelWinFE\"
    Write-Host "[-] Running MakeWinFEx64-x86.bat" -ForegroundColor Yellow
    Start-Process -Wait -FilePath "$FilePath\IntelWinFE\MakeWinFEx64-x86.bat" -PassThru -NoNewWindow
}

function Build-ISO {
    Set-Location -Path "$FilePath\IntelWinFE\"
    Write-Host "[-] Running Makex64-x86-CD.bat to create an ISO" -ForegroundColor Yellow
    Start-Process -Wait -FilePath "$FilePath\IntelWinFE\Makex64-x86-CD.bat" -PassThru -NoNewWindow
}

function Prepare-Disk {
    Write-Host "[-] Preparing USB drive for WinFE" -ForegroundColor Yellow
    $DiskNumber = (Disk-Info | ? DriveLetter -eq $DriveLetter | Foreach { $_.DiskNumber})
    Write-Host "[-] Clearing $DriveLetter, Disk Number $DiskNumber" -ForegroundColor Yellow
    Get-Disk $DiskNumber | Clear-Disk -RemoveData -Confirm:$false
    Set-Disk -Number $DiskNumber -PartitionStyle MBR
    Write-Host "[-] Creating a new partition on $DriveLetter, making it active, creating FAT32 File System" -ForegroundColor Yellow
    if ((Get-Disk $DiskNumber | foreach {$_.Size}) -gt 34359738368) {
        New-Partition -DiskNumber $DiskNumber -Size 34359738368 -DriveLetter $DriveLetter.TrimEnd(':') -IsActive:$true | 
        Format-Volume -FileSystem FAT32 -NewFileSystemLabel WinFE | Out-Null
    } else {
        New-Partition -DiskNumber $DiskNumber -UseMaximumSize -DriveLetter $DriveLetter.TrimEnd(':') -IsActive:$true | 
        Format-Volume -FileSystem FAT32 -NewFileSystemLabel WinFE | Out-Null
    }
    Write-Host "[-] Copying contents of $FilePath\IntelWinFE\USB\x86-x64 to $DriveLetter" -ForegroundColor Yellow
    Get-ChildItem -Path "$FilePath\IntelWinFE\USB\x86-x64" | Copy-Item -Destination $DriveLetter -Recurse -Container
    Write-Host "[-] Modifying Boot Sector" -ForegroundColor Yellow
    bootsect.exe /NT60 $DriveLetter /force /mbr | Out-Null
    if ($?) {
        Write-Host "[+] Installation complete! You may now safely eject your device." -ForegroundColor Green
    } else {
        Write-Host "[!] Installation failed! You may want to retry the installation again." -ForegroundColor Red
        exit 1
    }
}

function Disk-Info {
    Get-CimInstance Win32_Diskdrive -pv Disk |
    % { Get-CimAssociatedInstance $_ -Result Win32_DiskPartition -pv Partition }|
    % { Get-CimAssociatedInstance $_ -Result Win32_LogicalDisk } |
    Select-Object @{n='DriveLetter';e={$_.DeviceID}},
    @{n='DiskNumber';e={$Partition.DiskIndex}},
    @{n='PartitionNumber';e={$Partition.Index}},
    @{n='Disk';e={$Disk.DeviceID}},
    @{n='DiskSize';e={$Disk.size}},
    @{n='DiskModel';e={$Disk.model}},
    @{n='Partition';e={$Partition.name}},
    @{n='RawSize';e={$Partition.size}}
}

function Download-XWays() {
    $AuthToken = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($XUser + ":" + $XPass))
    Invoke-WebRequest -Uri "http://www.x-ways.net/xwf/xw_forensics$XWVERSION.zip" -Method GET -Headers @{ Authorization = "Basic $AuthToken" } -UserAgent "IPWorks HTTPComponent - www.nsoftware.com" -UseBasicParsing -OutFile $FilePath\xw_forensics$XWVERSION.zip
    Invoke-WebRequest -Uri "http://www.x-ways.net/res/viewer/xw_viewer.zip" -Method GET -Headers @{ Authorization = "Basic $AuthToken" } -UserAgent "IPWorks HTTPComponent - www.nsoftware.com" -UseBasicParsing -OutFile $FilePath\xw_viewer.zip
}

function Build-All {
    Extract-WinFE
    # Extract-FTKImager8664
    Move-Requirements
    Run-WinFEBatch
    if ($MakeIso) {
        Build-ISO
    }
    Prepare-Disk
}

function Invoke-WinFEInstaller {
    $runningUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $runningUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Host "[!] Not running as administrator, please re-run this script as Administrator" -ForegroundColor Red
        exit 1
    }
    if (-not($DriveLetter)) {
        Write-Host "[!] You must supply a value for DriveLetter" -ForegroundColor Red
        $AllDrives = (Get-CimInstance -ClassName Win32_volume | Where-Object DriveLetter -NE $null | Select @{n="Drive Letter";e={$_.DriveLetter}},@{n="Serial Number"; e={$_.SerialNumber.toString()}},@{n="File System";e={$_.Filesystem}},@{n="Capacity (GB)";e={[math]::truncate($_.Capacity / 1GB)}}) | Out-String
        $AllDrives
#        Get-WmiObject -class Win32_volume | Select DriveLetter,SerialNumber,Filesystem,@{n="Capacity / MB";e={[math]::truncate($_.Capacity / 1MB)}} | ? DriveLetter -ne "C:" | ? DriveLetter -ne $null
        exit 1
    }
    $DriveLetter = $DriveLetter.TrimEnd("\")
	if ($DriveLetter -eq "C:") {
		Write-Host "[!] DriveLetter cannot be C:. Please choose another drive letter" -ForegroundColor Red
		exit 1
	}
    $FilePath = $FilePath.TrimEnd("\")
    if (($Mode -ne "online") -and ($Mode -ne "offline")) {
        Write-Host "[!] The only valid modes are 'online' or 'offline'." -ForegroundColor Red
        exit 1
    }
    if ($Mode -eq "online") {
        Install-ScriptRequirements
        Start-Downloads
        Install-WinFERequirements
        Build-All
    } elseif ($Mode -eq "offline") {
        Install-ScriptRequirements
        Install-WinFERequirements
        Build-All
    }
}

function Create-FilePath {
	New-Item -ItemType "directory" -Path $FilePath | Out-Null
}

function Make-ISO {
    Install-ScriptRequirements
    Start-Downloads
    Install-WinFERequirements
    Extract-WinFE
    Extract-FTKImager8664
    Move-Requirements
    Run-WinFEBatch
    Build-ISO
}

function Show-WinFEInstallerHelp {
    Write-Host -ForegroundColor Yellow @"
Windows Forensics Environment (WinFE) Installer $VERSION
https://winfe.net

Usage:
    -DriveLetter <ltr> Choose the desired drive letter for which to configure the installation, no trailing slash
    -Mode <mode>       There are two modes to choose from for the installation:
                       online: Fetch the appropriate tools from online and use them to install the WinFE environment
                       offline: Assumes that you already have the WinFE package, FTK Imagers, and Win 10 ADK 1803 Setup
    -Installers <path> Path to the offline installers, required if choosing the offline mode.
    -MakeIso           When selected, this will create a bootable ISO
    -DownloadOnly      Will download the staging files for download, except the NuGet PowerShell module. Use -FilePath
					   to set the directory to download the files to. If not used, the default (C:\temp) will be used.
When selecting the Offline mode, the following files will be required:
    
    Nuget Powershell Module            (Install Nuget on an online machine and copy nuget folder from
                                       C:\Program Files\PackageManagement\ProviderAssemblies\ into the
                                       same location on this computer)                        
    7Zip4Powershell.2.1.0.nupkg        $7ZIP4PS_SRC
    AccessData FTK Imager 3.4.0.5      $FTKIMG_x86_SRC
    AccessData FTK Imager 4.7.3.81     $FTKIMG_x64_SRC
    Windows 10 ADK 1803                $WIN10ADK_SRC
    The latest Intel WinFE package     $WINFE_SRC
"@
}
if ($PSBoundParameters.Count -eq 0) {
    Show-WinFEInstallerHelp
    exit 1
} elseif ($Help -and $PSBoundParameters.Count -eq 1) {
    Show-WinFEInstallerHelp
    exit 1
} elseif (($Mode -eq 'online') -and ($PSBoundParameters.Count -ge 2) -and ($PSBoundParameters.ContainsKey('FilePath'))-and ($PSBoundParameters.ContainsKey('Mode'))) {
    Write-Host "[!] FilePath is only required for offline installation" -ForegroundColor Red
    exit 1
} elseif ($DownloadOnly) {
    Start-Downloads
	if ($?) { 
	    Write-Host "[+] Downloads complete. Files saved to $FilePath." -ForegroundColor Green
	} else { 
	    Write-Host "[!] One or more downloads failed." -ForegroundColor Red
	}
	exit 1
} elseif ($MakeIso) {
    Make-ISO
} else {
    Invoke-WinFEInstaller
}
