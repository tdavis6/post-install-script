param([switch]$Elevated)

function testAdmin {
  $currentUser = New-Object Security.Principal.WindowsPrincipal $([Security.Principal.WindowsIdentity]::GetCurrent())
  $currentUser.IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
}

if ((testAdmin) -eq $false)  {
    if ($elevated) {
        Please allow elevation to run properly.
    } 
    else {
        Start-Process powershell.exe -Verb RunAs -ArgumentList ('-noprofile -noexit -file "{0}" -elevated' -f ($myinvocation.MyCommand.Definition))
    }
    exit
}

Clear-Host

$title = "Windows Post Install"
$host.UI.RawUI.WindowTitle = $title

function Show-Menu {
    Write-Host "================ $title ================"
    Write-Host "1: Press '1' To Install All Apps"
    Write-Host "2: Press '2' To Disable Bing Search In Start Menu."
    Write-Host "3: Press '3' To Disable Modern Standby."
    Write-Host "4: Press '4' To Uninstall Edge"
    Write-Host "4: Press '5' To Uninstall OneDrive"
    Write-Host "A: Press 'A' To Run All."
    Write-Host "Q: Press 'Q' To Quit."
    Write-Host "`n"
}

function installAll {
    Write-Output "Installing Apps"
    $apps = @(
        @{name = "7zip.7zip" },
        @{name = "Adobe.Acrobat.Reader.64-bit" },
        @{name = "Git.Git" },
        @{name = "JanDeDobbeleer.OhMyPosh" },
        @{name = "JohnMacFarlane.Pandoc" },
        @{name = "Microsoft.dotnet" },
        @{name = "Microsoft.PowerShell" },
        @{name = "Microsoft.PowerToys" },
        @{name = "Microsoft.WindowsTerminal" },
        @{name = "Mozilla.Firefox" },
        @{name = "Notepad++.Notepad++" },
        @{name = "VideoLAN.VLC" },
        @{name = "Discord.Discord"},
        @{name = "MiKTeX.MiKTeX"},
        @{name = "TeXstudio.TeXstudio"},
        @{name = "OBSProject.OBSStudio"},
        @{name = "Spotify.Spotify"},
        @{name = "VB-Audio.Voicemeeter.Potato"},
        @{name = "Mozilla.Thunderbird"},
        @{name = "DigitalScholar.Zotero"},
        @{name = "Microsoft.VisualStudio.2022.Community"},
        @{name = "Anki.Anki"},
        @{name = ""}
        );
    Foreach ($app in $apps) {
        $listApp = winget list --exact -q $app.name
        if (![String]::Join("", $listApp).Contains($app.name)) {
            Write-host "Installing: " $app.name
            winget install -e -h --accept-source-agreements --accept-package-agreements --id $app.name 
        }
        else {
            Write-host "Skipping: " $app.name " (already installed)"
        }
    }
}

function disableBing {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "BingSearchEnabled" -Value 00000000 -Force -ErrorAction SilentlyContinue
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "CortanaConsent" -Value 00000000 -Force -ErrorAction SilentlyContinue
    Write-Host "Bing Search Disabled."
    Write-Host "`n"
}

function disableModernStandby {
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Control\Power" -Name "PlatformAoAcOverride" -Value 00000000 -Type "DWORD" -Force -ErrorAction SilentlyContinue
    Write-Host "Modern Standby Off, Please Reboot."
    Write-Host "`n"
}

function uninstallEdge {
    $edge = ${Env:ProgramFiles(x86)} + "\Microsoft\Edge\Application"

    if (Test-Path $edge) {
        Get-ChildItem -Path $edge -Filter setup.exe -Recurse -ErrorAction SilentlyContinue -Force |
        Foreach-Object {
            # Write-Host $_.FullName
            Start-Process $_.FullName "-uninstall -system-level -verbose-logging -force-uninstall" -wait
            Write-Host "Edge Is Uninstalled."
            Write-Host "`n"
        }
    } else {
        Write-Host "Good News! Edge Is Not Insalled... Yet."
        Write-Host "`n"
    }
}

function uninstallOneDrive {
    $x86 = $Env:SystemRoot + "\System32\OneDriveSetup.exe"
    $x64 = $Env:SystemRoot + "\SysWOW64\OneDriveSetup.exe"

    $OneDriveActive = Get-Process OneDrive -ErrorAction SilentlyContinue
    if ($null -eq $OneDriveActive) {
        Write-Host "OneDrive is not running."
        Write-Host "`n"
    } else {
        Write-Host "Closing OneDrive process."
        taskkill /f /im OneDrive.exe
        Write-Host "`n"
    }

    if (Test-Path $x86, $x64) {
        Write-Host "Uninstalling OneDrive."
        Write-Host "`n"
        if (Test-Path -Path $x64) {
            Start-Process $x64 /uninstall -wait
        } else {
            Start-Process $x86 /uninstall -wait
        }
        Write-Host "Removing OneDrive leftovers."
        Remove-Item $Env:USERPROFILE"\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "C:\OneDriveTemp" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $Env:APPDATA"\Microsoft\OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item $Env:ProgramData"\Microsoft OneDrive" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "`n"
        Write-Host "Removing OneDrive from the Explorer Side Panel."
        Remove-Item "Registry::HKEY_CLASSES_ROOT\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force -ErrorAction SilentlyContinue
        Remove-Item "Registry::HKEY_CLASSES_ROOT\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" -Recurse -Force -ErrorAction SilentlyContinue
        Write-Host "`n"
    } else {
        "OneDriveSetup.exe could not be found."
        Write-Host "`n"
    }
}

function runAll {
    disableBing
    disableModernStandby
    uninstallEdge
    uninstallOneDrive
}

do {
    Show-Menu
    $userInput = Read-Host "Please make a selection"
    Write-Host "`n"
    switch ($userInput) {
         '1' {
            installAll
        } 
        '2' {
            disableBing
        } 
        '3' {
            disableModernStandby
        } 
        '4' {
            uninstallEdge
        }
        '5' {
            uninstallOneDrive
        }
        'a' {
            runAll
        } 
        'q' {
            stop-process -Id $PID
        }
    }
    pause
    Write-Host "`n"
}
until ($userInput -eq 'q')