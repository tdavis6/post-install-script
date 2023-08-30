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
    winget install --id=7zip.7zip -e  ; winget install --id=Adobe.Acrobat.Reader.32-bit -e  ; winget install --id=Git.Git -e  ; winget install --id=JanDeDobbeleer.OhMyPosh -e  ; winget install --id=JohnMacFarlane.Pandoc -e  ; winget install --id=Ombrelin.PandocGui -e  ; winget install --id=Microsoft.dotnet -e  ; winget install --id=Microsoft.PowerShell -e  ; winget install --id=Microsoft.PowerToys -e  ; winget install --id=Microsoft.WindowsTerminal -e  ; winget install --id=Notepad++.Notepad++ -e  ; winget install --id=VideoLAN.VLC -e  ; winget install --id=Discord.Discord -e  ; winget install --id=MiKTeX.MiKTeX -e  ; winget install --id=TeXstudio.TeXstudio -e  ; winget install --id=OBSProject.OBSStudio -e  ; winget install --id=Spotify.Spotify -e  ; winget install --id=VB-Audio.VoiceMeeterBanana -e  ; winget install --id=Mozilla.Thunderbird -e  ; winget install --id=DigitalScholar.Zotero -e  ; winget install --id=Microsoft.VisualStudio.2022.Community -e  ; winget install --id=Anki.Anki -e  ; winget install --id=MilosParipovic.OneCommander -e  ; winget install --id=Valve.Steam -e  ; winget install --id=voidtools.Everything -e  ; winget install --id=stnkl.EverythingToolbar -e  ; winget install --id=SamHocevar.WinCompose -e 
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
    installAll
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
restart-computer