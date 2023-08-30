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
        @{name = "VB-Audio.Voicemeeter.Banana"},
        @{name = "Mozilla.Thunderbird"},
        @{name = "DigitalScholar.Zotero"},
        @{name = "Microsoft.VisualStudio.2022.Community"},
        @{name = "Anki.Anki"},
        @{name = "MilosParipovic.OneCommander"},
        @{name = "Valve.Steam"},
        @{name = "voidtools.Everything"},
        @{name = "stnkl.EverythingToolbar"},
        @{name = "SamHocevar.WinCompose"}
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