# Script d'installation de Ghidra 10.2.3
# Cree par : Kuroakashiro
# Start-Process -FilePath "$PWD\InstallGhidra.ps1" -Credential "$env:USERNAME"





$Back = "$PWD"
Write-Host ""
Write-Host ""
Write-Host "Installation de Ghidra 10.2.3 !" -ForegroundColor Green 
Write-Host "Attendee la fin de l'installation !" -ForegroundColor Magenta
Write-Host "Installation dans : '$env:USERPROFILE\'" -ForegroundColor Yellow 
Write-Host "[ in ] pour installer !"
Write-Host "[ un ] pour desinstaler !"
Write-Host ""
$user = Read-Host ": "

function install {
    $Back = "$PWD"
    #---------------
    # Install Ghibra

    curl -O "Ghidra 10.2.3.zip" "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.2.3_build/ghidra_10.2.3_PUBLIC_20230208.zip"
    
    if ($? -eq $True) {
        Write-Host "[OK] " -ForegroundColor Green -NoNewline
        Write-Host "Telechargement de Ghibra !"
    } else {Write-Host "[ERREUR] " -ForegroundColor Red -NoNewline; Write-Host "Telechargement de Ghibra";}
    Start-Sleep 5
    Expand-Archive -Path "$Back\Ghidra 10.2.3.zip" -DestinationPath "$env:USERPROFILE\"
    if ($? -eq $True) {
        Write-Host "[OK] " -ForegroundColor Green -NoNewline
        Write-Host "Decompression Ghibra !"
        cd "$Back"
        rm -force "$Back\Ghidra 10.2.3*.zip"
    } else {Write-Host "[ERREUR] " -ForegroundColor Red -NoNewline; Write-Host "Decompression Ghibra";}
    cd "$env:USERPROFILE\"
    Rename-Item "$env:USERPROFILE\ghidra_10.2.3_PUBLIC" -NewName "$env:USERPROFILE\Ghidra 10.2.3"
    #---------------
    # Retour Back
    cd "$Back"
    #---------------
    # Install Java
    java -version > $null 2>&1
    if ($? -eq $False) {

    curl -O "JavaSetup8u361.exe" "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=247917_0ae14417abb444ebb02b9815e2103550"
        
        Start-Process "JavaSetup8u361.exe" -Wait
        if ($? -eq $False) {
            Write-Host "[ERREUR] " -ForegroundColor Red -NoNewline
            Write-Host "Installation Java"
            Start-Sleep 10
            exit
        }
        # Retour Back
        cd "$Back"
        rm -force "JavaSetup8u361*.exe"
    } else {Write-Host "[ERREUR] " -ForegroundColor Red -NoNewline; Write-Host "Installation Java";}
    #---------------
    # Install JDK
    # Retour Back
    cd "$Back"

    
    curl -O "jdk-19_windows-x64_bin.exe" "https://download.oracle.com/java/17/latest/jdk-17_windows-x64_bin.exe"

    if ($? -eq $True) {
        Write-Host "[OK] " -ForegroundColor Green -NoNewline
        Write-Host "Telechargement de JDK !"
    } else {Write-Host "[ERREUR] " -ForegroundColor Red -NoNewline; Write-Host "Telechargement de JDK";}

    # Start-Process "jdk-19_windows-x64_bin.msi" -Wait
    .\jdk-19_windows-x64_bin.exe
    if ($? -eq $True) {
        Write-Host "[OK] " -ForegroundColor Green -NoNewline
        Write-Host "Installation JDK !"
    } else {Write-Host "[ERREUR]" -ForegroundColor Red -NoNewline; Write-Host "Installation JDK";}
    # Retour Back
    cd "$Back"
    rm -force "$Back\jdk-19_windows-x64_bin*.exe"
    #---------------
    # Racourci bureau de Ghibra
    cd "$Back"
    $WshShell = New-Object -ComObject WScript.Shell
    $Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Ghidra_10.2.3.lnk")
    $Shortcut.TargetPath = "$env:USERPROFILE\Ghidra 10.2.3\ghidraRun.bat"
    $Shortcut.IconLocation = "$env:USERPROFILE\Ghidra 10.2.3\support\ghidra.ico, 0"
    $Shortcut.Save()
    if ($? -eq $True) {
        Write-Host "[OK] " -ForegroundColor Green -NoNewline
        Write-Host "Racourci Ghidra cree !"
    } else {Write-Host "[ERREUR] " -ForegroundColor Red -NoNewline; Write-Host "Racourci Ghidra";}

    Start-Sleep 5

}

function uninstall {
    $Back = "$env:USERPROFILE\"
    Start-Process powershell.exe -Verb runAs -ArgumentList "-File `"$PWD\InstallGhidra.ps1`""
    if (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))
    {
    Write-Host "Le script nececite des droit Administrateur !" -ForegroundColor Red 
    Write-Host "Executer la commande 'set-executionpolicy remotesigned'" -ForegroundColor Yellow 
    Write-Host "dans un terminal PowerShell administrateur" -ForegroundColor Yellow 
    Write-Host "et re executer le script !" -ForegroundColor Yellow 
    Start-Sleep 10
    exit
    }
    # Java
    Write-Host "Desinstallation Java !  " -ForegroundColor Yellow -NoNewline
    Write-Host "..." -ForegroundColor Yellow
    curl -O "JavaSetup8u361.exe" "https://javadl.oracle.com/webapps/download/AutoDL?BundleId=247917_0ae14417abb444ebb02b9815e2103550"
    if ($? -eq $True) {
        Start-Process JavaSetup8u361.exe -ArgumentList "/s REBOOT=Suppress REMOVEOUTOFDATEJRES=1" -Wait -NoNewWindow
        if ($? -eq $True) {
            Write-Host "[OK] " -ForegroundColor Green -NoNewline
            Write-Host "Java desinstalle"
        } else {Write-Host "[ERREUR] " -ForegroundColor Red; Write-Host "Desinstallation Java !"; }
        rm -force "JavaSetup8u361.exe"
    }

    # JDK
    Write-Host "Desinstallation JDK !  " -ForegroundColor Yellow -NoNewline
    Write-Host "..." -ForegroundColor Yellow
    if (-not (Test-Path "jdk-19_windows-x64_bin.msi")) {
        curl -O "jdk-19_windows-x64_bin.msi" "https://download.oracle.com/java/19/archive/jdk-19.0.2_windows-x64_bin.msi"
    }
    if ($? -eq $True) {
        msiexec /x jdk-19_windows-x64_bin.msi /quiet
        if ($? -eq $True) {
            Write-Host "[OK] " -ForegroundColor Green -NoNewline
            Write-Host "JDK desinstalle"
        } else {Write-Host "[ERREUR] " -ForegroundColor Red; Write-Host "Desinstallation JDK !"; }
        rm -force "jdk-19_windows-x64_bin.msi"
    }

    # Racourci
    Write-Host "Desinstallation Racourci !  " -ForegroundColor Yellow -NoNewline
    Write-Host "..." -ForegroundColor Yellow
    if (Test-Path "$env:USERPROFILE\Desktop\Ghidra_10.2.3.lnk") {
        rm -force "$env:USERPROFILE\Desktop\Ghidra_10.2.3.lnk"
    }
    if ($? -eq $True) {
        Write-Host "[OK] " -ForegroundColor Green -NoNewline
        Write-Host "Racourci desinstalle"
    } else {Write-Host "[ERREUR] " -ForegroundColor Red; Write-Host "Desinstallation Racourci !"; }

    # Ghidra
    Write-Host "Desinstallation Ghidra !  " -ForegroundColor Yellow -NoNewline
    Write-Host "..." -ForegroundColor Yellow
    if (Test-Path "$env:USERPROFILE\Ghidra 10.2.3") {
        rm -force "$env:USERPROFILE\Ghidra 10.2.3"
    }
    if ($? -eq $True) {
        Write-Host "[OK] " -ForegroundColor Green -NoNewline
        Write-Host "Ghidra 10.2.3 desinstalle"
    } else {Write-Host "[ERREUR] " -ForegroundColor Red; Write-Host "Ghidra"; }

    Start-Sleep 5
}

if ($user -eq "in") {
    clear
    install
}

if ($user -eq "un") {
    clear
    uninstall
}

# desinstaller 
# msiexec /x jdk-19_windows-x64_bin.msi /quiet



