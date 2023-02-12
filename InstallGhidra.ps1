# Script d'installation de Ghidra 10.2.3
# Cree par : Kuroakashiro
$Back = "$PWD"
Write-Host ""
Write-Host ""
Write-Host "Installation de Ghidra 10.2.3 !" -ForegroundColor Green 
Write-Host "Attendee la fin de l'installation !" -ForegroundColor Magenta
Write-Host "Installation dans : '$env:USERPROFILE\'" -ForegroundColor Yellow 
Write-Host ""
Write-Host ""
Start-Sleep 5
#---------------
# Install Ghibra
curl -O "Ghidra 10.2.3.zip" "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.2.3_build/ghidra_10.2.3_PUBLIC_20230208.zip"
if ($? -eq $True) {
    Write-Host "[OK]" -ForegroundColor Green -NoNewline
    Write-Host "Telechargement de Ghibra !"
} else {Write-Host "[ERREUR]" -ForegroundColor Red -NoNewline; Write-Host "Telechargement de Ghibra";}

Expand-Archive -Path "Ghidra 10.2.3.zip" -DestinationPath "$env:USERPROFILE\"
if ($? -eq $True) {
    Write-Host "[OK]" -ForegroundColor Green -NoNewline
    Write-Host "Decompression Ghibra !"
} else {Write-Host "[ERREUR]" -ForegroundColor Red -NoNewline; Write-Host "Decompression Ghibra";}
cd "$Back"
rm -force "Ghidra 10.2.3*.zip"
cd "$env:USERPROFILE\"
Rename-Item "ghidra_10.2.3_PUBLIC" -NewName "Ghidra 10.2.3"
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
        Write-Host "[ERREUR]" -ForegroundColor Red -NoNewline
        Write-Host "Installation Java"
        Start-Sleep 10
        exit
    }
    # Retour Back
    cd "$Back"
    rm -force "JavaSetup8u361*.exe"
} else {Write-Host "[ERREUR]" -ForegroundColor Red -NoNewline; Write-Host "Installation Java";}
#---------------
# Install JDK
# Retour Back
cd "$Back"
curl -O "jdk-19_windows-x64_bin.msi" "https://download.oracle.com/java/19/latest/jdk-19_windows-x64_bin.msi"
if ($? -eq $True) {
    Write-Host "[OK]" -ForegroundColor Green -NoNewline
    Write-Host "Telechargement de JDK !"
} else {Write-Host "[ERREUR]" -ForegroundColor Red -NoNewline; Write-Host "Telechargement de JDK";}

# Start-Process "jdk-19_windows-x64_bin.msi" -Wait
msiexec /i "jdk-19_windows-x64_bin.msi" /quiet
if ($? -eq $True) {
    Write-Host "[OK]" -ForegroundColor Green -NoNewline
    Write-Host "Installation JDK !"
} else {Write-Host "[ERREUR]" -ForegroundColor Red -NoNewline; Write-Host "Installation JDK";}
# Retour Back
cd "$Back"
rm -force "jdk-19_windows-x64_bin*.msi"
#---------------
# Racourci bureau de Ghibra
cd "$Back"
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\Desktop\Ghidra_10.2.3.lnk")
$Shortcut.TargetPath = "$env:USERPROFILE\Ghidra 10.2.3\ghidraRun.bat"
$Shortcut.IconLocation = "$env:USERPROFILE\Ghidra 10.2.3\support\ghidra.ico, 0"
$Shortcut.Save()
if ($? -eq $True) {
    Write-Host "[OK]" -ForegroundColor Green -NoNewline
    Write-Host "Racourci Ghidra cree !"
} else {Write-Host "[ERREUR]" -ForegroundColor Red -NoNewline; Write-Host "Racourci Ghidra";}

Start-Sleep 5



