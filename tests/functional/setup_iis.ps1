# Script to install an IIS website with windows authentication only as well as setting up a local admin account
# Authors: Jordan Borean
# License: CC0 1.0 Universal: http://creativecommons.org/publicdomain/zero/1.0/

function SetupUser() {
    $computername = $env:computername
    $username = 'User'
    $password = 'Password01'
    $desc = 'Automatically created local admin account'

    $computer = [ADSI]"WinNT://$computername,computer"
    $user = $computer.Create("user", $username)
    $user.SetPassword($password)
    $user.Setinfo()
    $user.description = $desc
    $user.setinfo()
    $user.UserFlags = 65536
    $user.SetInfo()
    $group = [ADSI]("WinNT://$computername/administrators,group")
    $group.add("WinNT://$username,user")
}

function SetupIIS () {
    Import-Module WebAdministration

    $cert = New-SelfSignedCertificate -DnsName ("127.0.0.1") -CertStoreLocation cert:\LocalMachine\My
    $rootStore = Get-Item cert:\LocalMachine\Root
    $rootStore.Open("ReadWrite")
    $rootStore.Add($cert)
    $rootStore.Close();

    New-Item C:\temp -Type Directory -Force
    New-Item C:\temp\iisroot -Type Directory -Force
    New-Item C:\temp\iisroot\contents.txt -Type File -Force -Value "contents"

    $iisExec = "C:\Windows\System32\inetsrv\appcmd.exe"

    Start-Process -FilePath $iisExec -ArgumentList "add site /name:""Site1"" /id:11 /physicalPath:""C:\temp\iisroot"" /bindings:http/*:81:" -Wait
    Start-Process -FilePath $iisExec -ArgumentList "set config ""Site1"" -section:system.webServer/security/authentication/anonymousAuthentication /enabled:""False"" /commit:apphost" -Wait
    Start-Process -FilePath $iisExec -ArgumentList "set config ""Site1"" -section:system.webServer/security/authentication/windowsAuthentication /enabled:""True"" /commit:apphost" -Wait
    Start-Process -FilePath $iisExec -ArgumentList "set config ""Site1"" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:""Require"" /extendedProtection.flags:""None"" /commit:apphost" -Wait
    Start-Process -FilePath $iisExec -ArgumentList "stop site /site.name:""Site1"" " -Wait
    Start-Process -FilePath $iisExec -ArgumentList "start site /site.name:""Site1"" " -Wait

    Start-Process -FilePath $iisExec -ArgumentList "add site /name:""Site2"" /id:12 /physicalPath:""C:\temp\iisroot"" /bindings:http/*:82:" -Wait
    Start-Process -FilePath $iisExec -ArgumentList "set config ""Site2"" -section:system.webServer/security/authentication/anonymousAuthentication /enabled:""False"" /commit:apphost" -Wait
    Start-Process -FilePath $iisExec -ArgumentList "set config ""Site2"" -section:system.webServer/security/authentication/windowsAuthentication /enabled:""True"" /commit:apphost" -Wait
    Start-Process -FilePath $iisExec -ArgumentList "set config ""Site2"" -section:system.webServer/security/authentication/windowsAuthentication /extendedProtection.tokenChecking:""None"" /extendedProtection.flags:""None"" /commit:apphost" -Wait
    Start-Process -FilePath $iisExec -ArgumentList "stop site /site.name:""Site2"" " -Wait
    Start-Process -FilePath $iisExec -ArgumentList "start site /site.name:""Site2"" " -Wait

    Set-Location IIS:\SslBindings
    New-WebBinding -Name "Site1" -IP "*" -Port 441 -Protocol https
    New-WebBinding -Name "Site2" -IP "*" -Port 442 -Protocol https
    $cert | New-Item 0.0.0.0!441
    $cert | New-Item 0.0.0.0!442
}

function main () {
    SetupUser
    SetupIIS
}

main
