#
# Changes user password via powershell.

$user_name = "Administrator"
# $user_name = "myadmin"
$user_pass = (Get-Content -Path ./pass.txt)

Start-Transcript -Path ".\script.log" -Append

$hosts = (Get-ADComputer -Filter 'Name -like "asomething*" -or Name -like "bsomething*"' -SearchBase "OU=Servers,DC=example,DC=com" -Properties * | Select -ExpandProperty Name | Sort)

# foreach ($line in Get-Content hosts.txt) {  # Use if getting info from hosts file
foreach ($line in ($hosts) ) {   # use if getting info from Active Directory 
    $parameters = @{
        ComputerName = ${line} 
        ScriptBlock = { 
            Param(${user_name}, ${user_pass})
            $hostname_str = (hostname) | Out-String
            echo "Changing password on ${hostname_str} for ${user_name}"	
            net user "${user_name}" "${user_pass}"
        }
        ArgumentList = ${user_name}, ${user_pass}
    }
    Invoke-Command @parameters
}

Stop-Transcript


# Notes
# Get-LocalUser | Select Name,Enabled | findstr True
# Remove-LocalUser -Name "myuser"

# Ref 
# https://www.microsoft.com/en-au/download/details.aspx?id=45520  # rsat tools download for AD
# https://theitbros.com/install-and-import-powershell-active-directory-module/
# Add-WindowsCapability –online –Name “Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0”
# https://github.mktp.io/systems/kit/blob/master/win-reset-local-passwd/Reset-LocalAccountPassword.ps1
# https://blogs.vmware.com/consulting/2017/01/vro-powershell-execution.html
# $cred = (ConvertTo-SecureString -String $password -AsPlainText -Force)
# Authentication CredSSP -credential $cred
# Add-WindowsCapability Î
# Add-WindowsCapability oA
