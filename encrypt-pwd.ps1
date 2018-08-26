$PasswordFile = "c:\temp\Password.txt"
$KeyFile = "c:\temp\AES.key"
$Key = Get-Content $KeyFile
$Password = "Nutanix/4u!" | ConvertTo-SecureString -AsPlainText -Force
$Password | ConvertFrom-SecureString -key $Key | Out-File $PasswordFile