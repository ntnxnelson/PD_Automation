$User = "chris@nemo.corp"
$PasswordFile = "C:\temp\Password.txt"
$KeyFile = "C:\temp\AES.key"
$key = Get-Content $KeyFile
$MyCredential = New-Object -TypeName System.Management.Automation.PSCredential `
 -ArgumentList $User, (Get-Content $PasswordFile | ConvertTo-SecureString -Key $key)