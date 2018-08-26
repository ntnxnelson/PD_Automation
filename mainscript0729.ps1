add-type @"
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class TrustAllCertsPolicy : ICertificatePolicy {
    public bool CheckValidationResult(
    ServicePoint srvPoint, X509Certificate certificate,
    WebRequest request, int certificateProblem) {
        return true;
    }
}
"@
[System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllCertsPolicy


[Net.ServicePointManager]::SecurityProtocol = 'TLS11','TLS12','ssl3'

$username = "admin"
$password = "Nutanix/4u!"

$PDCounter = 0
$PDContentsCounter = 0

$PDListUrl = "https://10.1.174.199:9440/api/nutanix/v2.0/protection_domains/"
$UnprotectedUrl = "https://10.1.174.199:9440/api/nutanix/v2.0/protection_domains/unprotected_vms/"
$PDCreateUrl = "https://10.1.174.199:9440/PrismGateway/services/rest/v2.0/protection_domains/"


$BasePDName = "NTNXPD"

## Pull array of un-protected VMs

$Unprotected = Invoke-PrismRESTCall -method GET -url $UnprotectedUrl -username $username -password $password
$UnproList = $Unprotected.entities
Write-Host "There are" $UnproList.Count "unprotected VMs on this cluster."
echo ""

Foreach ($upvm in $Unprotected.entities) {
    $upvmname = $upvm.vm_name
    $upvmuuid = $upvm.uuid
    #Write-Host $upvmname $upvm.uuid
    $data = @{ uuids = @("$upvmuuid")}
    $upbodyjson = $data | ConvertTo-Json


    ## Find out how many protection domains

    $PDList = Invoke-PrismRESTCall -method GET -url $PDListUrl -username $username -password $password 
    #Write-Host "$(Get-Date) [SUCCESS] Successfully retrieved Protection Domain list"

    $PDObject = $PDList.entities
    #Write-Host "There are" $PDObject.count "Protection Domains on this cluster"

    For ($i=0 ; $i -lt $PDObject.Count ; $i++) {
        $PD = $PDObject[$i]
        $PDName = $PD.name
        $protectvm = "/protect_vms"
        $PDContents = Invoke-PrismRESTCall -method GET -url $($PDListUrl + $PDName) -username $username -password $password
        $PDVMs = $PDContents.vms | select -Property vm_name
        If ($PDVMs.Count -lt 4) {
            #Add vm to this PD
            #Write-Host "We must add" $upvmname "to the Protection domain" $PDName
            $ProtectURL = $($PDListURl + $PDName + $protectvm)
            $VMProtect = Invoke-PrismRESTCall -method POST -url $($PDListURl + $PDName + $protectvm) -username $username -password $password -body $upbodyjson | Get-Member
            
        }
        ElseIf ($i = $PDObject.Count) {
            #If this is the last PD, create another one and then add VM to the new PD
            #Write-Host "We must create a new PD for" $upvmname
            $NewPDCounter = $i + 1
            $NewPDName = $($BasePDName + $NewPDCounter)
            $newpddata = @{ value = "$NewPDName"}
            $newpdbodyjson = $newpddata | ConvertTo-Json
            $PDCreation = Invoke-PrismRESTCall -method POST -url $PDCreateUrl -username $username -password $password -body $newpdbodyjson | Get-Member
        }
        Else {
            #Move on
            Write-Host "Loop"
        }
    }
}



#Write-Host "There are " $PDCounter " Protection Domains."

## Find out how many VMs per protection domain




function Write-LogOutput
{
<#
.SYNOPSIS
Outputs color coded messages to the screen and/or log file based on the category.
.DESCRIPTION
This function is used to produce screen and log output which is categorized, time stamped and color coded.
.PARAMETER Category
This the category of message being outputed. If you want color coding, use either "INFO", "WARNING", "ERROR" or "SUM".
.PARAMETER Message
This is the actual message you want to display.
.PARAMETER LogFile
If you want to log output to a file as well, use logfile to pass the log file full path name.
.NOTES
Author: Stephane Bourdeaud (sbourdeaud@nutanix.com)
.EXAMPLE
PS> Write-LogOutput -category "ERROR" -message "You must be kidding!"
Displays an error message.
.LINK
https://github.com/sbourdeaud
#>
    [CmdletBinding(DefaultParameterSetName = 'None')] #make this function advanced

	param
	(
		[Parameter(Mandatory)]
        [ValidateSet('INFO','WARNING','ERROR','SUM')]
        [string]
        $Category,

        [string]
		$Message,

        [string]
        $LogFile
	)

    process
    {
        $Date = get-date #getting the date so we can timestamp the output entry
	    $FgColor = "Gray" #resetting the foreground/text color
	    switch ($Category) #we'll change the text color depending on the selected category
	    {
		    "INFO" {$FgColor = "Green"}
		    "WARNING" {$FgColor = "Yellow"}
		    "ERROR" {$FgColor = "Red"}
		    "SUM" {$FgColor = "Magenta"}
	    }

	    Write-Host -ForegroundColor $FgColor "$Date [$category] $Message" #write the entry on the screen
	    if ($LogFile) #add the entry to the log file if -LogFile has been specified
        {
            Add-Content -Path $LogFile -Value "$Date [$Category] $Message"
            Write-Verbose -Message "Wrote entry to log file $LogFile" #specifying that we have written to the log file if -verbose has been specified
        }
    }

}#end function Write-LogOutput

#this function is used to connect to Prism REST API


function Invoke-PrismRESTCall
{
	#input: username, password, url, method, body
	#output: REST response
<#
.SYNOPSIS
  Connects to Nutanix Prism REST API.
.DESCRIPTION
  This function is used to connect to Prism REST API.
.NOTES
  Author: Stephane Bourdeaud
.PARAMETER username
  Specifies the Prism username.
.PARAMETER password
  Specifies the Prism password.
.PARAMETER url
  Specifies the Prism url.
.EXAMPLE
  PS> PrismRESTCall -username admin -password admin -url https://10.10.10.10:9440/PrismGateway/services/rest/v1/ 
#>
	param
	(
		[string] 
        $username,
		
        [string] 
        $password,
        
        [string] 
        $url,
        
        [string] 
        [ValidateSet('GET','PATCH','PUT','POST','DELETE')]
        $method,
        
        $body
	)

    begin
    {
	 	#Setup authentication header for REST call
        $myvarHeader = @{"Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($username+":"+$password ))}   
    }

    process
    {
        if ($body) {
            $myvarHeader += @{"Accept"="application/json"}
		    $myvarHeader += @{"Content-Type"="application/json"}
            
            if ($IsLinux) {
                try {
			        if ($PSVersionTable.PSVersion.Major -ge 6) {
			            $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -SslProtocol Tls12 -ErrorAction Stop
                    } else {
                        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -SkipCertificateCheck -ErrorAction Stop
                    }
		        }
		        catch {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) {Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"}
                    }
                    catch {
                        Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                    }
			        Exit
		        }
            }else {
                try {
			        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -Body $body -ErrorAction Stop
		        }
		        catch {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) {Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"}
                    }
                    catch {
                        Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                    }
			        Exit
		        }
            }
        } else {
            if ($IsLinux) {
                try {
			        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -SkipCertificateCheck -ErrorAction Stop
		        }
		        catch {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) {Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"}
                    }
                    catch {
                        Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                    }
			        Exit
		        }
            }else {
                try {
			        $myvarRESTOutput = Invoke-RestMethod -Method $method -Uri $url -Headers $myvarHeader -ErrorAction Stop
		        }
		        catch {
			        Write-LogOutput -category "ERROR" -message "$($_.Exception.Message)"
                    try {
                        $RESTError = Get-RESTError -ErrorAction Stop
                        $RESTErrorMessage = ($RESTError | ConvertFrom-Json).Message
                        if ($RESTErrorMessage) {Write-LogOutput -category "ERROR" -message "$RESTErrorMessage"}
                    }
                    catch {
                        Write-LogOutput -category "ERROR" -message "Could not retrieve full REST error details."
                    }
			        Exit
		        }
            }
        }
    }

    end
    {
        return $myvarRESTOutput
    }
}#end function Get-PrismRESTCall