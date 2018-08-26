<#  
.SYNOPSIS  
    Authenticate, create vms, list
	vms and modify vms
.DESCRIPTION  
	This script demonstrates how to authenticate, create vms, list
	vms and modify vms. This script is ready to copy and paste
	for execution, but assign the variables in the script.
.NOTES  
    Requires   : PowerShell V5
#>
#Get input params
param(
    [Parameter(Mandatory=$true)][string]$ip_addr, 
    [Parameter(Mandatory=$true)][string]$username, 
    [Parameter(Mandatory=$true)][string]$password
    )

<#
This file has two functions: basic_auth and call_rest_method
    basic_auth to generate the authorization header
    call_rest_method is a general function to invoke rest method called with parameters
    Parameters are IP address, Sub uri(to construct the base uri), body, method name and content type.
#>

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
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Class api_class {
    
    [string]$ip_addr
    [string]$username
    [string]$password
    [string]$sub_url
    [string]$body
    [string]$method
    [string]$content_type
    [int]$status_code

    
    #Create Constructor to instantiate the variables
    api_class ([string]$ip_addr, $username, $password){

        $this.ip_addr = $ip_addr
        $this.username = $username
        $this.password = $password
        $this.sub_url = $null
        $this.body = $null
        $this.method = $null  
        $this.status_code =$null
           
    }
    
    [void]init_params([string]$sub_url, $body, [string]$method){
        $this.sub_url = $sub_url
        $this.body = $body
        $this.method = $method
        $this.content_type = "application/json"       
    }
    
    [string]invoke_api(){
        
        $base_url = "https://$($this.ip_addr):9440/api/nutanix/v2.0/$($this.sub_url)"
	
        $header = @{
            "Authorization" = "Basic "+[System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($this.username+":"+$this.password ))
        }
	        
        try {
            if ($this.method -ne "GET" ){
                
                $response = Invoke-WebRequest -Uri $base_url -Method $this.method -Headers $header -Body $this.body -ContentType $this.content_type -UseBasicParsing
                $this.status_code = $response.StatusCode
                return $response 

            } else {
                
                $response = Invoke-WebRequest -Uri $base_url -Method $this.method -Headers $header -ContentType $this.content_type -UseBasicParsing
                $this.status_code = $response.StatusCode
                return $response 
            }

        } catch {
        	       
            $this.status_code = $_.Exception.Response.StatusCode.Value__
            return $_
        }   
    }
}
<#
Class consists of functions to get api status, 
print the failures, tracking the status

#>

Class library_status_fns_api {

    # Return the status of API

    [string]get_api_status($response){
        if ($response){

            return $response.status.state #Get the status

        } else {

            return $null
        }
    }

    [void]print_failure_status($response){

        if ($response) {
            $api_status = $response.status
            if ($api_status -ne "failure"){
                $api_state = $response.status.state
                if ($api_state -eq "kError"){
                        Write-host "Reason: $($response.status.message_list.reason)"
                        Write-host "Status: $($response.status.state)"
                        Write-host "Message: $($response.status.message_list.message)" 
                    } else {
                        Write-host "Status Code: $($response.code)"
                        Write-host "Reason: $($response.message_list.reason)"
                      #  Write-host "Details: $($response.details)"
                        Write-host "Message: $($response.message_list.message)" 
                    }
                } else {                
                    Write-host "Status Code: $($response.code)"
                    Write-host "Details: $($response.details)"
                    Write-host "Status: $($response.status)"
                    Write-host "Message: $($response.message)"                   
                }     
        }
    }

    #Check the result whether completed

    [bool]is_status_completed($status_code, $response){

        if ($response -and ($status_code -eq 200)){
            $api_status = $response.status.state
            if(($api_status -eq "kComplete") -or ($api_status -eq "COMPLETE")){
                return $true
            }
        }
        return $false    
    }

    #Check the status of API

    [string]track_api_status ($status_code, $response, [scriptblock]$get_fn) {
        
        $retry_count = 5
        $wait_time = 2  # seconds
        $uuid = $null
 
        if ($response -and ($status_code -eq 202 -or $status_code -eq 200)) {
        
            $uuid = $response.metadata.uuid
        }

        if ($this.is_status_completed($status_code, $response)){
            
            return $uuid

        } else {
            
            $api_status = $response.status.state

            if ($uuid -and $api_status -ne "kComplete" -and $api_status -ne "kError"){           
                $count = 0

                while ($count -lt $retry_count){
                    $count = $count + 1
                    Start-Sleep $wait_time #In seconds

                    $status_code, $response = $get_fn.Invoke($args) #Call get api function
                    try {
                        $response = ConvertFrom-Json $response
                        $api_status = $response.status
			return $uuid 
                    } catch {
                        Write-Host $_
                    }
                    if ($this.is_status_completed($status_code, $response)){
                        
                        return $uuid

                    } elseif ($api_status -eq "failure") {
                        $this.print_failure_status($response)
                        return $null
                    }

                }

            }
            
            $this.print_failure_status($response)
            
            $api_status = $response.status.state
            Write-Host "API Status:: $api_status"
            return $null
        }
 
    }
}  


# Get all unprotected VMs in cluster.

function get_unprotected_vms($api_cls_obj){
    $api_cls_obj.init_params("protection_domains/unprotected_vms/", $null, "GET")
    $response = $api_cls_obj.invoke_api()
    $status_code = $api_cls_obj.status_code

    return $status_code, $response

}



# Main
function main($ip_addr, $username, $password){

    
    #initialize the classes
    $api_cls_obj = [api_class]::new($ip_addr, $username, $password)
    $status_lib_obj = [library_status_fns_api]::new() 

    #Get all unprotected VMs for cluster
    $status_code, $response = get_unprotected_vms -api_cls_obj $api_cls_obj

    if($status_code -eq 200){

        $unprotected_vms = $response | select -Property vm_name


        Write-Host $unprotected_vms

    }

}
main -ip_addr $ip_addr -username $username -password $password





