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
        
        $base_url = "https://$($this.ip_addr):9440/api/nutanix/v3/$($this.sub_url)"
	
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
# Get the list of clusters.

function list_clusters($api_cls_obj, $filter_key){

        $body = @"
    {
        "kind": "cluster",
        "filter": "$filter_key"
    }
    
"@
    $api_cls_obj.init_params("clusters/list", $body, "POST")           
    $response = $api_cls_obj.invoke_api()
    $status_code = $api_cls_obj.status_code

    return $status_code, $response
}
# Retrieves currently logged in user.

function get_current_user($api_cls_obj){

    $api_cls_obj.init_params("users/me", $null, "GET")           
    $response = $api_cls_obj.invoke_api()
    $status_code = $api_cls_obj.status_code

    return $status_code, $response
}
# Lists the available roles.

function list_roles($api_cls_obj, $filter_key){
    $body = @"
    {
        "kind": "role",
        "filter": "$filter_key"
    }
    
"@
    $api_cls_obj.init_params("roles/list", $body, "POST")          
    $response = $api_cls_obj.invoke_api()
    $status_code = $api_cls_obj.status_code

    return $status_code, $response
}
#Create unmanaged network
function create_unmanaged_network ($api_cls_obj, $network_name, [int] $vlan_id, $cluster_uuid){

    $body = @"
    {
      "spec": {
        "cluster_reference": {
            "kind": "cluster",
            "uuid": "$cluster_uuid"
                },
        "name": "$network_name",
            "resources":{
                "subnet_type": "VLAN",
                "vlan_id": $vlan_id
            }
      },
      "api_version": "3.0",
      "metadata": {
        "kind": "subnet"
      }
    }
"@
    $api_cls_obj.init_params("subnets", $body, "POST")            
    $response = $api_cls_obj.invoke_api()
    $status_code = $api_cls_obj.status_code

    return $status_code, $response
 }
# Get a network details with particular UUID.

function get_network_details($api_cls_obj, $network_uuid){

    $api_cls_obj.init_params("subnets/$network_uuid", $null, "GET")           
    $response = $api_cls_obj.invoke_api()
    $status_code = $api_cls_obj.status_code

    return $status_code, $response
}
#Creates project

function create_project_with_network($api_cls_obj, $project_name, $role_uuid, $user_uuid, $network_uuid){

    $body = @"
        {
          "spec": {
            "name": "$project_name",
            "resources": {            
              "user_reference_list": [
                {
                  "kind": "user",
		          "uuid": "$user_uuid"
                }
              ],
              "subnet_reference_list": [
                {
                  "kind": "subnet",
                  "uuid": "$network_uuid"
                }
              ]
            }
          },
          "api_version": "3.0",
          "metadata": {
            "kind": "project"
          }
    }
"@
    $api_cls_obj.init_params("projects", $body, "POST")             
    $response = $api_cls_obj.invoke_api()
    $status_code = $api_cls_obj.status_code

    return $status_code, $response
} 
# Get a project based on project_uuid

function get_project($api_cls_obj, $project_uuid){
 
    $api_cls_obj.init_params("projects/$project_uuid", $null, "GET") #(Url, body, method type)             
    $response = $api_cls_obj.invoke_api()
    $status_code = $api_cls_obj.status_code

    return $status_code, $response

}
# list all the projects

function list_project($api_cls_obj){

    $body = @"
    {
      "kind": "project"
    }
"@
    $api_cls_obj.init_params("projects/list", $body, "POST")             
    $response = $api_cls_obj.invoke_api()
    $status_code = $api_cls_obj.status_code

    return $status_code, $response

}


#Creates VM
function create_vm($api_cls_obj, $vm_name, $cluster_uuid, $network_uuid, [int] $vcpu, [int] $memory_in_mb){

    $body = @"
{
  "spec": {
    "cluster_reference": {
      "kind": "cluster",
      "uuid": "$cluster_uuid"
    },
    "name": "$vm_name",
    "resources": {
      "memory_size_mib": $memory_in_mb,
      "nic_list": [
        {
          "mac_address": "00:0c:f7:16:bb:9c",
          "subnet_reference": {
            "kind": "subnet",
            "uuid": "$network_uuid"
          }
        }
      ],
      "num_sockets": 1,
      "num_vcpus_per_socket": 1,
      "power_state": "ON"
    }
  },
      "api_version": "3.0",
      "metadata": {
        "kind": "vm",
        "categories": {}       
      }
}
"@
    $api_cls_obj.init_params("vms", $body, "POST")           
    $response = $api_cls_obj.invoke_api()
    $status_code = $api_cls_obj.status_code

    return $status_code, $response
}


# Get a VM details with particular UUID.

function get_vm_details($api_cls_obj, $vm_uuid){

    $api_cls_obj.init_params("vms/$vm_uuid", $null, "GET")             
    $response = $api_cls_obj.invoke_api()
    $status_code = $api_cls_obj.status_code

    return $status_code, $response

}

# Get all unprotected VMs in cluster.

function get_unprotected_vms($api_cls_obj, )
# Main
function main($ip_addr, $username, $password){

    $cluster_name = "cluster01"
    $network_name = "subnet_vm_create"
    $dhcp_ip = "192.168.1.3"
    $network_address = "192.168.1.0"
    $prefix_length = "24"
    $project_name = "ntnx.vmcreateproject"
    $vlan_id = "200"
    $vm_name = "VM123"
    $memory_in_mb = "1024"
    $role_name = "vm_user"
    $vcpu = "1"
    $mac_address = "00:0a:f7:16:bb:9c"
    
    #initialize the classes
    $api_cls_obj = [api_class]::new($ip_addr, $username, $password)
    $status_lib_obj = [library_status_fns_api]::new() 

    #Get the current logged in user's id
    $status_code, $response = get_current_user -api_cls_obj $api_cls_obj
    
    if($status_code -eq 200){

        $response = ConvertFrom-Json $response
        $user_uuid = $response.metadata.uuid
        write-host "Got the current logged in user uuid : $user_uuid"
        if(-not $user_uuid){
            Write-Host "No user logged in!!"   
				$host.SetShouldExit(1)
				exit
        }

    } else {

        try {
            $response = ConvertFrom-Json $response
            $status_lib_obj.print_failure_status($response) 
            #return $false
			$host.SetShouldExit(1)
			exit
        } catch {
            Write-host "Failed to get user!! $status_code' - '$response'"
            #return $_
			$host.SetShouldExit(1)
			exit
        }
    }

    #List all the roles and get the particular role's uuid

    $status_code, $response = list_roles -api_cls_obj $api_cls_obj
    
    if($status_code -eq 200){

        $response = ConvertFrom-Json $response
        $role_names = $response.entities.status.name 
        $role_uuids = $response.entities.metadata.uuid
        
        if ($role_uuids.count -gt 1) {

            #Get uuid of particular role
            $role_name =  $role_names[0]
            $role_uuid =  $role_uuids[0]
            Write-Host "Got the role uuid '$role_uuid' of role '$role_name'"
            
        } else {
            $role_name =  $role_names
            $role_uuid =  $role_uuids
            Write-Host "Got the role uuid '$role_uuid' of role '$role_name'" 
        }
        If(-not $role_uuid) {
            Write-Host "'$role_name' role doesn't exists!"
          #  return
		  $host.SetShouldExit(1)
		  exit
        }
        
    } else {
        try {
            $response = ConvertFrom-Json $response
            $status_lib_obj.print_failure_status($response) 
           # return $false
		   $host.SetShouldExit(1)
		   exit
        } catch {
            Write-host "Failed to get role!! $status_code' - '$response'"
            #return $_
			$host.SetShouldExit(1)
			exit
        }
    }
    
    #List all the cluster

    $status_code, $response = list_clusters -api_cls_obj $api_cls_obj   
    if ($status_code -eq 200) {
        $response = ConvertFrom-Json $response
        $cluster_name = $response.entities.status.name[0] 
        $cluster_uuid = $response.entities.metadata.uuid[0]
         
        Write-host "Cluster name '$cluster_name', its uuid '$cluster_uuid'"

    } Else {
       
        try {
            $response = ConvertFrom-Json $response
            $status_lib_obj.print_failure_status($response) 
            return
        } catch {
             Write-host "Failed to list cluster!! '$status_code' - '$response'"
            return $_
        }
    } 
        
    #Create an unmanaged Network
    $status_code, $response = create_unmanaged_network -api_cls_obj $api_cls_obj -network_name $network_name -vlan_id $vlan_id -cluster_uuid $cluster_uuid
    
    if ($status_code -eq 202){

        $response = ConvertFrom-Json $response
        $network_uuid = $response.metadata.uuid #get networks uuid
        
        $network_uuid = $status_lib_obj.track_api_status($status_code, $response, { get_network_details -api_cls_obj $api_cls_obj -network_uuid $network_uuid})
        if ($network_uuid) {

            Write-host "Created network '$network_name', it's uuid '$network_uuid'"

        } Else {
 
            Write-host "Failed to create network!! $network_name" 
            #return    
			$host.SetShouldExit(1)
			exit
        }
    } Else {
        try {
            $response = ConvertFrom-Json $response
            $status_lib_obj.print_failure_status($response) 
            #return
			$host.SetShouldExit(1)
			exit
        } catch {
            Write-host "Failed to create network!!  '$status_code' - '$response'"
            #return $_
			$host.SetShouldExit(1)
			exit
        }   
    }

    #Create a project with user uuid

    if ($role_uuid -and $network_uuid -and $user_uuid){
       
       $status_code, $response = create_project_with_network -api_cls_obj $api_cls_obj -project_name $project_name -role_uuid $role_uuid -user_uuid $user_uuid -network_uuid $network_uuid 

       if ($status_code){

            $response = ConvertFrom-Json $response
            $project_uuid = $response.metadata.uuid #get project uuid            
        
            $project_uuid = $status_lib_obj.track_api_status($status_code, $response, { get_project -api_cls_obj $api_cls_obj -project_uuid $project_uuid})
            if ($project_uuid) {

                Write-host "Created project '$project_name', it's uuid '$project_uuid'"

            } Else {
                Write-host "Failed to create project!! $project_name"     
					$host.SetShouldExit(1)
					exit
            }
        } Else {
            try {
                $response = ConvertFrom-Json $response
                $status_lib_obj.print_failure_status($response) 
            #    return $false
				$host.SetShouldExit(1)
				exit
            } catch {
                Write-host "Failed to create project!! $status_code' - '$response'"
				#	return $_
				$host.SetShouldExit(1)
				exit
            }
        }
    }

    #Create VM
    if($project_uuid -and $network_uuid){

        $status_code, $response = create_vm -api_cls_obj $api_cls_obj -vm_name $vm_name -cluster_uuid $cluster_uuid -network_uuid $network_uuid -memory_in_mb $memory_in_mb -vcpu $vcpu # -project_name $project_name               
        if ($status_code){

            $response = ConvertFrom-Json $response
            $vm_uuid = $response.metadata.uuid #get vm uuid        
            $vm_uuid = $status_lib_obj.track_api_status($status_code, $response, { get_vm_details -api_cls_obj $api_cls_obj -vm_uuid $vm_uuid})
            if ($vm_uuid) {

                Write-host "Created VM '$vm_name', it's uuid '$vm_uuid'"

            } Else {
                Write-host "Failed to create VM!! $vm_name"  
					$host.SetShouldExit(1)
					exit
            }
        } Else {
           try {
                $response = ConvertFrom-Json $response
                $status_lib_obj.print_failure_status($response) 
                #return $false
				$host.SetShouldExit(1)
				exit
            } catch {
                Write-host "Failed to create vm!! $status_code' - '$response'"
               # return $_
			   $host.SetShouldExit(1)
			   exit
            }
        }
    
    }

    # Get the VM details
    if ($vm_uuid){

        $status_code, $response = get_vm_details -api_cls_obj $api_cls_obj -vm_uuid $vm_uuid
        if ($status_code -eq 200) {
            $response = ConvertFrom-Json $response

            Write-Output "VM details:: $response $($response.status.name)"
            
        } Else {
         
            try {
                $response = ConvertFrom-Json $response
                $status_lib_obj.print_failure_status($response) 
               # return $false
			   $host.SetShouldExit(2)
			   exit
            } catch {
                Write-host "Failed to get vm!! $status_code' - '$response'"
             #   return $_
			 $host.SetShouldExit(2)
			 exit
            }    
        }
    }
}
main -ip_addr $ip_addr -username $username -password $password





