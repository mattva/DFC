#register an application the following example is for a SP with contributor role - check Least Privileges
#az ad sp create-for-rbac --role Contributor --scopes /subscriptions/xxxxxxxx-d42d-427a-be6f-bd986473915b
#az ad sp create-for-rbac --role Contributor --scopes /providers/Microsoft.Management/managementGroups/xxxxxxxx-bc24-40c7-95a4-b17d1889750f
#az role assignment create --assignee "xxxxxxxx-f00e-4f67-b0b7-0d646bb1afd3" --role "Contributor"--scope "/providers/Microsoft.Management/managementGroups/xxxxxxxx-bc24-40c7-95a4-b17d1889750f"
# requires PS 7

$apiversion="2015-06-01-preview" #supports 2015-06-01-preview and 2020-01-01
$subID="xxxxxxxx-bffc-426f-99dd-0b52fa36f4b8"
$tenantID="xxxxxxxx-bc24-40c7-95a4-b17d1889750f"
$clientID="xxxxxxxx-f00e-4f67-b0b7-0d646bb1afd3"
$clientSecret="Yg5xxxxxxxxxxNqaZz"
$dfcLocation="westeurope"

Function Authenticate {
    <#
    .SYNOPSIS
    OAuth 2.0 authentication with client_credentials flow
    .DESCRIPTION
    .INPUTS
    clientID, clientSecret, tenantID
    .OUTPUTS
    Authentication token
    .EXAMPLE
    #>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$False)]
    [String]
    $clientID = "$clientID",
    [Parameter(Mandatory=$False)]
    [string]
    $clientSecret = "$clientSecret",
    [Parameter(Mandatory=$False)]
    [string]
    $tenantID = "$tenantID"
    )
    $tokenBody = @{  
        Grant_Type    = "client_credentials"  
        Scope         = "https://management.azure.com/.default"  
        Client_Id     = $clientId  
        Client_Secret = $clientSecret  
    }   

    try {
        $tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$Tenantid/oauth2/v2.0/token" -Method POST -Body $tokenBody        
    }
    catch {
        Write-Output "Cannot authenticate to tenant $tenantID"
        exit
    }
    return $tokenResponse
}

#Function get-MDCAACGroups
# input:  subscription
# output: list of AAC groups
Function get-MDCAACGroups {
    <#
    .SYNOPSIS
    Get all Adaptive Application Control groups defined for the susbscription
    .DESCRIPTION
    .INPUTS
    access token object, subscriptionid, apiversion
    .OUTPUTS
    list of groups defined
    .EXAMPLE
    #>
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory=$False)]
        [String]
        $SubID = "$subID",    
        [Parameter(Mandatory=$False)]
        [string]
        $apiversion = "$apiversion",
        [Parameter(Mandatory=$True)]
        [PSCustomObject]
        $tk
    )
    $headers = @{ 
        "Authorization" = "Bearer $($tk.access_token)" 
        "Content-type" = "application/json" 
    }         
    $Url="https://management.azure.com/subscriptions/$subID/providers/Microsoft.Security/applicationWhitelistings?api-version=$apiversion"
    $groups=((Invoke-WebRequest -uri $Url -Headers $headers -Method GET).Content | convertFrom-Json).value
    return $groups
}
#Function get-MDCAACGroupRecommendations
Function get-MDCAACGroupRecommendations {
    <#
    .SYNOPSIS
    Get all recommendations inside a group
    .DESCRIPTION
    .INPUTS
    Subscription ID, Location of AAC group, apiversion, groupname, authentication token
    .OUTPUTS
    list of recommendations inside the specified AAC group
    .EXAMPLE
    #>
    [CmdletBinding()]
    Param(
    [Parameter(Mandatory=$False)]
    [String]
    $SubID = "$subID",
    [Parameter(Mandatory=$False)]
    [string]
    $dfcLocation = "$dfcLocation",
    [Parameter(Mandatory=$False)]
    [string]
    $apiversion = "$apiversion",
    [Parameter(Mandatory=$True)]
    [string]
    $groupName,
    [Parameter(Mandatory=$True)]
    [PSCustomObject]
    $tk
    )
    $headers = @{ 
        "Authorization" = "Bearer $($tk.access_token)" 
        "Content-type" = "application/json" 
    }         

    $Url="https://management.azure.com/subscriptions/$subID/providers/Microsoft.Security/locations/$dfcLocation/applicationWhitelistings/${groupName}?api-version=$apiversion"
    $recommendations=((Invoke-WebRequest -uri $Url -Headers $headers -Method GET).Content | convertFrom-Json).properties
    return $recommendations
}

$token = Authenticate
$subs = (Get-AzSubscription).id
$rules=@()

foreach ($sub in $subs) {
    $groups = (get-MDCAACGroups -tk $token -SubID $sub ).name
    foreach ($group in $groups){
        write-host $group;
        $recommendations = get-MDCAACGroupRecommendations -SubID $sub -groupName $group -TK $token
        #check if $vms is not null
        $vms=$recommendations.vmRecommendations.resourceId
        $paths=$recommendations.pathRecommendations;
        foreach ($vm in $vms) {
            $vm=$vm.split('/')[-1]
            foreach ($path in $paths) {
                $rule = New-Object PSobject -Property @{
                    "subscription" = $sub
                    "group" = $group
                    "vm" = "$vm"
                    "arch" = $recommendations.sourceSystem -eq "Azure_AuditD" ? "Linux" : "Windows"
                    "path" = $path.path
                    "type" = $path.type
                    "common" = $path.common
                    "filetype" = $path.filetype
                    "status" = $path.configurationStatus
                }
                $rules+=$rule
            }
        }
    }
}

$rules | Select-Object subscription,group,vm,arch,type,filetype,common,path,status | Export-Csv -Path ./rules.csv