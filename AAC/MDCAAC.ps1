#register an application the following example is for a SP with contributor role - check Least Privileges
#az ad sp create-for-rbac --role Contributor --scopes /subscriptions/xxxxxxxx-d42d-427a-be6f-bd986473915b
#az ad sp create-for-rbac --role Contributor --scopes /providers/Microsoft.Management/managementGroups/xxxxxxxx-bc24-40c7-95a4-b17d1889750f
#az role assignment create --assignee "xxxxxxxx-f00e-4f67-b0b7-0d646bb1afd3" --role "Contributor"--scope "/providers/Microsoft.Management/managementGroups/xxxxxxxx-bc24-40c7-95a4-b17d1889750f"
# requires PS 7

$apiversion="2015-06-01-preview" #supports 2015-06-01-preview and 2020-01-01
$subID="c3aad7b8-bffc-426f-99dd-0b52fa36f4b8"
$tenantID="75c0f721-bc24-40c7-95a4-b17d1889750f"
$clientID="1a1f4bbc-f00e-4f67-b0b7-0d646bb1afd3"
$clientSecret="Yg58Q~41GQYc_--ZVxCnh~U0vK4y3GyV9~WNqaZz"
$dfcLocation="westeurope"

#connect to tenant - check Least privilege role required
$tokenBody = @{  
    Grant_Type    = "client_credentials"  
    Scope         = "https://management.azure.com/.default"  
    Client_Id     = $clientId  
    Client_Secret = $clientSecret  
}   

$tokenResponse = Invoke-RestMethod -Uri "https://login.microsoftonline.com/$Tenantid/oauth2/v2.0/token" -Method POST -Body $tokenBody
$headers = @{ 
	"Authorization" = "Bearer $($tokenResponse.access_token)" 
	"Content-type" = "application/json" 
} 


#Function get-MDCAACGroups
# input:  subscription
# output: list of AAC groups
Function get-MDCAACGroups {
    $Url="https://management.azure.com/subscriptions/$subID/providers/Microsoft.Security/applicationWhitelistings?api-version=$apiversion"
    $groups=((Invoke-WebRequest -uri $Url -Headers $headers -Method GET).Content | convertFrom-Json).value
    return $groups
}
#Function get-MDCAACGroupRecommendations
# input:  group, location, subscription
# output: list of recommendations configured in the group
Function get-MDCAACGroupRecommendations {
<#
    .SYNOPSIS
    .DESCRIPTION
    .INPUTS
    .OUTPUTS
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
    $groupName
    )

    $Url="https://management.azure.com/subscriptions/$subID/providers/Microsoft.Security/locations/$dfcLocation/applicationWhitelistings/${groupName}?api-version=$apiversion"
    $recommendations=((Invoke-WebRequest -uri $Url -Headers $headers -Method GET).Content | convertFrom-Json).properties
    return $recommendations
}

$groups = (get-MDCAACGroups).name
$rules=@()


foreach ($group in $groups){
    write-host $group;
    $recommendations = get-MDCAACGroupRecommendations -groupName $group
    #check if $vms is not null
    $vms=$recommendations.vmRecommendations.resourceId
    $paths=$recommendations.pathRecommendations;
    foreach ($vm in $vms) {
        $vm=$vm.split('/')[-1]
        foreach ($path in $paths) {
            $rule = New-Object PSobject -Property @{
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

$rules | Select-Object vm,arch,type,filetype,common,path,status | Export-Csv -Path ./rules.csv