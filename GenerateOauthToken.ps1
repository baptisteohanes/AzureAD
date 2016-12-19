workflow Security_Center_Reports
{

Param(
    <#--        
        # Fully-qualified name of the Azure DB server 
        [parameter(Mandatory=$true)] 
        [string] $AzureSqlServerName,

        # Azure Database Name 
        [parameter(Mandatory=$true)] 
        [string] $AzureDBName,

        # Credentials for $SqlServerName stored as an Azure Automation credential asset
        # When using in the Azure Automation UI, please enter the name of the credential asset for the "Credential" parameter
        [parameter(Mandatory=$true)] 
        [PSCredential] $SQLCredential,
    
        #Connections used to connect to the subscriptions
		[Parameter(Mandatory=$true)]
        [String]
		$ConnectionName
        --#>
)
InlineScript{

#Generate Bearer token 

    #Aggregate calling application data

        $clientId = Get-AutomationVariable -Name 'clientId'
        $clientSecret = Get-AutomationVariable -Name 'clientSecret'
        $resourceAppIdURIARM = "https://management.azure.com/"
        $tenantID = Get-AutomationVariable -Name 'tenantID'

    # Authenticate and Acquire Token

        $authorityURI = "https://login.microsoftonline.com/$tenantID/oauth2/token"
        $postParams = @{grant_type='client_credentials';client_id=$clientID;client_secret=$clientSecret;resource=$resourceAppIdURIARM}
        $response = Invoke-WebRequest -Uri $authorityURI -Method POST -Body $postParams -useBasicParsing
    
    #Generate Authorization header

        $authHeader = (Convertfrom-Json ($response.Content)).token_type + " "+ (Convertfrom-Json ($response.Content)).access_token
        $requestHeader = @{
        "x-ms-version" = "2014-10-01"; #'2014-10-01'
        "Authorization" = $authHeader
        }
  # List all susbscriptions
    
    $subscriptionIDs = $null
    $Uri1 = "https://management.azure.com/subscriptions?api-version=2014-04-01"
    try{
    $Uri1Result = Invoke-RestMethod -Method Get -Headers $requestheader -Uri $Uri1
    }
    catch{
    $RESTerror = $null
    foreach($RESTerror in $_){
    ($RESTerror.ErrorDetails.Message | ConvertFrom-Json).error
    }
    }
    $subscriptionIDs += $Uri1Result.value.id

    Write-Output "List fo subscriptions that will be parsed :"
    Write-Output ""
    Write-Output $subscriptionIDs
    Write-Output ""
    
    #List "owners" role definitions for each subscription

    $SubscriptionOwners = @()
    $vmids = @()
    foreach($subscriptionID in $subscriptionIDs){

        #Extract the "Owner" role definition ID

        $OwnerRoleDefinitionID = $null
        $filtervalue = '$filter=roleName%20eq%20' +"'Owner'"
        $Uri2 = "https://management.azure.com$subscriptionID/providers/Microsoft.Authorization/roleDefinitions?api-version=2015-07-01&"+ $filtervalue
        try{
            $Uri2Result = Invoke-RestMethod -Method Get -Headers $requestheader -Uri $Uri2
        }
        catch{
            $RESTerror = $null
            foreach($RESTerror in $_){
                ($RESTerror.ErrorDetails.Message | ConvertFrom-Json).error
            }
        }
        $OwnerRoleDefinitionID = $Uri2Result.value.id
        
        #Get all the role definitions on the subscription

        $roleAssignments = $null
        $filtervalue = '$filter' +"=atScope()"
        $Uri3 = "https://management.azure.com$subscriptionID/providers/Microsoft.Authorization/roleAssignments?api-version=2015-07-01&" + $filtervalue
        try{
            $Uri3Result = Invoke-RestMethod -Method Get -Headers $requestheader -Uri $Uri3
        }
        catch{
            $RESTerror = $null
            foreach($RESTerror in $_){
                ($RESTerror.ErrorDetails.Message | ConvertFrom-Json).error
            }
        }
        $roleAssignments = $Uri3Result.value

        #Filter the role assignement for Owners only and extract their PrincipalID

        foreach($roleAssignment in $roleAssignments){
            if($roleAssignment.properties.roleDefinitionId -eq $OwnerRoleDefinitionID){
                $item = New-Object PSObject
                $item | Add-Member -type NoteProperty -Name 'subscriptionname' -Value $SubscriptionID
                $item | Add-Member -type NoteProperty -Name 'principalID' -Value $roleAssignment.properties.principalID
                $SubscriptionOwners += $item
            }
        }


        # Get the subscription security statuses
    
        $Uri4 = "https://management.azure.com$subscriptionID/providers/microsoft.Security/securitystatuses?api-version=2015-06-01-preview"
        try{
        $Uri4Result = Invoke-RestMethod -Method Get -Headers $requestheader -Uri $Uri4
        }
        catch{
        $RESTerror = $null
        foreach($RESTerror in $_){
        ($RESTerror.ErrorDetails.Message | ConvertFrom-Json).error
        }
        }
        $SubSecurityStatuses =$Uri4Result.Value


        #Extract VMs resource IDs from security statuses

        foreach($Status in $SubSecurityStatuses){
            if($Status.id.split("/")[7] -eq "virtualMachines"){
                $vmid=$null
                $i=1
                while($i -lt 9){
                    $vmid += "/" + $Status.id.split("/")[$i]
                    $i++
                    }
                $vmids += $vmid
                $vmids = $vmids | Get-Unique
            }
        }
    }
    $tempOutput = "List of all owners service principals for subscription" + $subscriptionID
    Write-Output $tempOutput
    Write-Output ""
    Write-Output $subscriptionOwners
    Write-Output ""
    Write-Output "List of VMs that will be analyzed"
    Write-Output $vmids
    
    #Get patchdata collection statuses from each VM

    $VMinfos = @()    
    foreach($vm in $vmids){
        $Uri2 = "https://management.azure.com{0}/providers/microsoft.Security/dataCollectionResults?api-version={1}" -f $VM,'2015-06-01-preview'
        try{
            $VMinfos += Invoke-RestMethod -Method Get -Headers $requestheader -Uri $uri2
        }
        catch{
            $RESTerror = $null
            foreach($RESTerror in $_){
                ($RESTerror.ErrorDetails.Message | ConvertFrom-Json).error
            }
        }
    }
    
    #Get Missing Updates and Baseline rules for each VM

    foreach($VMinfo in $VMinfos){
        $VMname = $VMinfo.id.split("/")[8]
        if($VMinfos[0].id.Split("/")[13] -eq "Patch"){
            $patches = $VMinfo.properties.missingPatches
            foreach($patch in $patches){
                $item = New-Object PSObject
                $item | Add-Member -type NoteProperty -Name 'subscriptionname' -Value $Subscription.SubscriptionName
                $item | Add-Member -type NoteProperty -Name 'scenario' -Value 'Patch'
                $item | Add-Member -type NoteProperty -Name 'vm' -Value $VMname
                $item | Add-Member -type NoteProperty -Name 'time' -Value $ExecutionTime
                $item | Add-Member -type NoteProperty -Name 'osType' -Value $patch.osType
                $item | Add-Member -type NoteProperty -Name 'patchId' -Value $patch.patchId
                $item | Add-Member -type NoteProperty -Name 'title' -Value $patch.title
                $item | Add-Member -type NoteProperty -Name 'description' -Value $patch.description
                $item | Add-Member -type NoteProperty -Name 'severity' -Value $patch.severity
                $item | Add-Member -type NoteProperty -Name 'isMandatory' -Value $patch.isMandatory
                $item | Add-Member -type NoteProperty -Name 'releaseDate' -Value $patch.releaseDate
                $item | Add-Member -type NoteProperty -Name 'linksToMsDocumentation' -Value $Subscription.linksToMsDocumentation
                $patchsecurityresults += $item
            }
        if($VMinfo.id.Split("/")[13] -eq "Baseline"){
            $category = "Baseline"
            $baselinerules = $VMinfo.properties.failedBaselineRules.baselineruledata
            foreach($baselinerule in $baselinerules){
                $item = New-Object PSObject
                $item | Add-Member -type NoteProperty -Name 'subscriptionname' -Value $Subscription.SubscriptionName
                $item | Add-Member -type NoteProperty -Name 'scenario' -Value 'Baseline'
                $item | Add-Member -type NoteProperty -Name 'vm' -Value $VMname
                $item | Add-Member -type NoteProperty -Name 'time' -Value $ExecutionTime
                $item | Add-Member -type NoteProperty -Name 'cceid' -Value $baselinerule.cceid   
                $item | Add-Member -type NoteProperty -Name 'name' -Value $baselinerule.name
                $item | Add-Member -type NoteProperty -Name 'severity' -Value $baselinerule.severity
                $item | Add-Member -type NoteProperty -Name 'description' -Value $baselinerule.description
                $item | Add-Member -type NoteProperty -Name 'vulnerability' -Value $baselinerule.vulnerability
                $item | Add-Member -type NoteProperty -Name 'impact' -Value $baselinerule.impact
                $baselinesecurityresults += $item
            }
        }
    }
    }

}
}