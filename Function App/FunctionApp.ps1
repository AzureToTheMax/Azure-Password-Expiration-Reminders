#Function App for checking password expiration via graph
#See AzureToTheMax.Net
        #Author:      Maxton Allen
        #Contact:     @AzuretotheMax
        #Website:     AzureToTheMax.net
        #Created:     01-30-2023


using namespace System.Net
# Input bindings are passed in via param block.
param($Request)
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
#region functions
function Get-AuthToken {
    <#
    .SYNOPSIS
        Retrieve an access token for the Managed System Identity.
    
    .DESCRIPTION
        Retrieve an access token for the Managed System Identity.
    
    .NOTES
        Author:      Nickolaj Andersen
        Contact:     @NickolajA
        Created:     2021-06-07
        Updated:     2021-06-07
    
        Version history:
        1.0.0 - (2021-06-07) Function created
    #>
    Process {
        # Get Managed Service Identity details from the Azure Functions application settings
        $MSIEndpoint = $env:MSI_ENDPOINT
        $MSISecret = $env:MSI_SECRET

        # Define the required URI and token request params
        $APIVersion = "2017-09-01"
        $ResourceURI = "https://graph.microsoft.com"
        $AuthURI = $MSIEndpoint + "?resource=$($ResourceURI)&api-version=$($APIVersion)"

        # Call resource URI to retrieve access token as Managed Service Identity
        $Response = Invoke-RestMethod -Uri $AuthURI -Method "Get" -Headers @{ "Secret" = "$($MSISecret)" }

        # Construct authentication header to be returned from function
        $AuthenticationHeader = @{
            "Authorization" = "Bearer $($Response.access_token)"
            "ExpiresOn" = $Response.expires_on
        }
        # Handle return value
        return $AuthenticationHeader
    }
}#end function 

function Get-BearerAuthToken {
    <#
    #Obtain and return a raw bearer token using self identity.
    #Unlike Get-AuthToken - this function returns the Bearer token alone.
    #>
    Process {
        # Get Managed Service Identity details from the Azure Functions application settings
        $MSIEndpoint = $env:MSI_ENDPOINT
        $MSISecret = $env:MSI_SECRET

        # Define the required URI and token request params
        $APIVersion = "2017-09-01"
        $ResourceURI = "https://graph.microsoft.com"
        $AuthURI = $MSIEndpoint + "?resource=$($ResourceURI)&api-version=$($APIVersion)"

        # Call resource URI to retrieve access token as Managed Service Identity
        $Response = Invoke-RestMethod -Uri $AuthURI -Method "Get" -Headers @{ "Secret" = "$($MSISecret)" }

        # Handle return value
        $BearerToken = $Response.access_token
        return $BearerToken
    }
}#end function 

Function Invoke-MSGraphQuery {
    [CmdletBinding(DefaultParametersetname = "Default")]
    Param(
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Refresh')]
        [string]$URI,
 
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Refresh')]
        [string]$Body,
 
        [Parameter(Mandatory = $true, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $true, ParameterSetName = 'Refresh')]
        [string]$token,
 
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Refresh')]
        [ValidateSet('GET', 'POST', 'PUT', 'PATCH', 'DELETE')]
        [string]$method = "GET",
    
        [Parameter(Mandatory = $false, ParameterSetName = 'Default')]
        [Parameter(Mandatory = $false, ParameterSetName = 'Refresh')]
        [switch]$recursive,
    
        [Parameter(Mandatory = $true, ParameterSetName = 'Refresh')]
        [switch]$tokenrefresh,
    
        [Parameter(Mandatory = $true, ParameterSetName = 'Refresh')]
        [pscredential]$credential,
    
        [Parameter(Mandatory = $true, ParameterSetName = 'Refresh')]
        [string]$tenantID
    )
    $authHeader = @{
        'Accept'        = 'application/json'
        'Content-Type'  = 'application/json'
        'Authorization' = "Bearer $Token"
    }
    
    [array]$returnvalue = $()
    Try {
        If ($body) {
            $Response = Invoke-RestMethod -Uri $URI -Headers $authHeader -Body $Body -Method $method -ErrorAction Stop
        }
        Else {
            $Response = Invoke-RestMethod -Uri $URI -Headers $authHeader -Method $method -ErrorAction Stop
        }
    }
    Catch {
        If (($Error[0].ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue).error.Message -eq 'Access token has expired.' -and $tokenrefresh) {
            $token = Get-BearerAuthToken
 
            $authHeader = @{
                'Content-Type'  = 'application/json'
                'Authorization' = $Token
            }
            $returnvalue = $()
            If ($body) {
                $Response = Invoke-RestMethod -Uri $URI -Headers $authHeader -Body $Body -Method $method -ErrorAction Stop
            }
            Else {
                $Response = Invoke-RestMethod -Uri $uri -Headers $authHeader -Method $method
            }
        }
        Else {
            Throw $_
        }
    }
 
    $returnvalue += $Response
    If (-not $recursive -and $Response.'@odata.nextLink') {
        Write-Warning "Query contains more data, use recursive to get all!"
        Start-Sleep 1
    }
    ElseIf ($recursive -and $Response.'@odata.nextLink') {
        If ($PSCmdlet.ParameterSetName -eq 'default') {
            If ($body) {
                $returnvalue += Invoke-MSGraphQuery -URI $Response.'@odata.nextLink' -token $token -body $body -method $method -recursive -ErrorAction SilentlyContinue
            }
            Else {
                $returnvalue += Invoke-MSGraphQuery -URI $Response.'@odata.nextLink' -token $token -method $method -recursive -ErrorAction SilentlyContinue
            }
        }
        Else {
            If ($body) {
                $returnvalue += Invoke-MSGraphQuery -URI $Response.'@odata.nextLink' -token $token -body $body -method $method -recursive -tokenrefresh -credential $credential -tenantID $TenantID -ErrorAction SilentlyContinue
            }
            Else {
                $returnvalue += Invoke-MSGraphQuery -URI $Response.'@odata.nextLink' -token $token -method $method -recursive -tokenrefresh -credential $credential -tenantID $TenantID -ErrorAction SilentlyContinue
            }
        }
    }
    Return $returnvalue
}





#Start script

Write-Information "Password last set request recieved."
#region initialize

# Setting inital Status Code: 
$StatusCode = [HttpStatusCode]::OK

#Tenant ID pulled from Application Configuration in Azure rather than hard coded.
$TenantID = $env:TenantID


#Extract variables from payload
#Who our user is, the devices Azure ID, and the Devices tenant ID.
$CurrentAzureADUser = $Request.Body.CurrentAzureADUser
$InboundDeviceID= $Request.Body.AzureADDeviceID
$InboundTenantID = $Request.Body.AzureADTenantID

Write-Information "Request recieved for $($CurrentAzureADUser)"

#region script
# Write to the Azure Functions log stream.
Write-Information "Inbound DeviceID $($InboundDeviceID)"
Write-Information "Inbound TenantID $($InboundTenantID)"
Write-Information "Environment TenantID $TenantID"

# Declare response object as Arraylist
$ResponseArray = New-Object -TypeName System.Collections.ArrayList

# Verify request comes from correct tenant
if($TenantID -eq $InboundTenantID){
    Write-Information "Request is comming from correct tenant"
    # Retrieve authentication token

    # Query graph for device verification 
    # Retrieve authentication token
    $Script:AuthToken = Get-AuthToken
    $DeviceURI = "https://graph.microsoft.com/v1.0/devices?`$filter=deviceId eq '$($InboundDeviceID)'"
    $DeviceIDResponse = (Invoke-RestMethod -Method "Get" -Uri $DeviceURI -ContentType "application/json" -Headers $Script:AuthToken -ErrorAction Stop).value

    # Assign to variables for matching 
    $DeviceID = $DeviceIDResponse.deviceId  
    $DeviceEnabled = $DeviceIDResponse.accountEnabled    
    Write-Information "DeviceID $DeviceID"   
    Write-Information "DeviceEnabled: $DeviceEnabled"
    # Verify request comes from a valid device

    if($DeviceID -eq $InboundDeviceID){
        Write-Information "Request is coming from a valid device in Azure AD"
        if($DeviceEnabled -eq "True"){
            Write-Information "Requesting device is not disabled in Azure AD"                       
            
            #Call our query for user
            $BearerToken = Get-BearerAuthToken
            $UserName   = $CurrentAzureADUser
            $resourceURL = "https://graph.microsoft.com/v1.0/users/$UserName`?`$select=userprincipalname,lastPasswordChangeDateTime"
            $User = Invoke-MSGraphQuery -method GET -URI $resourceURL -token $BearerToken
            
            #Format the date we get back
            [datetime]$lastpasswordChange = $User.lastPasswordChangeDateTime -replace "T", " " -replace "Z",""
            write-host "Password last set for $($CurrentAzureADUser) on $($lastpasswordChange)"

            #This is what we will return. It's the Azure User who was requested along with the date they last change their password.
            $PSObject = [PSCustomObject]@{
                CurrentAzureADUser = $CurrentAzureADUser
                lastpasswordChange = $lastpasswordchange
            }
            $ResponseArray.Add($PSObject) | Out-Null
            $StatusCode = [HttpStatusCode]::OK
            
                    
            } 
    else{
            Write-Warning "Device is not enabled - Forbidden"
            $StatusCode = [HttpStatusCode]::Forbidden
        }
    }
    else{
        Write-Warning  "Device not in my Tenant - Forbidden"
        $StatusCode = [HttpStatusCode]::Forbidden
    }
}
else{
    Write-Warning "Tenant not allowed - Forbidden"
    $StatusCode = [HttpStatusCode]::Forbidden
}
#endregion script
$body = $ResponseArray | ConvertTo-Json 
# Associate values to output bindings by calling 'Push-OutputBinding'.
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
    StatusCode = $StatusCode
    Body = $body
})
