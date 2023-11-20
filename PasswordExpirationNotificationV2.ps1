#Function App for checking password expiration via graph
        #Author:      Maxton Allen
        #Contact:     @AzuretotheMax
        #Website:     AzureToTheMax.net
        #Created:     01-30-2023
	#Credit: This script is based on the client-side script by Jan Ketil Skanke (@JankeSkanke) of the MSEndpointMgr team. It is also based on Viktor's original script in the smthwentright blog. See my blog below covering this project for further details.
 	#Blog: https://azuretothemax.net/2023/02/10/windows-toast-notification-based-password-expiration-reminders/


#changeable Values
$FunctionURL = "https:/XXXXXXX.azurewebsites.net/api/XXXXXX?" #Your Function App URL and Function trigger name itself.
$PasswordExpirationDays = 365 #How often do passwords expire
$MinimumDays = 14 #how many days remaning of password life before you start to prompt. Eg: 14. use higher values for testing.
$HeroImageFile = "https://XXXXXXXX.blob.core.windows.net/XXXXXXXX/Microsoft.jpg" #Your Image URL including the image name.
$HeroImageName = "Microsoft.jpg" #Just the image name
$Action = "https://passwordreset.microsoftonline.com/" #Link for the reset button. This is the SSPR portal, there are several you could driect users to. SSPR requires M-MFA to be registered, try it out.
$logfilename = "PasswordNotification" #Name of the log file for logging out when this runs and what it does. Good for troubleshooting and proving it's doing it's job.
$logfile = Join-Path "C:\programdata\PasswordNotification"-Childpath "$logfilename.log" #where the log file will be stored. Change the storage dir creation if you alter this!
$LogfileSizeMax = 500 #MB How big the log file can get. Don't worry it grows very slowly. 


#Write JSON to file for testing only! Should be FALSE
$WriteLogFile = $false

#Create my Storage Dir
$TestFolder = Test-Path C:\ProgramData\PasswordNotification
if ($TestFolder -eq $false) {
New-Item C:\programdata\PasswordNotification -ItemType Directory -ErrorAction SilentlyContinue > $null 
#Set dirs as hidden
$folder = Get-Item "C:\programdata\PasswordNotification" 
$folder.Attributes = 'Directory','Hidden' 
}

#begin logging
If ($logfilename) {
    If (((Get-Item -ErrorAction SilentlyContinue $logfile).length / 1MB) -gt $LogfileSizeMax) { Remove-Item $logfile -Force }
    Start-Transcript $logfile -Append | Out-Null
    Get-Date
}



#region functions
#Function to get AzureAD TenantID
function Get-AzureADTenantID {
    # Cloud Join information registry path
    $AzureADTenantInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\TenantInfo"
    # Retrieve the child key name that is the tenant id for AzureAD
    $AzureADTenantID = Get-ChildItem -Path $AzureADTenantInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
    return $AzureADTenantID
}           

function Get-AzureADDeviceID {
    Process {
        # Define Cloud Domain Join information registry path
        $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
        # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
        $AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
        if ($AzureADJoinInfoThumbprint -ne $null) {
            # Retrieve the machine certificate based on thumbprint from registry key
            $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoThumbprint }
            if ($AzureADJoinCertificate -ne $null) {
                # Determine the device identifier from the subject name
                $AzureADDeviceID = ($AzureADJoinCertificate | Select-Object -ExpandProperty "Subject") -replace "CN=", ""
                # Handle return value
                return $AzureADDeviceID
            }
            if ($AzureADJoinCertificate -eq $null) {
                $AzureADDeviceID = $AzureADJoinInfoThumbprint
                return $AzureADDeviceID
            }
        }
    }
} #endfunction 

function Test-WindowsPushNotificationsEnabled() {
	$ToastEnabledKey = (Get-ItemProperty "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name ToastEnabled -ErrorAction Ignore).ToastEnabled
	if ($ToastEnabledKey -eq "1") {
		Write-Output "Toast notifications are enabled in Windows"
		return $true
	}
	elseif ($ToastEnabledKey -eq "0") {
		Write-Output "Toast notifications are not enabled in Windows. The script will run, but toasts might not be displayed"
		return $false
	}
	else {
		Write-Output "The registry key for determining if toast notifications are enabled does not exist. The script will run, but toasts might not be displayed"
		return $false
	}
}
 
function Display-ToastNotification() {
 
	$Load = [Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
	$Load = [Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
 
	# Load the notification into the required format
	$ToastXml = New-Object -TypeName Windows.Data.Xml.Dom.XmlDocument
	$ToastXml.LoadXml($Toast.OuterXml)
		
	# Display the toast notification
	try {
		Write-Output "All good. Displaying the toast notification"
		[Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($App).Show($ToastXml)
	}
	catch { 
		Write-Output "Something went wrong when displaying the toast notification"
		Write-Output "Make sure the script is running as the logged on user"    
	}
	if ($CustomAudio -eq "True") {
		Invoke-Command -ScriptBlock {
			Add-Type -AssemblyName System.Speech
			$speak = New-Object System.Speech.Synthesis.SpeechSynthesizer
			$speak.Speak($CustomAudioTextToSpeech)
			$speak.Dispose()
		}    
	}
}
 
function Test-NTSystem() {  
	$currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
	if ($currentUser.IsSystem -eq $true) {
		$true  
	}
	elseif ($currentUser.IsSystem -eq $false) {
		$false
	}
}

function Get-AzureADJoinDate {
    Process {
        # Define Cloud Domain Join information registry path
        $AzureADJoinInfoRegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\CloudDomainJoin\JoinInfo"
		
        # Retrieve the child key name that is the thumbprint of the machine certificate containing the device identifier guid
        $AzureADJoinInfoThumbprint = Get-ChildItem -Path $AzureADJoinInfoRegistryKeyPath | Select-Object -ExpandProperty "PSChildName"
        if ($AzureADJoinInfoThumbprint -ne $null) {
            # Retrieve the machine certificate based on thumbprint from registry key
            $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Thumbprint -eq $AzureADJoinInfoThumbprint }
            if ($AzureADJoinCertificate -ne $null) {
                # Determine the device identifier from the subject name
                $AzureADJoinDate = ($AzureADJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
                # Handle return value
                return $AzureADJoinDate
            }
            if ($AzureADJoinCertificate -eq $null) {
                $AzureADJoinCertificate = Get-ChildItem -Path "Cert:\LocalMachine\My" -Recurse | Where-Object { $PSItem.Subject -eq "CN=$($AzureADJoinInfoThumbprint)" }
                $AzureADJoinDate = ($AzureADJoinCertificate | Select-Object -ExpandProperty "NotBefore") 
                return $AzureADJoinDate
            }
        }
    }
} #endfunction 


#Region gather values
$AzureADDeviceID = Get-AzureADDeviceID
$AzureADTenantID = Get-AzureADTenantID



#Gather user SID / active user

        #Active Sessions
        $CurrentLoggedOnUser = (Get-CimInstance win32_computersystem).UserName

    if (-not ([string]::IsNullOrEmpty($CurrentLoggedOnUser))) {
        #Active Sessions
        write-host "Active Sessions"
        $AdObj = New-Object System.Security.Principal.NTAccount($CurrentLoggedOnUser)
        $strSID = $AdObj.Translate([System.Security.Principal.SecurityIdentifier])
        $LoggedSID = $strSID.Value
    } else {
        #Remote Sessions
        write-host "Remote Session"
        $users = Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object { $_.GetOwner() } | Select-Object -Unique -Expand User

        if ($users -ne $null) {
			#Azure/local domain suffix!
            $users = "AzureAD\$($users)"
            $LoggedSID = $users | ForEach-Object { ([System.Security.Principal.NTAccount]$_).Translate([System.Security.Principal.SecurityIdentifier]).Value }    
        }
    }
    
 

$CurrentAzureADUser = (Get-ItemProperty -ErrorAction SilentlyContinue -Path "HKLM:\SOFTWARE\Microsoft\IdentityStore\Cache\$LoggedSID\IdentityCache\$LoggedSID" -Name UserName).UserName

#If we failed to pull a value both ways, which means were probably on a hybrid device, try getting the user to query by looking at who is running process explorer. 
#This would probably not go well on a RDP multi-session system.
If (!($CurrentAzureADUser)) { Write-Output "Failed to gather CurrentAzureADUser. Value returned is $CurrentAzureADUser : Trying Explorer process owner." 

$users = Get-WmiObject Win32_Process -Filter "Name='explorer.exe'" | ForEach-Object { $_.GetOwner() } | Select-Object -Unique -Expand User
#Set Domain Suffix
$CurrentAzureADUser = $users + "@XXXXX.com" #Set me!!!

}

#if still nothing, something is horribly wrong.
If (!($CurrentAzureADUser)) { Write-Output "Error: Failed to gather CurrentAzureADUser entirely. Value returned is $CurrentAzureADUser : exiting" 

exit 1

}


write-host "User is $CurrentAzureADUser"
#endregion




#assemble our query to our funciton app
$headers = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
$headers.Add("Content-Type", "application/json")

$MainPayLoad = [PSCustomObject]@{
    AzureADTenantID = $AzureADTenantID
    AzureADDeviceID = $AzureADDeviceID
	CurrentAzureADUser = $CurrentAzureADUser
}
$MainPayLoadJson = $MainPayLoad  | ConvertTo-Json







#Make our query

#If testing is on and for some reason you want to see the JSON we are using...
if ($WriteLogFile){
    write-host "writting log file"
New-Item C:\Temp -ItemType Directory -ErrorAction SilentlyContinue > $null 
New-Item C:\Temp\PasswordPopup -ItemType Directory -ErrorAction SilentlyContinue > $null 
$MainPayLoadJson  | Out-File "C:\Temp\PasswordPopup\Payload.json"

} else {

# Submit the data to the API endpoint

#execution randomization
#Randomize over 50 minutes to spread load on Azure Function - disabled on date of enrollment 
$JoinDate = Get-AzureADJoinDate
$DelayDate = $JoinDate.AddDays(1)
$CompareDate = ($DelayDate - $JoinDate)
if ($CompareDate.Days -ge 1){
	$ExecuteInSeconds = (Get-Random -Maximum 3000 -Minimum 1)
	#Write-Output "Randomzing execution time by $($ExecuteInSeconds) seconds."
	#Start-Sleep -Seconds $ExecuteInSeconds
}


#Write upload intent to console
Write-Output "Sending Payload..."

#Upload Data

    #Function App Upload Commands
    $Response = Invoke-RestMethod $FunctionURL -Method 'POST' -Headers $headers -Body $MainPayLoadJson 
    write-host "User: $($response.CurrentAzureADUser)"
    write-host "Last Reset: $($response.lastpasswordchange)"
}


#verify matching user on return data
if ($response.CurrentAzureADUser -eq $CurrentAzureADUser){
    write-host "Returned user ID of $($response.CurrentAzureADUser) matched sent user ID of $($CurrentAzureADUser)"
} else {
    write-host "Error: Returned user ID of $($response.CurrentAzureADUser) does NOT match user ID of $($CurrentAzureADUser)"
    exit 1
}


#parse return values
$lastpasswordChange = [datetime]($response.lastpasswordchange)
$PasswordExpirationDate = ($lastpasswordChange).AddDays($PasswordExpirationDays)
 
$StartDate  = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
 
$TimeSpan = New-Timespan -Start $StartDate -End $PasswordExpirationDate

Write-host "$($TimeSpan.days) days remaining of password life"


#Further Math Controls
#Use this if you want it to stop prompting say after -31 days
#If (($TimeSpan.Days -le $MinimumDays) -and ($TimeSpan.Days -ge -31))

#I recommend doing this though and using an exception group for anyone who clearly isnt under the same policy (could always deploy more than one of these for each policy) or has no expiration at all!
If (($TimeSpan.Days -le $MinimumDays)) {
    Write-Output "Warning: Password Expires within the minimum set of $($MinimumDays) days - throwing notification!"
    
#Generate popup
#Message Text
$TitleText = "Windows Password Alert"
$BodyText1 = "Your Windows password will expire soon."
$BodyText2 = "Your password is $($TimeSpan.Days) day(s) from expiring. Please consider changing it soon. If you are unable to reset your password or your password has already been reset, please contact the help desk."
$HeaderText = "Windows Account Security Notification"


 
$WindirTemp = Join-Path $Env:Windir -Childpath "Temp"
$UserTemp = $Env:Temp
$UserContext = [Security.Principal.WindowsIdentity]::GetCurrent()
 
Switch ($UserContext) {
    { $PSItem.Name -Match       "System"    } { Write-Output "Running as System"  ; $Temp =  $UserTemp   }
    { $PSItem.Name -NotMatch    "System"    } { Write-Output "Not running System" ; $Temp =  $WindirTemp }
    Default { Write-Output "Could not translate Usercontext" }
}
 

 
	$HeroImagePath = Join-Path -Path $Env:Temp -ChildPath $HeroImageName
	If (!(Test-Path $HeroImagePath)) { Start-BitsTransfer -Source $HeroImageFile -Destination $HeroImagePath }	
 
	##Setting image variables
	$LogoImage = ""
	$HeroImage = $HeroImagePath
	$RunningOS = Get-CimInstance -Class Win32_OperatingSystem | Select-Object BuildNumber
 
	$isSystem = Test-NTSystem
	if ($isSystem -eq $True) {
		Write-Output "Aborting script"
		Exit 1
	}
 
	$WindowsPushNotificationsEnabled = Test-WindowsPushNotificationsEnabled
 
	$PSAppStatus = "True"
 
	if ($PSAppStatus -eq "True") {
		$RegPath = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Notifications\Settings"
		#App Control
		#$App = "Microsoft.CompanyPortal_8wekyb3d8bbwe!App"
		$App = "Windows.SystemToast.DeviceManagement"
		
		if (-NOT(Test-Path -Path "$RegPath\$App")) {
			New-Item -Path "$RegPath\$App" -Force
			New-ItemProperty -Path "$RegPath\$App" -Name "ShowInActionCenter" -Value 1 -PropertyType "DWORD"
		}
		
		if ((Get-ItemProperty -Path "$RegPath\$App" -Name "ShowInActionCenter" -ErrorAction SilentlyContinue).ShowInActionCenter -ne "1") {
			New-ItemProperty -Path "$RegPath\$App" -Name "ShowInActionCenter" -Value 1 -PropertyType "DWORD" -Force
		}
	}

	$EnabledKey = get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\$($App)\"
	$EnabledKey = $EnabledKey.Enabled
	if ($EnabledKey -eq "0") {
		#If it exists, it means it's actually disabled - change it to 1. Deleting it doesn't work (even though that's the default enabled state)
		write-host "Warning: $($App) notifications have been silenced! Re-enabling!"
		new-itemproperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\$($App)\" -name "Enabled" -value 1 -ErrorAction SilentlyContinue
		set-itemproperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\$($App)\" -name "Enabled" -value 1 -ErrorAction SilentlyContinue

	}

	$UrgentKey = get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\$($App)\"
	$UrgentKey = $UrgentKey.AllowUrgentNotifications
	if ($UrgentKey -ne "1"){
		write-host "Warning: $($App) notifications were not allowed to send during DND, changing!"
		new-itemproperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\$($App)\" -name "AllowUrgentNotifications" -value 1 -ErrorAction SilentlyContinue
		set-itemproperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\$($App)\" -name "AllowUrgentNotifications" -value 1 -ErrorAction SilentlyContinue
	}

	$LockKey = get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\$($App)\"
	$LockKey = $LockKey.AllowContentAboveLock
	if ($LockKey -ne "0"){
		write-host "Warning: $($App) notifications were allowed on the lock screen, changing!"
		new-itemproperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\$($App)\" -name "AllowContentAboveLock" -value 0 -ErrorAction SilentlyContinue
		set-itemproperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\$($App)\" -name "AllowContentAboveLock" -value 0 -ErrorAction SilentlyContinue
	}

	$RankKey = get-ItemProperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\$($App)\"
	$RankKey = $RankKey.Rank
	if ($RankKey -ne "99"){
		write-host "Warning: $($App) notifications were not set to priority, changing!"
		new-itemproperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\$($App)\" -name "Rank" -value 99 -ErrorAction SilentlyContinue
		set-itemproperty -path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings\$($App)\" -name "Rank" -value 99 -ErrorAction SilentlyContinue
	}
	



 
	#$AttributionText = "Information"
 
	$ActionButtonContent = "Change Password"
	$DismissButtonContent = "Remind me later"
 
	$CustomAudio = "false"
	$CustomAudioTextToSpeech = $Xml.Configuration.Option | Where-Object {$_.Name -like 'CustomAudio'} | Select-Object -ExpandProperty 'TextToSpeech'
 
	
	$Scenario = "Reminder"
		
	# Formatting the toast notification XML
	# Create the default toast notification XML with action button and dismiss button
	[xml]$Toast = @"
	<toast scenario="$Scenario">
	<visual>
	<binding template="ToastGeneric">
		<image placement="hero" src="$HeroImage"/>
		<image id="1" placement="appLogoOverride" hint-crop="circle" src="$LogoImage"/>
		<text>$HeaderText</text>
		<group>
			<subgroup>
				<text hint-style="title" hint-wrap="true" >$TitleText</text>
			</subgroup>
		</group>
		<group>
			<subgroup>     
				<text hint-style="body" hint-wrap="true" >$BodyText1</text>
			</subgroup>
		</group>
		<group>
			<subgroup>     
				<text hint-style="body" hint-wrap="true" >$BodyText2</text>
			</subgroup>
		</group>
	</binding>
	</visual>
	<actions>
		<action activationType="protocol" arguments="$Action" content="$ActionButtonContent" />
		<action activationType="system" arguments="dismiss" content="$DismissButtonContent"/>
	</actions>
	</toast>
"@
	
	Display-ToastNotification
 
    If ($logfilename) {
        Stop-Transcript | Out-Null

        exit 0
    }

} else {

    Write-Output "Account still has $($TimeSpan.Days) days remaining, which is greater than the minimum notification range of $($MinimumDays) days - exiting!"
    If ($logfilename) {
        Stop-Transcript | Out-Null
    }
    exit 0

}
 
