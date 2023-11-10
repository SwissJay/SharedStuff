[CmdletBinding(SupportsShouldProcess=$true)]
Param (
    [Parameter(Mandatory=$false)][Switch]$ClearAll,
    [Parameter(Mandatory=$false)][Switch]$ClearSettingsFiles,
    [Parameter(Mandatory=$false)][Switch]$ClearLocalStorageDB
)
<#
.SYNOPSIS
This script uninstalls the Teams app and removes the Teams directory for a user. It also removes a registry key, as listed at https://docs.microsoft.com/en-us/microsoftteams/msi-deployment#clean-up-and-redeployment-procedure
.DESCRIPTION
Use this script to remove and clear the Teams app for each user on a computer. After you run this script, redeploy Teams.
#>
# *******************************************************************************************
# Functions
Function Test-RegistryValue
{
    param(
        [parameter(Mandatory=$true)][string]$RegKeyPath,
        [parameter(Mandatory=$true)][string]$Value
    )
    if(Test-Path -Path $RegKeyPath)
    {
        $ValueExist = $null -ne (Get-ItemProperty $RegKeyPath).$Value
    } else {
        $ValueExist = $false
    }
    Return $ValueExist
}
# *******************************************************************************************
# Out-JH-Log - Write to CSV logfile.
function Out-JH-Log
{
    [CmdletBinding()]
    param (
		[Parameter(Mandatory=$true)][string]$LogFilePathName,
		[Parameter(Mandatory=$false)][bool]$Append,
        [Parameter(Mandatory=$false)][string]$LogFileMessage,
		[Parameter(Mandatory=$false)][string]$LogFileHeader
    )
	# Did Append parameter get passed?
	if(!($PSBoundParameters.ContainsKey('Append')))
	{
		# If not, default to appending
		$Append = $true
	}
	# Prepend Header with data/time only if passed, otherwise log file is reset
	if($LogFileHeader)
	{
		$LogFileHeader = "Date_Time," + $LogFileHeader
	}
	# Prepend current date/time to LogFileMessage
	if($LogFileMessage)
	{
		$LogFileMessage = (Get-Date).ToString("yyyyMMdd_hhmmss_fff") + "," + $LogFileMessage
	}
	# Does logfile exist?
    if(Test-Path -Path $LogFilePathName)
    {
        # File exists, are we not appending?
        if(!($Append))
        {
            # Delete existing file and initialize with new header.
            Remove-Item -Path $LogFilePathName
            # Write new header to file
            $LogFileHeader | Out-File -FilePath $LogFilePathName -Encoding ascii
        }
        # Output message
        $LogFileMessage | Out-File -FilePath $LogFilePathName -Encoding ascii -Append
        # We're done here
        Return "OK"
    } else {
        # Log file does not exist, create path one folder at a time, if needed
        If((Test-Path (Split-Path -Path $LogFilePathName)) -ne $true)
        {
            $Folders = (Split-Path -Path $LogFilePathName).Split("\")
            $PathToTest = ""
            # Check each folder and create, if needed
            foreach($Folder in $Folders)
            {
                if($Folder.Length -gt 0)
                {
                    $ParentPath = $PathToTest
                    $PathToTest += $Folder
                    if((Test-Path -Path $PathToTest) -ne $true)
                    {
                        New-Item -Path $ParentPath -Name $Folder -ItemType Directory | Out-Null
                    }
                    $PathToTest += "\"
                }
            }
            # Final test
            If((Test-Path (Split-Path -Path $LogFilePathName)) -ne $true)
            {
                # Failed to create path
                Return "Failed to create log file path, aborting!"
            }
        }
        # Now create log file
        # Write new header to file if it's been passed
        if($LogFileHeader)
        {
            $LogFileHeader | Out-File -FilePath $LogFilePathName -Encoding ascii
        }
        # Output message
		if($LogFileMessage)
		{
			$LogFileMessage | Out-File -FilePath $LogFilePathName -Encoding ascii -Append
		}
        # We're done here
        Return "OK"
    }
}
# *******************************************************************************************

# Main Function
Write-Host ""
Write-Host "Microsoft Teams Cleaner v2022-05-06-1247" -ForegroundColor Blue
Write-Host "----------------------------------------" -ForegroundColor Blue
Write-Host ""
# Log
$LogFilePath = "C:\HCC\$($MyInvocation.MyCommand.Name)_RunLog.csv"
Out-JH-Log -LogFilePathName $LogFilePath -LogFileHeader "Microsoft Teams Cleaner v2022-05-06-1247" -LogFileMessage "Starting" | Out-Null
#Check incoming parameters
if($ClearAll)
{
    $ClearSettingsFiles = $True
    $ClearLocalStorageDB = $True
}
Write-Host "ClearAll           : $($ClearAll.ToString())" -ForegroundColor Yellow
Write-Host "ClearSettingsFiles : $($ClearSettingsFiles.ToString())" -ForegroundColor Yellow
Write-Host "ClearLocalStorageDB: $($ClearLocalStorageDB.ToString())" -ForegroundColor Yellow
Write-Host ""
Out-JH-Log -LogFilePathName $LogFilePath -LogFileMessage "Incoming parameters:`r`nClearAll           : $($ClearAll.ToString())`r`nClearSettingsFiles : $($ClearSettingsFiles.ToString())`r`nClearLocalStorageDB: $($ClearLocalStorageDB.ToString())" | Out-Null
#Find all the user profiles on the local machine
Write-Host "Checking for local user profiles... " -NoNewLine -ForegroundColor Yellow
$users = Get-ChildItem "C:\Users" -Exclude "defaultuser0","Public"
Write-Host "Found $($users.Count)." -ForegroundColor Green
#Loop through each profile and run the Microsoft steps
foreach($user in $users)
{
    Write-Host "*************************************" -ForegroundColor Blue
    Write-Host "Working on $($user):" -ForegroundColor Yellow
    # Teams install in <userprofile>\AppData\Local\Microsoft\Teams
    $TeamsPath = [System.IO.Path]::Combine($user.FullName, 'Appdata', 'Local', 'Microsoft', 'Teams')
    Write-Host "- Teams Path: " -NoNewLine -ForegroundColor Yellow
    Write-Host "$($TeamsPath)" -ForegroundColor Green
    # Teams cache is <userprofile>\AppData\Roaming\Microsoft\Teams
    $TeamsCachePath = [System.IO.Path]::Combine($user.FullName, 'Appdata', 'Roaming', 'Microsoft', 'Teams')
    Write-Host "- Teams Cache Path: " -NoNewLine -ForegroundColor Yellow
    Write-Host "$($TeamsCachePath)" -ForegroundColor Green
    # Microsoft's script from https://docs.microsoft.com/en-us/microsoftteams/scripts/powershell-script-deployment-cleanup, altered a bit.
    # Teams Update.EXE is in <userprofile>\AppData\Local\Microsoft\Teams
    $TeamsUpdateExePath = [System.IO.Path]::Combine($TeamsPath, 'Update.exe')
    Write-Host "- Teams Uninstaller Path: " -NoNewLine -ForegroundColor Yellow
    Write-Host "$($TeamsUpdateEXEPath)" -ForegroundColor Green
    Write-Host ""
    Out-JH-Log -LogFilePathName $LogFilePath -LogFileMessage "User $($user):`r`nTeams Path: $($TeamsPath)`r`nTeams Cache Path: $($TeamsCachePath)`r`nTeams Uninstaller Path: $($TeamsUpdateEXEPath)" | Out-Null
    try
    {
        # Uninstall app
        Write-Host "Uninstalling Teams... " -NoNewLine -ForegroundColor Yellow
        if([System.IO.File]::Exists($TeamsUpdateExePath))
        {
            Write-Verbose ""
            Write-Verbose "Running $($TeamsUpdateExePath) -uninstall -s"
            $proc = Start-Process $TeamsUpdateExePath "-uninstall -s" -PassThru -Wait
            #$proc.WaitForExit()
            Write-Host "OK" -ForegroundColor Green
        } else {
            Write-Host "Not installed for user" -ForegroundColor Magenta
        }
        # Delete app folder
        Write-Host "Removing folder $($TeamsPath)... " -NoNewLine -ForegroundColor Yellow
        if(Test-Path -Path $TeamsPath)
        {
            Remove-Item -path $TeamsPath -recurse -force
            Write-Host "OK" -ForegroundColor Green
        } else {
            Write-Host "Not present for user" -ForegroundColor Magenta
        }
        # Delete cache folder
        # Preserve files: storage.json, desktop-config.json, settings.json, Preferences
        # Preserve folders: Backgrounds
        # Exclude folders: meeting-addin
        Write-Host "Clearing most content from folder $($TeamsCachePath)... " -NoNewLine -ForegroundColor Yellow
        if(Test-Path -Path $TeamsCachePath)
        {
            Write-Verbose ""
            Write-Verbose "$($TeamsCachePath) exists."
            # Outlook (because of the add-in) and Teams (for obvious reasons) should not be running for any of this to work, of course.
            # If ClearAll is set, nuke it all!
            if($ClearAll)
            {
                Remove-Item -path $TeamsCachePath -recurse -force -confirm:$false
            } else {
                # Start by deleting items that do not match any exclusions
                Get-ChildItem -Path $TeamsCachePath -Recurse -Exclude "storage.json","desktop-config.json","settings.json","Preferences" |
                    Select-Object -ExpandProperty FullName |
                        Where-Object {($_ -notlike "$($TeamsCachePath)\Backgrounds\*") -And ($_ -notlike "$($TeamsCachePath)\Backgrounds") -And ($_ -notlike "$($TeamsCachePath)\meeting-addin\*") -And ($_ -notlike "$($TeamsCachePath)\meeting-addin") -And ($_ -notlike "$($TeamsCachePath)\Local Storage\*") -And ($_ -notlike "$($TeamsCachePath)\Local Storage")} |
                            Sort-Object length -Descending |
                                Remove-Item -Force -Recurse -Confirm:$false
                # Now check passed switches
                if($ClearSettingsFiles)
                {
                    # Same as above but no file exclusions
                    Get-ChildItem -Path $TeamsCachePath -Recurse |
                    Select-Object -ExpandProperty FullName |
                        Where-Object {($_ -notlike "$($TeamsCachePath)\Backgrounds\*") -And ($_ -notlike "$($TeamsCachePath)\Backgrounds") -And ($_ -notlike "$($TeamsCachePath)\meeting-addin\*") -And ($_ -notlike "$($TeamsCachePath)\meeting-addin") -And ($_ -notlike "$($TeamsCachePath)\Local Storage\*") -And ($_ -notlike "$($TeamsCachePath)\Local Storage")} |
                            Sort-Object length -Descending |
                                Remove-Item -Force -Confirm:$false
                }
                if($ClearLocalStorageDB)
                {
                    # Save it all but rid us of the local store db
                    Get-ChildItem -Path $TeamsCachePath -Recurse -Exclude "storage.json","desktop-config.json","settings.json","Preferences" |
                    Select-Object -ExpandProperty FullName |
                        Where-Object {($_ -notlike "$($TeamsCachePath)\Backgrounds\*") -And ($_ -notlike "$($TeamsCachePath)\Backgrounds") -And ($_ -notlike "$($TeamsCachePath)\meeting-addin\*") -And ($_ -notlike "$($TeamsCachePath)\meeting-addin")} |
                            Sort-Object length -Descending |
                                Remove-Item -Force -Confirm:$false
                }                
            }
            Write-Host "OK" -ForegroundColor Green
        } else {
            Write-Host "Not present for user" -ForegroundColor Magenta
        }
        # Fix registry key, per Microsoft.
        $ntPath = $user.FullName + "\NTUSER.DAT"
        $hiveName = "HKU\" + $user.Name
        $userName = $user.Name
        $TeamsRegistryKey = "HKEY_USERS\$($userName)\Software\Microsoft\Office\Teams"
        $TeamsRegistryValue = "$($TeamsRegistryKey)\PreventInstallationFromMsi"
        $RegistryInUse = $False
        Write-Host "Removing registry value $($TeamsRegistryValue)... " -NoNewLine -ForegroundColor Yellow
        # Load user hive
        Write-Verbose ""
        Write-Verbose "Running c:\windows\system32\reg.exe load $($hiveName) $($ntPath)"
        $proc = Start-Process c:\windows\system32\reg.exe "load $($hiveName) $($ntPath)" -PassThru -WindowStyle Hidden -Wait
        #$proc.WaitForExit()
        # If it returns 1, try to access directly as it might be a logged-in user
        if($proc.ExitCode -eq 1)
        {
            Out-JH-Log -LogFilePathName $LogFilePath -LogFileMessage "User registry in use, attempting alternate way." | Out-Null
            Write-Host "In Use?!"
            Write-Host "Profile appears to be in use, attempting alternate way..." -ForegroundColor Yellow
            $RegistryInUse = $True
            # Need user SID
            $UserAccount = New-Object System.Security.Principal.NTAccount($userName)
            $UserSID = ($UserAccount.Translate([System.Security.Principal.SecurityIdentifier]).Value)
            # Build new key
            $TeamsRegistryKey = "HKEY_USERS\$($UserSID)\Software\Microsoft\Office\Teams"
            $TeamsRegistryValue = "$($TeamsRegistryKey)\PreventInstallationFromMsi"
            Write-Host "Removing registry value $($TeamsRegistryValue)... " -NoNewLine -ForegroundColor Yellow
        }
        if(Test-RegistryValue -RegKeyPath "Registry::$($TeamsRegistryKey)" -Value "PreventInstallationFromMsi")
        {
            # Reset the user's registry key
            Remove-ItemProperty -Path "Registry::$($TeamsRegistryKey)" -Name "PreventInstallationFromMsi" -Force
            Write-Host "OK" -ForegroundColor Green
        } else {
            Write-Host "Not present for user" -ForegroundColor Magenta
        }
        # Collect garbage    
        [gc]::Collect()
        # Unload ntuser.dat user hive
        if(!($RegistryInUse))
        {
            Write-Verbose ""
            Write-Verbose "Running c:\windows\system32\reg.exe unload $($hiveName)"
            $proc = Start-Process c:\windows\system32\reg.exe "unload $($hiveName)" -PassThru -WindowStyle Hidden -Wait
            #$proc.WaitForExit()
        }
    }
    catch
    {
        Write-Host "Uninstall failed with error $($_.exception.message)!"
        Out-JH-Log -LogFilePathName $LogFilePath -LogFileMessage "Uninstall failed with error $($_.exception.message)!" | Out-Null
    }
    #######################################################################################################################
}
Write-Host "*************************************" -ForegroundColor Blue
Write-Host "All done, re-install the system-wide installer and login to test."
Out-JH-Log -LogFilePathName $LogFilePath -LogFileMessage "All done, re-install the system-wide installer and login to test." | Out-Null

