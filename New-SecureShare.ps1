#Requires -Version 5
#Requires -RunAsAdministrator
<#PSScriptInfo
    .VERSION 2.0
    .GUID f5fcfeee-d09e-48ce-b0b7-c68e23d64f66
    .AUTHOR Aaron Parker, @stealthpuppy
    .COMPANYNAME stealthpuppy
    .COPYRIGHT Aaron Parker, https://stealthpuppy.com
    .TAGS Secure Shares NTFS
    .LICENSEURI https://github.com/aaronparker/secure-shares/blob/master/LICENSE
    .PROJECTURI https://github.com/aaronparker/secure-shares/
    .ICONURI 
    .EXTERNALMODULEDEPENDENCIES 
    .REQUIREDSCRIPTS 
    .EXTERNALSCRIPTDEPENDENCIES 
    .RELEASENOTES
    .PRIVATEDATA
#>
<#
    .SYNOPSIS
        Create secure shared folders for home directories / redirected folders and profiles.
    
    .DESCRIPTION
        Create secure shared folders for home directories / redirected folders and profiles.
        
        Sources:
        https://support.microsoft.com/en-us/help/274443/how-to-dynamically-create-security-enhanced-redirected-folders-by-using-folder-redirection-in-windows-2000-and-in-windows-server-2003
        https://technet.microsoft.com/en-us/library/jj649078(v=ws.11).aspx

    .NOTES
        Name: New-SecureShare.ps1
        Author: Aaron Parker
        Twitter: @stealthpuppy
        
    .LINK
        https://stealthpuppy.com

    .INPUTS
    
    .OUTPUTS

    .PARAMETER Path
        Specifies a local path to share.

    .PARAMETER Description
        Specifies a description for the share.

    .PARAMETER CachingMode
        Specifies the caching mode of the offline files for the SMB share. There are five caching modes:

            -- None. Prevents users from storing documents and programs offline.
            -- Manual. Allows users to identify the documents and programs they want to store offline.
            -- Programs. Automatically stores documents and programs offline.
            -- Documents. Automatically stores documents offline.
            -- BranchCache. Enables BranchCache and manual caching of documents on the shared folder.

    .EXAMPLE
        .\New-SecureShare.ps1 -Path "E:\Home" -CachingMode Documents

        Description:
        Creates a secure share for the folder E:\Home named Home, with Offline Settings set to automatic.

    .EXAMPLE
        .\New-SecureShare.ps1 -Path "E:\Profiles" -Description "User roaming profiles"

        Description:
        Creates a secure share for the folder E:\Profiles named Profiles, with Offline Settings set to none and sets a custom description.
#>
[CmdletBinding(SupportsShouldProcess = $True, HelpUri = 'https://github.com/aaronparker/secure-shares')]
[OutputType([System.Array])]
Param (
    [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, `
            HelpMessage = 'Specify a target path for the share.')]
    [ValidateScript( {
            if ( -Not ((Split-Path -Path $_) | Test-Path) ) {
                throw "Parent path $(Split-Path -Path $_) does not exist."
            }
            return $true
        })]
    [Alias('FullName', 'PSPath')]
    [string] $Path,

    [Parameter(Mandatory = $False, HelpMessage = 'Specify a description for the share.')]
    [string] $Description = "Secure share with access-based enumeration. Created with PowerShell.",

    [Parameter(Mandatory = $False, HelpMessage = 'Set the share caching mode. Use None for profile shares.')]
    [ValidateSet('None', 'Manual', 'Documents', 'Programs', 'BranchCache')]
    [string] $CachingMode = "None"
)

# Trust the PowerShell Gallery
Function Install-PSGallery {
    [CmdletBinding(SupportsShouldProcess = $True)]
    Param()
    If (Get-PSRepository | Where-Object { $_.Name -eq "PSGallery" -and $_.InstallationPolicy -ne "Trusted" }) {
        Write-Verbose "Trusting the repository: PSGallery"
        If ($pscmdlet.ShouldProcess("NuGet", "Installing Package Provider")) {
            try {
                Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.208
            }
            catch {
                Throw "Failed to install package provider NuGet with error $_."
                Break
            }
        }
        If ($pscmdlet.ShouldProcess("PowerShell Gallery", "Trusting PowerShell Repository")) {
            Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
        }
    }
}

# Get share name from $Path
$share = $(Split-Path $Path -Leaf)
If (Get-SmbShare -Name $share -ErrorAction SilentlyContinue) {
    Write-Warning "$share share already exists."
    $output = Get-SmbShare -Name $share -ErrorAction SilentlyContinue | Select-Object -First 1
    Write-Output $output
}
Else {
    try {
        # Install the NTFSSecurity module from the PowerShell Gallery
        If (!(Get-Module NTFSSecurity)) {
            Install-PSGallery
            If ($pscmdlet.ShouldProcess("NTFSSecurity", "Installing module")) {
                Install-Module -Name NTFSSecurity -ErrorAction SilentlyContinue -Verbose
            }
        }
    }
    catch {
        Write-Error "Unable to install the module NTFSSecurity with error $_."
        Break
    }
    finally {
        # Create the folder
        try {
            If (!(Test-Path -Path $Path)) {
                If ($pscmdlet.ShouldProcess($Path, "Creating directory")) {
                    New-Item -Path $Path -ItemType Directory > $Null
                }
            }
        }
        catch {
            Write-Error "Failed to create folder $Path with error $_."
        }

        # Clear permissions on the path so that we can re-create secure permissions
        If ($pscmdlet.ShouldProcess($Path, "Clearing NTFS permissions")) {
            Clear-NTFSAccess -Path $Path -DisableInheritance
        }

        # Add NTFS permissions for securely creating shares
        # Administrators and System
        If ($pscmdlet.ShouldProcess($Path, "Adding 'Administrators', 'System' with Full Control")) {
            ForEach ($account in 'Administrators', 'System') {
                $addNtfsParams = @{
                    Path         = $Path
                    Account      = $account
                    AccessRights = 'FullControl'
                }
                Add-NTFSAccess @addNtfsParams
            }
        }

        # Users - enable the ability to create a folder
        If ($pscmdlet.ShouldProcess($Path, "Adding 'Users' rights to create sub-folders")) {
            $addNtfsParams = @{
                Path         = $Path
                Account      = 'Users'
                AppliesTo    = 'ThisFolderOnly'
                AccessRights = @('CreateDirectories', 'ListDirectory', 'AppendData', 'Traverse', 'ReadAttributes')
            }
            Add-NTFSAccess @addNtfsParams
        }

        # Creator Owner - users then get full control on the folder they've created
        If ($pscmdlet.ShouldProcess($Path, "Adding 'CREATOR OWNER' with Full Control on sub-folders")) {
            $addNtfsParams = @{
                Path         = $Path
                Account      = 'CREATOR OWNER'
                AppliesTo    = 'SubfoldersAndFilesOnly'
                AccessRights = 'FullControl'
            }
            Add-NTFSAccess @addNtfsParams
        }

        # Share the folder with access-based enumeration
        If ($pscmdlet.ShouldProcess($Path, "Sharing")) {
            $newShareParams = @{
                Name                  = $share
                Path                  = $Path
                FolderEnumerationMode = 'AccessBased'
                FullAccess            = 'Administrators'
                ChangeAccess          = 'Authenticated Users'
                ReadAccess            = 'Everyone'
                CachingMode           = $CachingMode
                Description           = $Description
            }
            New-SMBShare @newShareParams
        }
    }

    # Return share details (Get-SmbShare returns the shared folder twice)
    $output = Get-SmbShare -Name $share -ErrorAction SilentlyContinue | Select-Object -First 1
    Write-Output $output
}
