# Requires -Version 2
# Requires -RunAsAdministrator
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
        Create secure shared folders for home directories / redirected folders and profiles
    
    .DESCRIPTION
        Create secure shared folders for home directories / redirected folders and profiles
        
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
        Specified a local path to share.

    .EXAMPLE
        .\New-SecureShare.ps1 -Path "E:\Home"

        Description:
        Creates a secure share for the folder E:\Home named Home.
#>
[CmdletBinding(SupportsShouldProcess = $True, HelpUri = 'https://github.com/aaronparker/secure-shares')]
[OutputType([System.Array])]
Param (
    [Parameter(Mandatory = $True, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, `
            HelpMessage = 'Specify a target path for the share.')]
    [Alias('FullName', 'PSPath')]
    [string] $Path,

    [Parameter(Mandatory = $True, HelpMessage = 'Specify a description for the share.')]
    [string] $Description = "User home folders"
)

Function Install-PSGallery {
    <# Trust the PowerShell Gallery #>
    If (Get-PSRepository | Where-Object { $_.Name -eq "PSGallery" -and $_.InstallationPolicy -ne "Trusted" }) {
        Write-Verbose "Trusting the repository: PSGallery"
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Set-PSRepository -Name PSGallery -InstallationPolicy Trusted
    }
}

# Get share name from $Path
$share = $(Split-Path $Path -Leaf)

try {
    # Install the NTFSSecurity module from the PowerShell Gallery
    If (!(Get-Module NTFSSecurity)) {
        Install-PSGallery
        Install-Module -Name NTFSSecurity -ErrorAction SilentlyContinue -Verbose
    }
}
catch {
    Write-Error "Unable to install the module NTFSSecurity with error $_."
    Break
}
finally {
    # Create the folder
    try {
        If (!(Test-Path -Path $Path)) { New-Item -Path $Path -ItemType Directory }
    }
    catch {
        Write-Error "Failed to create folder $Path with error $_."
    }

    # If the folder was created, let's set permissions and share it
    If (Test-Path -Path $Path) {
        Disable-NTFSAccessInheritance -Path $Path
        Get-NTFSAccess -Path $Path -Account Users | Remove-NTFSAccess
        Add-NTFSAccess -Path $Path -Account Users -AppliesTo ThisFolderOnly `
            -AccessRights CreateDirectories, ListDirectory, AppendData, Traverse, ReadAttributes

        # Share the folder
        New-SMBShare –Name $share –Path $Path `
            -FolderEnumerationMode AccessBased `
            –FullAccess "Administrators"  `
            -ChangeAccess "Authenticated Users" `
            -ReadAccess "Everyone" `
            -CachingMode Documents `
            -Description $Description

        # Return share details
        Write-Output (Get-SmbShare -Name $share)
    }
}
