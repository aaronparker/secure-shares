# Requires -Version 2
# Requires -RunAsAdministrator
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
        Specified a path to one or more location which to scan files.

    .EXAMPLE
        .\New-SecureShare.ps1 -Path "E:\Home"

        Description:
        Creates a secure share for the folder E:\Home named Home.
#>
[CmdletBinding(SupportsShouldProcess = $False, HelpUri = 'https://github.com/aaronparker/secure-shares')]
[OutputType([System.Array])]
Param (
    [Parameter(Mandatory = $False, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True, `
            HelpMessage = 'Specify a target path for the share.')]
    [Alias('FullName', 'PSPath')]
    [string[]]$Path
)
Begin {
    Try {
        If (!(Get-Module NTFSSecurity)) {
            Install-Module -Name NTFSSecurity -ErrorAction SilentlyContinue -Verbose
        }
    }
    Catch {
        Write-Error "Unable to install the module NTFSSecurity."
        Break
    }
}
Process {
    ForEach ($Folder in $Path) {
        # Create the folder and set permissions
        If (!(Test-Path -Path $Folder)) { New-Item -Path $Folder -ItemType Directory }
        Disable-NTFSAccessInheritance -Path $Path
        Get-NTFSAccess -Path $Folder -Account Users | Remove-NTFSAccess
        Add-NTFSAccess -Path $Folder -Account Users -AppliesTo ThisFolderOnly `
        -AccessRights CreateDirectories, ListDirectory, AppendData, Traverse, ReadAttributes

        # Share the folder
        New-SMBShare –Name $(Split-Path $Folder -Leaf) –Path $Folder `
            -FolderEnumerationMode AccessBased `
            –FullAccess "Administrators"  `
            -ChangeAccess "Authenticated Users" `
            -ReadAccess "Everyone" `
            -CachingMode Documents `
            -Description "User home folders"
    }
}
End {

}