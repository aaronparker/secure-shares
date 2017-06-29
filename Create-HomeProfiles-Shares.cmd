@ECHO OFF
REM Creating secure shared folders for home directories / redirected folders and profiles
REM Sample articles:
REM https://support.microsoft.com/en-us/help/274443/how-to-dynamically-create-security-enhanced-redirected-folders-by-using-folder-redirection-in-windows-2000-and-in-windows-server-2003
REM https://technet.microsoft.com/en-us/library/jj649078(v=ws.11).aspx

REM Create and share folders with permissions for home directories / redirected folders and profiles
md e:\Home
net share Home=e:\Home /GRANT:Users,CHANGE /GRANT:Administrators,FULL /CACHE:Automatic /REMARK:"User home folders"
icacls e:\Home /inheritance:d
icacls e:\Home /remove Users
icacls e:\Home /grant Users:(S,RD,AD,X,RA)

REM Create and share folders with permissions for profiles
md e:\Profiles
net share Profiles=e:\Profiles /GRANT:Users,CHANGE /GRANT:Administrators,FULL /CACHE:None /REMARK:"User profiles"
icacls e:\Profiles /inheritance:d
icacls e:\Profiles /remove Users
icacls e:\Profiles /grant Users:(S,RD,AD,X,RA)
