@echo off

REM Create and share folders with permissions for home directories / redirected folders and profiles
md e:\Home
net share Home=e:\Home /GRANT:Everyone,FULL
icacls e:\Home /grant Users:(S,RD,AD,X,RA)
icacls e:\Home /inheritance:d
icacls e:\Home /remove Users
icacls e:\Home /grant Users:(S,RD,AD,X,RA)

md e:\Profiles
net share Profiles=e:\Profiles /GRANT:Everyone,FULL /CACHE:None
icacls e:\Profiles /inheritance:d
icacls e:\Profiles /remove Users
icacls e:\Profiles /grant Users:(S,RD,AD,X,RA)