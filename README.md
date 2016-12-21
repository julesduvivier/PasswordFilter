# PasswordFilter

## Introduction

[PasswordFilterService](https://github.com/julesduvivier/PasswordFilterService) is a password policy enforcement tool for Windows Active Directory.

Windows has a basic password complexity rule but no good controls to enforce the use of reasonable passwords. 
This basic policy accepts many weak password like `Password1` or `Company2017`

PasswordFilterService checks new passwords for compliance with your custom password policy and rejects non-compliant passwords.

## How it works

The password filter DLL is coded in C and loaded by LSASS on boot and will be queried every time a users try to change his password. See the MSDN for more information : 
https://msdn.microsoft.com/fr-fr/library/windows/desktop/ms721882(v=vs.85).aspx 

LSA checks the Windows Domain Password Policy, if the password meets domain rules, then it calls the password filter.
The password filter tells LSA if password is acceptable and if so the password change is accepted

A password filter respond to 3 functions from the LSA :

*InitializeChangeNotify(void);*

*PasswordFilter(AccountName,FullName,Password,SetOperation);*

*PasswordChangeNotify(Username,RelativeId,NewPassword);*

Every time a password change reaches the DC, LSA calls the `PasswordFilter()` function. If the `PasswordFilter()` returns 
`True` the new password is comitted to the Active Directory Database and then the LSA will call the `PasswordChangeNotify()` 
function for all DLLs listed on the registry's Notification Packages Key

The DLL is only loaded during the boot cycle (that's why you need to reboot your DC when you first start using your password policy).

On boot the system reads the `HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa\Notification Packages` registry key and loads all DLLs listed there.
