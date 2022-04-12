from lib.Windows.implemented_classes import *
from lib.audit_types import *


############## Global Variables
      
predefined_items = {
    "Account Lockout" : {
        "Account lockout duration" : TIME_VALUE,
        "Account lockout threshold" : POLICY_DWORD,
        "Enforce user logon restrictions" : POLICY_SET
    },
    "Audit Policy" : {
        "Audit account logon events" : AUDIT_SET,
        "Audit account management" : AUDIT_SET,
        "Audit directory service access" : AUDIT_SET,
        "Audit logon events" : AUDIT_SET,
        "Audit object access" : AUDIT_SET,
        "Audit policy change" : AUDIT_SET,
        "Audit privilege use" : AUDIT_SET,
        "Audit process tracking" : AUDIT_SET,
        "Audit system events" : AUDIT_SET
    },
    "Event Log" : {
        "Maximum application log size" : POLICY_KBYTE,
        "Maximum security log size" : POLICY_KBYTE,
        "Maximum system log size" : POLICY_KBYTE,
        "Prevent local guests group from accessing application log" : POLICY_SET,
        "Prevent local guests group from accessing security log" : POLICY_SET,
        "Prevent local guests group from accessing system log" : POLICY_SET,
        "Retain application log" : POLICY_DAY,
        "Retain system log" : POLICY_DAY,
        "Retention method for application log" : EVENT_MEATHOD,
        "Retention method for security log" : EVENT_MEATHOD,
        "Retention method for system log" : EVENT_MEATHOD
    },
    "Kerberos Policy" : {
        "Maximum lifetime for service ticket" : TIME_VALUE,
        "Maximum lifetime for user ticket" : TIME_VALUE,
        "Maximum lifetime for user renewal ticket" : TIME_VALUE,
        "Maximum tolerance for computer clock synchronization" : TIME_VALUE
    },
    "Password Policy" : {
        "Enforce password history": POLICY_DWORD,
        "Maximum password age" : TIME_VALUE,
        "Minimum password age" : TIME_VALUE,
        "Minimum password length" : POLICY_DWORD,
        "Password must meet complexity requirements" : POLICY_SET,
    },
    "Security Options" : {
        "Accounts: Administrator account status" : POLICY_SET,
        "Accounts: Guest account status" : POLICY_SET,
        "Accounts: Limit local account use of blank password to console logon only" : POLICY_SET,
        "Accounts: Rename administrator account" : POLICY_TEXT,
        "Accounts: Rename guest account" : POLICY_TEXT,
        "Audit: Audit the access of global system objects" : POLICY_SET,
        "Audit: Audit the use of Backup and Restore privilege" : POLICY_SET,
        "Audit: Shut down system immediately if unable to log security audits" : POLICY_SET,
        "DCOM: Machine Launch Restrictions in Security Descriptor Definition Language (SDDL) syntax" : POLICY_TEXT,
        "DCOM: Machine Access Restrictions in Security Descriptor Definition Language (SDDL) syntax" : POLICY_TEXT,
        "Devices: Allow undock without having to log on" : POLICY_SET,
        "Devices: Allowed to format and eject removable media" : DASD_SET,
        "Devices: Prevent users from installing printer drivers" : POLICY_SET,
        "Devices: Restrict CD-ROM access to locally logged-on user only" : POLICY_SET,
        "Devices: Restrict floppy access to locally logged-on user only" : POLICY_SET,
        "Devices: Unsigned driver installation behavior" : DRIVER_SET,
        "Domain controller: Allow server operators to schedule tasks" : POLICY_SET,
        "Domain controller: LDAP server signing requirements" : LDAP_SET,
        "Domain controller: Refuse machine account password changes" : POLICY_SET,
        "Domain member: Digitally encrypt or sign secure channel data (always)" : POLICY_SET,
        "Domain member: Digitally encrypt secure channel data (when possible)" : POLICY_SET,
        "Domain member: Digitally sign secure channel data (when possible)" : POLICY_SET,
        "Domain member: Disable machine account password changes" : POLICY_SET,
        "Domain member: Maximum machine account password age" : POLICY_DAY,
        "Domain member: Require strong (Windows 2000 or later) session key" : POLICY_SET,
        "Interactive logon: Display user information when the session is locked" : LOCKEDID_SET,
        "Interactive logon: Do not display last user name" : POLICY_SET,
        "Interactive logon: Do not require CTRL+ALT+DEL" : POLICY_SET,
        "Interactive logon: Message text for users attempting to log on" : POLICY_TEXT,
        "Interactive logon: Message title for users attempting to log on" : POLICY_TEXT,
        "Interactive logon: Number of previous log-ons to cache (in case domain controller is not available)" : POLICY_DWORD,
        "Interactive logon: Prompt user to change password before expiration" : POLICY_DWORD,
        "Interactive logon: Require Domain Controller authentication to unlock workstation" : POLICY_SET,
        "Interactive logon: Require smart card" : POLICY_SET,
        "Interactive logon: Smart card removal behavior" : SMARTCARD_SET,
        "Microsoft network client: Digitally sign communications (always)" : POLICY_SET,
        "Microsoft network client: Digitally sign communications (if server agrees)" : POLICY_SET,
        "Microsoft network client: Send unencrypted password to third-party SMB servers" : POLICY_SET,
        "Microsoft network server: Amount of idle time required before suspending session" : POLICY_DWORD,
        "Microsoft network server: Digitally sign communications (always)" : POLICY_SET,
        "Microsoft network server: Digitally sign communications (if client agrees)" : POLICY_SET,
        "Microsoft network server: Disconnect clients when logon hours expire" : POLICY_SET,
        "Network access: Allow anonymous SID/Name translation" : POLICY_SET,
        "Network access: Do not allow anonymous enumeration of SAM accounts" : POLICY_SET,
        "Network access: Do not allow anonymous enumeration of SAM accounts and shares" : POLICY_SET,
        "Network access: Do not allow storage of credentials or .NET Passports for network authentication" : POLICY_SET,
        "Network access: Let Everyone permissions apply to anonymous users" : POLICY_SET,
        "Network access: Named Pipes that can be accessed anonymously" : POLICY_MULTI_TEXT,
        "Network access: Remotely accessible registry paths and sub-paths" : POLICY_MULTI_TEXT,
        "Network access: Remotely accessible registry paths" : POLICY_MULTI_TEXT,
        "Network access: Restrict anonymous access to Named Pipes and Shares" : POLICY_SET,
        "Network access: Shares that can be accessed anonymously" : POLICY_MULTI_TEXT,
        "Network access: Sharing and security model for local accounts" : LOCALACCOUNT_SET,
        "Network security: Do not store LAN Manager hash value on next password change" : POLICY_SET,
        "Network security: Force log off when logon hours expire" : POLICY_SET, 
        "Network security: LAN Manager authentication level" : LANMAN_SET,
        "Network security: LDAP client signing requirements" : LDAPCLIENT_SET,
        "Network security: Minimum session security for NTLM SSP based (including secure RPC) clients" : NTLMSSP_SET,
        "Network security: Minimum session security for NTLM SSP based (including secure RPC) servers" : NTLMSSP_SET,
        "Recovery console: Allow automatic administrative logon" : POLICY_SET,
        "Recovery console: Allow floppy copy and access to all drives and all folders" : POLICY_SET,
        "Shutdown: Allow system to be shut down without having to log on" : POLICY_SET,
        "Shutdown: Clear virtual memory pagefile" : POLICY_SET,
        "System cryptography: Force strong key protection for user keys stored on the computer" : CRYPTO_SET,
        "System cryptography: Use FIPS compliant algorithms for encryption, hashing, and signing" : POLICY_SET,
        "System objects: Default owner for objects created by members of the Administrators group" : OBJECT_SET,
        "System objects: Require case insensitivity for non-Windows subsystems" : POLICY_SET,
        "System objects: Strengthen default permissions of internal system objects (e.g. Symbolic Links)" : POLICY_SET,
        "System settings: Optional subsystems" : POLICY_MULTI_TEXT,
        "System settings: Use Certificate Rules on Windows Executables for Software Restriction Policies" : POLICY_SET
    },
    "User Rights Assignments" : {
    },
    "Account Logon" : {},
    "Account Management" : {},
    "Detailed Tracking" : {},
    "Logon/Logoff" : {},
    "Object Access" : {},
    "Policy Change" : {},
    "Privilege Use" : {},
    "System" : {},
}

policy_paths = ("Account Lockout",
    "Audit Policy" ,
    "Event Log" ,
    "Kerberos Policy" ,
    "Password Policy" ,
    "Security Options" ,
    "User Rights Assignments" ,
    "Account Logon" ,
    "Account Management" ,
    "Detailed Tracking" ,
    "Logon/Logoff" ,
    "Object Access" ,
    "Policy Change" ,
    "Privilege Use" ,
    "System" ,
)

implemented_classes = {
    "Account Lockout" : {
        "Reset account lockout counter after" :(
            LOCKOUT_RESET,
            TIME_VALUE
        )
    },
    "Audit Policy" : {
    },
    "Event Log" : {
    },
    "Kerberos Policy" : {
    },
    "Password Policy" : {
        "Store passwords using reversible encryption":(
            REVERSIBLE_ENCRYPTION,
            POLICY_SET
        )
    },
    "Security Options" : {
        "Accounts: Limit local account use of blank passwords to console logon only":(
            BLANK_PASSWORD,
            POLICY_SET
        ),
        "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings":(
            AUDIT_FORCE_AUDIT,
            POLICY_SET
        ),
        "Interactive logon: Machine inactivity limit":(
            INACTIVE_MACHINE,
            POLICY_DWORD
        ),
        "Network access: Restrict clients allowed to make remote calls to SAM":(
            REMOTE_SAM_CALLS,
            POLICY_TEXT
        ),
        "Network security: Allow LocalSystem NULL session fallback":(
            NULL_SESSION,
            POLICY_SET
        ),
        "User Account Control: Admin Approval Mode for the Built-in Administrator account":(
            APPROVAL_MODE_FOR_BA,
            POLICY_SET
        ),
        "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode":(
            ELEVATION_PROMPT_ADMIN,
            ADMIN_PROMPT_SET
        ),
        "User Account Control: Behavior of the elevation prompt for standard users":(
            ELEVATION_PROMPT_SU,
            SU_PROMPT_SET
        ),
        "User Account Control: Detect application installations and prompt for elevation":(
            DETECT_INSTALL,
            POLICY_SET
        ),
        "User Account Control: Only elevate UIAccess applications that are installed in secure locations":(
            UIACCESS_ELEVATION,
            POLICY_SET
        ),
        "User Account Control: Run all administrators in Admin Approval Mode":(
            RUN_ADMINS_APROVAL,
            POLICY_SET
        ),
        "User Account Control: Virtualize file and registry write failures to per-user locations":(
            VIRT_FAILURES,
            POLICY_SET
        )
    },
    "User Rights Assignments" : {
    },
    "Account Logon" : {
        "Audit Credential Validation" : (
            CREDENTIAL_VALIDATION,
            AUDIT_SET
        )
    },
    "Account Management" : {
        "Audit Security Group Management" : (
            SECURITY_GROUP_MANAGMENT,
            AUDIT_SET
        ),
        "Audit User Account Management" : (
            USER_ACCOUNT_MANAGEMENT,
            AUDIT_SET
        )
    },
    "Detailed Tracking" : {
        "Audit PNP Activity" : (
            PNP_EVENTS,
            AUDIT_SET
        ),
        "Audit Process Creation" : (
            PROCESS_CREATION,
            AUDIT_SET
        )
    },
    "Logon/Logoff" : {
        "Audit Account Lockout" : (
            ACCOUNT_LOCKOUT,
            AUDIT_SET
        ),
        "Audit Group Membership": (
            GROUP_MEMBERSHIP,
            AUDIT_SET
        ),
        "Audit Logon" : (
            AUDIT_LOGON,
            AUDIT_SET
        ),
        "Audit Other Logon/Logoff Events" : (
            AUDIT_EVENTS,
            AUDIT_SET
        ),
        "Audit Special Logon" : (
            SPECIAL_LOGON,
            AUDIT_SET
        )
    },
    "Object Access" : {
        "Audit Detailed File Share" : (
            DETAILED_FILE_SHARE,
            AUDIT_SET
        ),
        "Audit File Share" : (
            FILE_SHARE,
            AUDIT_SET
        ),
        "Audit Other Object Access Events" : (
            OTHER_OBJECT_ACCESS,
            AUDIT_SET
        ),
        "Audit Removable Storage" : (
            REMOVABLE_MEDIA,
            AUDIT_SET
        )
    },
    "Policy Change" : {
        "Audit Audit Policy Change" : (
            POLICY_CHANGE,
            AUDIT_SET
        ),
        "Audit Authentication Policy Change" : (
            AUTHENTICATION_CHANGE,
            AUDIT_SET
        ),
        "Audit MPSSVC Rule-Level Policy Change" : (
            MPSSVC_CHANGE,
            AUDIT_SET
        ),
        "Audit Other Policy Change Events" : (
            OTHER_EVENTS,
            AUDIT_SET
        )
    },
    "Privilege Use" : {
        "Audit Sensitive Privilege Use" : (
            SENSITIVE_USE,
            AUDIT_SET
        )
    },
    "System" : {
        "Audit Other System Events" : (
            OTHER_SYSTEM_EVENTS,
            AUDIT_SET
        ),
        "Audit Security State Change" : (
            SECURITY_STATE_CHANGE,
            AUDIT_SET
        ),
        "Audit Security System Extension" : (
            SECURITY_SYSTEM_EXTENSION,
            AUDIT_SET
        ),
        "Audit System Integrity" : (
            SYSTEM_INTEGRITY,
            AUDIT_SET
        )
    },
}

