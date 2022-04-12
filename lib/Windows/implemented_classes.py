from lib.Windows.custom_item_types import PASSWORD_POLICY, REGISTRY_SETTING, AUDIT_POLICY_SUBCATEGORY, item, LOCKOUT_POLICY
from lib.audit_types import POLICY_SET, POLICY_DWORD, POLICY_TEXT, AUDIT_SET

############## Implemetations

class REVERSIBLE_ENCRYPTION(PASSWORD_POLICY):
    password_policy = "REVERSIBLE_ENCRYPTION"
    description = "Store passwords using reversible encryption"
    value_type = "POLICY_SET"

    def __init__(self, value_data:POLICY_SET):
        super().__init__(self.password_policy, self.description, self.value_type, value_data)


class AUDIT_FORCE_AUDIT(REGISTRY_SETTING):
    type = "REGISTRY_SETTING"
    description = "Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings"
    value_type = "POLICY_DWORD"
    reg_key =  "HKLM\System\CurrentControlSet\Control\Lsa"
    reg_item =  "SCENoApplyLegacyAuditPolicy"

    def __init__(self, value_data:POLICY_SET):
        super().__init__(self.description, self.value_type, POLICY_DWORD(value_data), self.reg_key, self.reg_item)


class INACTIVE_MACHINE(REGISTRY_SETTING):
    type = "REGISTRY_SETTING"
    description = "Interactive logon: Machine inactivity limit"
    value_type = "POLICY_DWORD"
    reg_key =  "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    reg_item =  "InactivityTimeoutSecs"

    def __init__(self, value_data:POLICY_DWORD):
        super().__init__(self.description, self.value_type, value_data, self.reg_key, self.reg_item)


class REMOTE_SAM_CALLS(REGISTRY_SETTING):
    type = "REGISTRY_SETTING"
    description = "Network access: Restrict clients allowed to make remote calls to SAM"
    value_type = "POLICY_TEXT"
    reg_key = "HKLMM\System\CurrentControlSet\Control\Lsa"
    reg_item = "RestrictRemoteSAM"

    def __init__(self, value_data:POLICY_TEXT):
        super().__init__(self.description, self.value_type, value_data, self.reg_key, self.reg_item)


class NULL_SESSION(REGISTRY_SETTING):
    type = "REGISTRY_SETTING"
    description = "Network security: Allow LocalSystem NULL session fallback"
    value_type = "POLICY_DWORD"
    reg_key = "HKLM\System\CurrentControlSet\Control\Lsa\MSV1_0"
    reg_item = "allownullsessionfallback"

    def __init__(self, value_data:POLICY_SET):
        super().__init__(self.description, self.value_type, POLICY_DWORD(value_data), self.reg_key, self.reg_item)


class APPROVAL_MODE_FOR_BA(REGISTRY_SETTING):
    description = "User Account Control: Admin Approval Mode for the Built-in Administrator account"
    value_type = "POLICY_DWORD"
    reg_key = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    reg_item = "FilterAdministratorToken"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, POLICY_DWORD(value_data), self.reg_key, self.reg_item, reg_option="CAN_NOT_BE_NULL")


class ELEVATION_PROMPT_ADMIN(REGISTRY_SETTING):
    description  = "User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode"
    value_type = "POLICY_DWORD"
    reg_key = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    reg_item = "ConsentPromptBehaviorAdmin"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, POLICY_DWORD(value_data), self.reg_key, self.reg_item)


class ELEVATION_PROMPT_SU(REGISTRY_SETTING):
    description = "User Account Control: Behavior of the elevation prompt for standard users"
    value_type = "POLICY_DWORD"
    reg_key = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    reg_item = "ConsentPromptBehaviorUser"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, POLICY_DWORD(value_data), self.reg_key, self.reg_item)


class DETECT_INSTALL(REGISTRY_SETTING):
    description = "User Account Control: Detect application installations and prompt for elevation"
    value_type = "POLICY_DWORD"
    reg_key = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    reg_item = "EnableInstallerDetection"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, POLICY_DWORD(value_data), self.reg_key, self.reg_item)


class UIACCESS_ELEVATION(REGISTRY_SETTING):
    description = "User Account Control: Only elevate UIAccess applications that are installed in secure locations"
    value_type = "POLICY_DWORD"
    reg_key = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    reg_item = "EnableSecureUIAPaths"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, POLICY_DWORD(value_data), self.reg_key, self.reg_item)


class RUN_ADMINS_APROVAL(REGISTRY_SETTING):
    description = "User Account Control: Run all administrators in Admin Approval Mode"
    value_type = "POLICY_DWORD"
    reg_key = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    reg_item = "EnableLUA"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, POLICY_DWORD(value_data), self.reg_key, self.reg_item)


class VIRT_FAILURES(REGISTRY_SETTING):
    description = "User Account Control: Virtualize file and registry write failures to per-user locations"
    value_type = "POLICY_DWORD"
    reg_key = "HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\System"
    reg_item = "EnableVirtualization"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, POLICY_DWORD(value_data), self.reg_key, self.reg_item)


class LOCKOUT_RESET(LOCKOUT_POLICY):
    lockout_policy = "LOCKOUT_RESET"
    description = "Reset lockout account counter after"
    value_type = "TIME_MINUTE"

    def __init__(self, value_data):
        super().__init__(self.lockout_policy, self.description, self.value_type, value_data)


class BLANK_PASSWORD(item):
    name = "Accounts: Limit local account use of blank password to console logon only"

    def __init__(self, value:POLICY_SET):
        super().__init__(self.name, value)


class CREDENTIAL_VALIDATION(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Credential Validation"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Credential Validation"

    def __init__(self, value_data:AUDIT_SET):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class SECURITY_GROUP_MANAGMENT(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Security Group Management"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Security Group Management"

    def __init__(self, value_data:AUDIT_SET):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class USER_ACCOUNT_MANAGEMENT(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit User Account Management"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "User Account Management"

    def __init__(self, value_data:AUDIT_SET):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class PNP_EVENTS(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit PNP Activity"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Plug and Play Events"

    def __init__(self, value_data: AUDIT_SET):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)
    

class PROCESS_CREATION(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Process Creation"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Process Creation"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class ACCOUNT_LOCKOUT(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Account Lockout"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Account Lockout"

    def __init__(self, value_data:AUDIT_SET):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class GROUP_MEMBERSHIP(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Group Membership"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Group Membership"

    def __init__(self, value_data: AUDIT_SET):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class AUDIT_LOGON(AUDIT_POLICY_SUBCATEGORY):
    description =  "Audit Logon"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Logon"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class AUDIT_EVENTS(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Other Logon/Logoff Events"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Other Logon/Logoff Events"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)
    

class SPECIAL_LOGON(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Special Logon"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Special Logon"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class DETAILED_FILE_SHARE(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Detailed File Share"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Detailed File Share"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class FILE_SHARE(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit File Share"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "File Share"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class OTHER_OBJECT_ACCESS(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Other Object Access Events"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Other Object Access Events"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class REMOVABLE_MEDIA(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Removable Storage"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Removable Storage"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class POLICY_CHANGE(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Audit Policy Change"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Audit Policy Change"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class AUTHENTICATION_CHANGE(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Authentication Policy Change"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Authentication Policy Change"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class MPSSVC_CHANGE(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit MPSSVC Rule-Level Policy Change"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "MPSSVC Rule-Level Policy Change"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class OTHER_EVENTS(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Other Policy Change Events"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Other Policy Change Events"

    def __init__(self, value_data):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class SENSITIVE_USE(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Sensitive Privilege Use"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Special Logon"

    def __init__(self, value_data:AUDIT_SET):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class OTHER_SYSTEM_EVENTS(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Other System Events"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Other System Events"

    def __init__(self, value_data:AUDIT_SET):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class SECURITY_STATE_CHANGE(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Security State Change"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Security State Change"

    def __init__(self, value_data:AUDIT_SET):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class SECURITY_SYSTEM_EXTENSION(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit Security System Extension"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "Security System Extension"

    def __init__(self, value_data:AUDIT_SET):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)


class SYSTEM_INTEGRITY(AUDIT_POLICY_SUBCATEGORY):
    description = "Audit System Integrity"
    value_type = "AUDIT_SET"
    audit_policy_subcategory = "System Integrity"

    def __init__(self, value_data:AUDIT_SET):
        super().__init__(self.description, self.value_type, value_data, self.audit_policy_subcategory)