from lib.audit_types import VALUE_TYPE, AUDIT_SET, PolicyTypeError, POLICY_TEXT

############# Items

class Tag:
    def write(self) -> str:
        return "\n\t\t<tag/>"
    
    def __repr__(self) -> str:
        return self.write()


class item (Tag):
    
    def __init__(self, name: str, value: VALUE_TYPE):
        self.name = name
        self.value = value

    def write(self) -> str:
        return "\n\t\t<item>\n\t\t\tname: \"%s\"\n\t\t\tvalue: %s\n\t\t</item>" % (self.name, self.value)


class custom_item(Tag):
    type = ""
    def __init__(self,
    description: str,
    value_type: str,
    value_data: VALUE_TYPE,
    check_type: (str, None)=None):
        self.description = description
        self.value_type = value_type
        if isinstance(value_data, VALUE_TYPE):
            self.value_data = value_data
        else:
            raise PolicyTypeError(value_data, "value_data")
        self.check_type = check_type

    def enumerate_fields(self) -> tuple:
        fields =  ["type: %s" % self.type,"description: \"%s\"" % self.description, "value_type: %s" % self.value_type, "value_data: %s"% str(self.value_data)]
        if self.check_type is not None:
            fields.append("check_type: %s" % str(self.check_type))
        
        return tuple(fields)
    
    def write(self) -> str:
        out = "\n\t\t<custom_item>"
        for field in self.enumerate_fields():
            out += "\n\t\t\t"+field
        return out + "\n\t\t</custom_item>"


class PASSWORD_POLICY(custom_item):
    type = "PASSWORD_POLICY"

    def __init__(self,
    password_policy: str,
    description: str,
    value_type: str,
    value_data: VALUE_TYPE,
    check_type: (str,None)=None):
        if password_policy in ("ENFORCE_PASSWORD_HISTORY",
        "MAXIMUM_PASSWORD_AGE",
        "MINIMUM_PASSWORD_AGE",
        "MINIMUM_PASSWORD_LENGTH",
        "COMPLEXITY_REQUIREMENTS",
        "REVERSIBLE_ENCRYPTION",
        "FORCE_LOGOFF"):
            self.password_policy = password_policy
        else:
            raise PolicyTypeError(password_policy,"password_policy")
        
        super().__init__(description, 
        value_type, 
        value_data,
        check_type)

    def enumerate_fields(self) -> tuple:
        return super().enumerate_fields() + tuple(["password_policy: %s" % str(self.password_policy)])
        

class LOCKOUT_POLICY(custom_item):
    type = "LOCKOUT_POLICY"

    def __init__(self, 
    lockout_policy: str,
    description: str,
    value_type: str,
    value_data: VALUE_TYPE,
    check_type: str=None):
        if lockout_policy in ("LOCKOUT_DURATION",
        "LOCKOUT_THRESHOLD", 
        "LOCKOUT_RESET"):
            self.lockout_policy = lockout_policy
        else:
            raise PolicyTypeError(lockout_policy, "lockout_policy")
        
        super().__init__(description, 
        value_type, 
        value_data, 
        check_type)

    def enumerate_fields(self) -> tuple:
        return super().enumerate_fields() + tuple(["lockout_policy: "+self.lockout_policy])


class KERBEROS_POLICY(custom_item):
    type = "KERBEROS_POLICY"

    def __init__(self, 
    kerberos_policy: str, 
    description: str, 
    value_type: str, 
    value_data: VALUE_TYPE, 
    check_type: str =None):
        super().__init__(description, 
        value_type, 
        value_data, 
        check_type)

        if kerberos_policy in ("USER_LOGON_RESTRICTIONS",
        "SERVICE_TICKET_LIFETIME",
        "USER_TICKET_LIFETIME",
        "USER_TICKET_RENEWAL_LIFETIME",
        "CLOCK_SYNCHRONIZATION_TOLERANCE"):
            self.kerberos_policy = kerberos_policy
        else: 
            raise PolicyTypeError(kerberos_policy, "kerberos_policy")

    def enumerate_fields(self) -> tuple:
        return super().enumerate_fields() + tuple(["kerberos_policy: "+self.kerberos_policy])


class REGISTRY_SETTING(custom_item):
    type = "REGISTRY_SETTING"

    def __init__(self, 
    description:str, 
    value_type:str, 
    value_data:VALUE_TYPE,
    reg_key:str,
    reg_item:str,
    check_type:(str,None)=None,
    reg_option:(str,None)=None,
    reg_enum:(str,None)=None):
        super().__init__(description, value_type, value_data,check_type)
        self.reg_key = reg_key
        self.reg_item = reg_item
        self.reg_option = reg_option
        self.reg_enum = reg_enum

    def enumerate_fields(self) -> tuple:
        fields = ["type: %s" % self.type, "description: \"%s\"" % self.description,"value_type: %s" % self.value_type, "value_data: %s"% self.value_data,"reg_key: \"%s\"" % self.reg_key, "reg_item: \"%s\"" % self.reg_item]
        if self.check_type is not None:
            fields.append("check_type: %s" % self.check_type)
        if self.reg_option is not None:
            fields.append("reg_option: %s" % self.reg_option)
        if self.reg_enum is not None:
            fields.append("reg_enum: %s" % self.reg_enum)
        return tuple(fields)


class AUDIT_POLICY_SUBCATEGORY(custom_item):
    type = "AUDIT_POLICY_SUBCATEGORY"

    def __init__(self, description:str, value_type:str, value_data:AUDIT_SET, audit_policy_subcategory:str, check_type:(str,None) = None):
        super().__init__(description, value_type, value_data, check_type)
        if audit_policy_subcategory in ("Security State Change",
        "Security System Extension",
        "System Integrity",
        "IPsec Driver",
        "Group Membership",
        "Other System Events",
        "Logon",
        "Logoff",
        "Account Lockout",
        "IPsec Main Mode",
        "IPsec Quick Mode",
        "IPsec Extended Mode",
        "Special Logon",
        "Other Logon/Logoff Events",
        "Network Policy Server",
        "File System",
        "Registry",
        "Kernel Object",
        "SAM",
        "Certification Services",
        "Application Generated",
        "Handle Manipulation",
        "File Share",
        "Plug and Play Events",
        "Detailed File Share",
        "Filtering Platform Packet Drop",
        "Filtering Platform Connection",
        "Other Object Access Events",
        "Sensitive Privilege Use",
        "Non Sensitive Privilege Use",
        "Other Privilege Use Events",
        "Process Creation",
        "Process Termination",
        "DPAPI Activity",
        "RPCEvents",
        "Removable Storage",
        "Audit Policy Change",
        "Authentication Policy Change",
        "Authorization Policy Change",
        "MPSSVC Rule-Level Policy Change",
        "Filtering Platform Policy Change",
        "Other Policy Change Events",
        "User Account Management",
        "Computer Account Management",
        "Security Group Management",
        "Distribution Group Management",
        "Application Group Management",
        "Other Account Management Events",
        "Directory Service Access",
        "Directory Service Changes",
        "Directory Service Replication",
        "Detailed Directory Service Replication",
        "Credential Validation",
        "Kerberos Service Ticket Operations",
        "Other Account Logon Events"):
            self.audit_policy_subcategory = audit_policy_subcategory
        else: 
            raise PolicyTypeError( audit_policy_subcategory, "audit_policy_subcategory" )

    def enumerate_fields(self) -> tuple:
        return super().enumerate_fields() + tuple(["audit_policy_subcategory: \"%s\"" % self.audit_policy_subcategory])


class WMI_POLICY(custom_item):
    type = "WMI_POLICY"

    def __init__(self, description:str, value_type:str, value_data:POLICY_TEXT,wmi_namespace:str,wmi_request:str,wmi_attribute:str,wmi_keys:str,wmi_option = None,wmi_exclude_result= None,only_show_query_output=None,check_type=None):
        super().__init__(description, value_type, value_data,check_type)
        self.wmi_namespace = wmi_namespace
        self.wmi_request = wmi_request
        self.wmi_attribute = wmi_attribute
        self.wmi_keys = wmi_keys
        self.wmi_option = wmi_option
        self.wmi_exclude_result = wmi_exclude_result
        self.only_show_query_output = only_show_query_output

    def enumerate_fields(self)->tuple:
        fields = list(super().enumerate_fields())
        for k in self.__dict__:
            if self.__dict__[k] is not None:
                if "%s: %s" %(k, self.__dict__[k]) not in fields:
                    add = "%s: \"%s\"" % (k, self.__dict__[k])
                    if add not in fields:
                        fields.append(add)
        return tuple(fields)

