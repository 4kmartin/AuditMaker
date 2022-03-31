import re


class PolicyTypeError(Exception):

    def __init__(self, erronious_input:str,field:str):
        super().__init__("%s is not a valid input for %s" % ( erronious_input, field )) 



############## VALUE_TYPES

class VALUE_TYPE:

    def __init__(self, value):
        self.value = value

    def _validate(self, value:any) -> bool:
        return True

    def __repr__(self) -> str:
        return "%s" % str(self.value)


class DWORD(VALUE_TYPE):
    
    def __init__(self, value:int):
        if value == 'MIN':
            value = 0
        elif value == "MAX":
            value = 2147483647
        if self._validate(value):
            self.value = int(value)
        else: 
            raise TypeError("%s is not a valid value for DWORD" % str(value))

    def _validate(self, value:int) -> bool:
        if isinstance(value, int):
            return value < 2147483648
        
        elif isinstance(value, str):
            try:
                int(value)
            except ValueError:
                return False
            else:
                return int(value) < 2147483648
        else:
            return False
    
    def __repr__(self) -> str:
        return "%d" % self.value


class RANGE(VALUE_TYPE):

    def __init__(self, minimum_value: DWORD, maximum_value: DWORD):
        if self._validate(minimum_value, maximum_value):
            self.value = (minimum_value, maximum_value)
        else: 
            raise TypeError("%s is not a valid value for RANGE" % str((minimum_value, maximum_value)))

    def _validate(self, minimum_value: DWORD, maximum_value: DWORD):
        if isinstance(minimum_value, DWORD) and isinstance( maximum_value, DWORD):
            return minimum_value < maximum_value
        else:
            return False

    def __repr__(self) -> str:
        return "[%d..%d]" % self.value

        
class POLICY_SET(VALUE_TYPE):

    def __init__(self, value:str):

        if self._validate(value):
            self.value = value
        
        else:
            raise TypeError("%s is not a valid value for POLICY_SET" % str(value))

    def convert_to_DWORD(self) -> DWORD:
        return DWORD(("Disabled","Enabled").index(self.value))

    def _validate(self, value:str)->bool:
        return value in ("Enabled","Disabled")

    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class POLICY_DWORD(VALUE_TYPE):

    def __init__(self, value:(DWORD, RANGE)):
        if self._validate(value):
            self.value = value
        elif isinstance(value, convertable_type_list):
            self.value = value.convert_to_DWORD()
        else: 
            raise TypeError("%s is not a valid value for POLICY_DWORD" % str(value))

    def _validate(self, value: (DWORD, RANGE))->bool:
        return isinstance(value, (DWORD, RANGE)) 
    
    def __repr__(self) -> str:
        return "%s" % self.value


class POLICY_TEXT(VALUE_TYPE):

    def __init__(self, value:str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for POLICY_TEXT" % str(value))

    def _validate(self, value) -> bool:
        return isinstance(value, str)

    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class POLICY_MULTI_TEXT(VALUE_TYPE):

    def __init__(self,value:[POLICY_TEXT]):
        if self._validate(value):
            self.value = tuple(value)
        else:
            raise TypeError("%s is not a valid value for POLICY_MULTI_TEXT" % str(value))

    def _validate(self, value:[POLICY_TEXT]) -> bool:
        if not isinstance(value, (list, tuple)):
            return False

        for x in value:
            if not isinstance(x, POLICY_TEXT):
                return False
        
        return True

    def __repr__(self) -> str:
        return str(self.value).replace(", "," && ").replace("(","").replace(")","").replace("'","\"")


class TIME_VALUE(VALUE_TYPE):

    def __init__(self, value:int):
        if self._validate(value):
            self.value = int(value)
        
        else:
            raise TypeError("%s is not a valid value for TIME" % str(value))

    def _validate(self, value:int)->bool:
        if isinstance(value, int):
            return True
        elif isinstance(value, str):
            try:
                int(value)
            except ValueError:
                return False
            else:
                return True
        else:
            return False

    def __repr__(self) -> str:
        return "%d" % self.value


class AUDIT_SET(VALUE_TYPE):

    def __init__(self,value:str):
        if " and " in value:
            value = value.replace(" and", ",")
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for AUDIT_SET" % str(value))

    def _validate(self, value:str)->bool:
        return value in ("No auditing", "Success", "Failure", "Success, Failure") 

    def __repr__(self):
        return "\"%s\"" % self.value


class DRIVER_SET(VALUE_TYPE):
    def __init__(self, value: str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for DRIVER_SET" % str(value))

    def _validate(self, value: str) -> bool:
        return value in ("Silent Succeed", "Warn but allow installation", "Do not allow installation")
    
    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class LDAP_SET(VALUE_TYPE):

    def __init__(self, value: str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for LDAP_SET" % str(value))

    def _validate(self, value: str) -> bool:
        return value in ("None","Require Signing")
    
    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class LOCKEDID_SET(VALUE_TYPE):

    def __init__(self, value: str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for LOCKEDID_SET" % str(value))

    def _validate(self, value: str) -> bool:
        return value in ("user display name, domain and user names", "user display name only", "do not display user information")
    
    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class SMARTCARD_SET(VALUE_TYPE):
 
    def __init__(self, value: str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for SMARTCARD_SET" % str(value))

    def _validate(self, value: str) -> bool:
        return value in ("No action", "Lock Workstation", "Force logoff", "Disconnect if a remote terminal services session")
    
    def __repr__(self) -> str:
        return "\"%s\"" % self.value   


class LOCALACCOUNT_SET(VALUE_TYPE):

    def __init__(self, value: str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for LOCALACCOUNT_SET" % str(value))

    def _validate(self, value: str) -> bool:
        return value in ("Classic - local users authenticate as themselves", "Guest only - local users authenticate as guest")
    
    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class NTLMSSP_SET(VALUE_TYPE):
    def __init__(self, value: str):
        if "and" in value.split(" "):
            val1, val2 = tuple(map(lambda x: x.capitalize() ,value.lower().split(" and ")))
            if self._validate(val1) and self._validate(val2):
                self.value = "\"%s\" && \"%s\"" % (val1, val2)
            else:
                raise TypeError("%s is not a valid value for NTLMSSP_SET" % str(value))
        elif self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for NTLMSSP_SET" % str(value))

    def _validate(self, value: str) -> bool:
        return value in ("No minimum", "Require message integrity", "Require message confidentiality", "Require ntlmv2 session security", "Require 128-bit encryption")
    
    def __repr__(self) -> str:
        if " && " in self.value:
            return self.value
        else:
            return "\"%s\"" % self.value


class CRYPTO_SET(VALUE_TYPE):

    def __init__(self, value: str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for CRYPTO_SET" % str(value))

    def _validate(self, value: str) -> bool:
        return value in ("User input is not required when new keys are stored and used", "User is prompted when the key is first used", "User must enter a password each time they use a key")
    
    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class OBJECT_SET(VALUE_TYPE):
    
    def __init__(self, value: str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for OBJECT_SET" % str(value))

    def _validate(self, value: str) -> bool:
        return value in ("Administrators group", "Object creator")

    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class DASD_SET(VALUE_TYPE):

    def __init__(self, value: str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for DASD_SET" % str(value))

    def _validate(self, value: str) -> bool:
        return value in ("Administrators", "administrators and power users", "Administrators and interactive users")
    
    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class LANMAN_SET(VALUE_TYPE):

    def __init__(self, value: str):
        value = value.replace(". ", "\\").lower()
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for LANMAN_SET" % str(value))

    def _validate(self, value: str) -> bool:
        return value in ("Send LM & NTLM responses", "send lm & ntlm - use ntlmv2 session security if negotiated", "send ntlm response only", "send ntlmv2 response only", "send ntlmv2 response only\\refuse lm", "send ntlmv2 response only\\refuse lm & ntlm")
    
    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class LDAPCLIENT_SET(VALUE_TYPE):
    def __init__(self, value: str):
        value = value.title()
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for LDAPCLIENT_SET" % str(value))

    def _validate(self, value: str) -> bool:
        return value in ("None", "Negotiate Signing", "Require Signing")
    
    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class EVENT_MEATHOD(VALUE_TYPE):

    def __init__(self, value: str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for EVENT_MEATHOD" % str(value))

    def _validate(self, value: str) -> bool:
        return value in ("by days", "manually", "as needed")
    
    def __repr__(self) -> str:
        return "\"%s\"" % self.value    


class POLICY_DAY(POLICY_DWORD):

    def __init__(self, value:DWORD):
        super().__init__(value)


class POLICY_KBYTE(POLICY_DWORD):

    def __init__(self, value:DWORD):
        super().__init__(value)


class ADMIN_PROMPT_SET(VALUE_TYPE):
    
    def __init__(self, value: str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for PROMPT_POLICY_SET" % str(value))

    def convert_to_DWORD(self) -> DWORD:
        return DWORD(("Elevate without prompting", "Prompt for credentials on the secure desktop", "Prompt for consent on the secure desktop", "Prompt for credentials", "Prompt for consent", "Prompt for consent for non-Windows binaries").index(self.value))

    def _validate(self, value: str) -> bool:
        return value in ("Elevate without prompting", "Prompt for credentials on the secure desktop", "Prompt for consent on the secure desktop", "Prompt for credentials", "Prompt for consent", "Prompt for consent for non-Windows binaries")
    
    def __repr__(self) -> str:
        return "\"%s\"" % self.value   


class SU_PROMPT_SET(VALUE_TYPE):

    def __init__(self, value: str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for PROMPT_POLICY_SET" % str(value))

    def convert_to_DWORD(self) -> DWORD:
        return DWORD(("Automatically deny elevation requests", "Prompt for credentials on the secure desktop", "Prompt for credentials").index(self.value))

    def _validate(self, value: str) -> bool:
        return value in ("Automatically deny elevation requests", "Prompt for credentials on the secure desktop", "Prompt for credentials")

    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class INTERNET_ZONE_SET(VALUE_TYPE):

    def __init__(self, value:str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for INTERNET_ZONE_SET" % str(value))

    def convert_to_DWORD(self) -> DWORD:
        return DWORD(("Enable", "Disable", "Prompt").index(self.value))
    
    def _validate(self, value:str) -> bool:
        return value in ("Enable", "Disable", "Prompt")

    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class JAVA_PERMISSIONS_SET(VALUE_TYPE):

    def __init__(self, value:str):
        value = value.title()
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for JAVA_PERMISSIONS_SET" % str(value))

    def convert_to_DWORD(self) -> DWORD:
        return DWORD({"High Safety" : 65536, 
        "Medium Safety" : 131072, 
        "Low Safety" : 196608, 
        "Custom" : 8388608, 
        "Disable Java" : 0}[self.value])

    def _validate(self, value:str) -> bool:
        return value in ("High Safety", "Medium Safety", "Low Safety", "Custom", "Disable Java")

    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class DMA_SET(VALUE_TYPE):

    def __init__(self, value:str):
        value = value.capitalize()
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for DMA_SET" % str(value))

    def convert_to_DWORD(self) -> DWORD:
        return DWORD(("Block all", "Only while logged in", "Allow all").index(self.value))
    
    def _validate(self, value:str) -> bool:
        return value in ("Block all", "Only while logged in", "Allow all")

    def __repr__(self) -> str:
        return "\"%s\"" % self.value


class SSL_FALLBACK(VALUE_TYPE):

    def __init__(self, value:str):
        value = value.title()
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for SSL_FALLBACK" % str(value))
    
    def convert_to_DWORD(self) -> DWORD:
        return DWORD(("No Sites", "Non-Protected Mode Sites", "All Sites").index(self.value))

    def _validate(self, value) -> bool:
        return value in ("No Sites", "Non-Protected Mode Sites", "All Sites")
    
    def __repr__(self) ->str:
        return "\"%s\"" % self.value


class DEFENDER_SET(VALUE_TYPE):

    def __init__(self, value:str):
        value = value.title()
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for DEFENDER_SET" % str(value))

    def convert_to_DWORD(self) -> DWORD:
        return DWORD(("Disable (Default)","Block", "Audit Mode").index(self.value))

    def _validate(self, value:str) -> bool:
        return value in ("Disable (Default)","Block", "Audit Mode")

    def __repr__(self)->str:
        return "\"%s\"" % self.value


class SMB_DRIVER(VALUE_TYPE):

    def __init__(self, value:str):
        value = value.capitalize()
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for SMB_DRIVER" % str(value))

    def convert_to_DWORD(self) -> DWORD:
        return DWORD({"Disable driver":4,
        "Manual start":3, 
        "Automatic start":2}[self.value])

    def _validate(self, value:str) -> bool:
        return value in ("Disable driver","Manual start", "Automatic start")

    def __repr__(self)->str:
        return "\"%s\"" % self.value


class ORACLE_REMEDIATION(VALUE_TYPE):

    def __init__(self, value:str):
        value = value.title()
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for ORACLE_REMEDIATION" % str(value))

    def convert_to_DWORD(self) -> DWORD:
        return DWORD(("Force Updated Clients","Mitigated","Vulnerable").index(self.value))

    def _validate(self, value: str) -> bool:
        return value in ("Force Updated Clients","Mitigated","Vulnerable")
    
    def __repr__(self)->str:
        return "\"%s\"" % self.value


class JOIN_MAPS(VALUE_TYPE):

    def __init__(self, value:str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for JOIN_MAPS" % str(value))

    def convert_to_DWORD(self) -> DWORD:
        return DWORD(("Disabled", "Basic MAPS", "Advanced MAPS").index(self.value))

    def _validate(self, value: str) -> bool:
        return value in ("Disabled", "Basic MAPS", "Advanced MAPS")
    
    def __repr__(self)->str:
        return "\"%s\"" % self.value


class SERVICE_SET(VALUE_TYPE):
    value_type = "SERVICE_SET"

    def __init__(self, value:str):
        if self._validate(value):
            self.value = value
        else:
            raise TypeError("%s is not a valid value for SERVICE_SET" % str(value))
    
    def convert_to_DWORD(self) -> DWORD:
        return DWORD(("Automatic", "Manual", "Disabled").index(self.value))

    def _validate(self, value) -> bool:
        return value in ("Automatic", "Manual", "Disabled")

    def __repr__(self) -> str:
        return "\"%s\"" % self.value



convertable_type_list = (
    DWORD,
    POLICY_SET,
    ADMIN_PROMPT_SET,
    SU_PROMPT_SET,
    INTERNET_ZONE_SET,
    JAVA_PERMISSIONS_SET,
    DMA_SET,
    SSL_FALLBACK,
    DEFENDER_SET,
    SMB_DRIVER,
    ORACLE_REMEDIATION,
    JOIN_MAPS
)