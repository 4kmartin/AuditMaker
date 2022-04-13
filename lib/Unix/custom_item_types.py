from lib.audit_tags import custom_item
from lib.audit_types import VALUE_TYPE, POLICY_TEXT



class CHKCONFIG(custom_item):
    """Only works on RedHat systems or derivatives such as Fedora:
            Anthany's note:
            it is unclear from the Documentation if this includes CentOS and the Various Forks of it. 
            (i.e. Rocky Linux, Alma Linux, etc) 
            also the Documentation is unclear as to the structure of this type so this is based soley on
            what I've been able to infer"""

    def __init__(self, description:str, service:str, levels:str, status:str, check_type:str = None, check_option:str = None, system:str = None):
        self.system = system
        self.type = "CHKCONFIG"
        super().__init__(description, None, None, check_type)
        self.service = POLICY_TEXT(service)
        self.levels = POLICY_TEXT(levels)
        self.status = status


class CMD_EXEC(custom_item):

    def __init__(self, description, cmd:str, expect:str, timeout: int = None, dont_echo_cmd:str = None, check_type:str = None, system:str = None):
        self.system = system
        self.type = "CMD_EXEC"
        super().__init__(description, None, None, check_type)
        self.cmd = POLICY_TEXT(cmd)
        self.timeout = POLICY_TEXT(str(timeout))
        self.expect = POLICY_TEXT(expect)
        self.dont_echo_cmd = dont_echo_cmd
        
