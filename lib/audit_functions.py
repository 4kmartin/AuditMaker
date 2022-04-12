from lib.audit_tags import Tag
from lib.Windows.custom_item_types import  REGISTRY_SETTING, WMI_POLICY
from lib.audit_types import POLICY_DWORD, POLICY_TEXT

def getfilecontents(path_to_file:str)->str:
    openfile = open(path_to_file,"r")
    contents = openfile.read()
    openfile.close()
    return contents

def savefile(path_to_file:str,data_to_save:str):
    openfile= open(path_to_file,"w")
    openfile.write(data_to_save)
    openfile.close()

def make_registry_item(description:str, value: (POLICY_DWORD, POLICY_TEXT), reg_key:str, reg_item: str) -> REGISTRY_SETTING:
    if isinstance(value, POLICY_DWORD):
        return REGISTRY_SETTING(description, "POLICY_DWORD", value, reg_key, reg_item)
    else:
        return REGISTRY_SETTING(description, "POLICY_TEXT", value, reg_key, reg_item)

