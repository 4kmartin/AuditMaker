from lib.audit_tags import Tag, REGISTRY_SETTING, WMI_POLICY
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

def write_audit_file_contents(list_of_items:[Tag]) -> str:
    contents = "<check_type: \"Windows\" version:\"2\">\n\t<group_policy: \"Audit file for Windows 10\">"
    for item in list_of_items:
        if isinstance(item, Tag):
            contents += item.write().replace("\n", "\n\t")
        else:
            continue
    return contents + "\n\t</group_policy>\n</check_type>"

def make_registry_item(description:str, value: (POLICY_DWORD, POLICY_TEXT), reg_key:str, reg_item: str) -> REGISTRY_SETTING:
    if isinstance(value, POLICY_DWORD):
        return REGISTRY_SETTING(description, "POLICY_DWORD", value, reg_key, reg_item)
    else:
        return REGISTRY_SETTING(description, "POLICY_TEXT", value, reg_key, reg_item)

