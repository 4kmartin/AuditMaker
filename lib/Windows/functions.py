from lib.audit_types import POLICY_DWORD, POLICY_TEXT
from lib.Windows.custom_item_types import REGISTRY_SETTING

def make_registry_item(description:str, value: (POLICY_DWORD, POLICY_TEXT), reg_key:str, reg_item: str) -> REGISTRY_SETTING:
    if isinstance(value, POLICY_DWORD):
        return REGISTRY_SETTING(description, "POLICY_DWORD", value, reg_key, reg_item)
    else:
        return REGISTRY_SETTING(description, "POLICY_TEXT", POLICY_TEXT(value), reg_key, reg_item)
