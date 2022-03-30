from lib import *

def main():
    pass

def make_wmi_query(description, value_type, value_data, wmi_namespace,set_option =True, wmi_attribute=None, wmi_key= None,wmi_request = None, only_show_query_output = None)->WMI_POLICY:
    if wmi_request is None:
        wmi_request = input("Please specicfy your WMI query here (note: wildcards are not allowed)\n.> ")
    if wmi_attribute is None and set_option:
        wmi_attribute = input("Attribute:\n.> ")
    if wmi_key is None and set_option:
        wmi_key = input("Key:\n.> ")
    return WMI_POLICY(description, value_type, POLICY_TEXT(value_data), wmi_namespace, wmi_request, wmi_attribute=wmi_attribute, wmi_key=wmi_key, only_show_query_output=only_show_query_output)
    
def make_registry_query(description:str, value: (POLICY_DWORD, POLICY_TEXT), reg_key:str, reg_item: str) -> REGISTRY_SETTING:
    if isinstance(value, POLICY_DWORD):
        return REGISTRY_SETTING(description, "POLICY_DWORD", value, reg_key, reg_item)
    else:
        return REGISTRY_SETTING(description, "POLICY_TEXT", value, reg_key, reg_item)

def make_policy_query()->Tag:
    pass

def write_audit_file_contents(list_of_items:[Tag]) -> str:
    contents = "<check_type: \"Windows\" version:\"2\">\n\t<group_policy: \"Audit file for Windows 10\">"
    for item in list_of_items:
        if issubclass(item.__class__, Tag):
            contents += item.write()
        else:
            continue
    return contents + "\n\t</group_policy>\n</check_type>"


if __name__ == "__main__":
    description = "test: %s"
    value_type = "POLICY_TEXT"
    value_data = ""
    wmi_namespace = "root\SecurityCenter2"
    wmi_request="SELECT displayName, productState, timestamp FROM %s"

    test = []
    test.append(make_wmi_query(description % "AntiVirusProduct", value_type, value_data, wmi_namespace,False,wmi_request=wmi_request % "AntiVirusProduct",only_show_query_output="YES"))
    test.append(make_wmi_query(description % "AntiSpywareProduct", value_type, value_data, wmi_namespace,False,wmi_request= wmi_request % "AntiSpywareProduct",only_show_query_output="YES"))
    test.append(make_wmi_query(description % "FirewallProduct", value_type, value_data, wmi_namespace,False,wmi_request=wmi_request % "FirewallProduct", only_show_query_output="YES"))
    
    wmi_namespace = "root\Microsoft\SecurityClient"
    wmi_request = "SELECT %s FROM AntimalwareHealthStatus"

    test.append(make_wmi_query(description % "AntispywareEnabled", value_type, value_data, wmi_namespace,False,wmi_request=wmi_request % "AntispywareEnabled", only_show_query_output="YES"))
    test.append(make_wmi_query(description % "AntispywareSignatureAge", value_type, value_data, wmi_namespace,False,wmi_request=wmi_request % "AntispywareSignatureAge", only_show_query_output="YES"))
    test.append(make_wmi_query(description % "AntivirusEnabled", value_type, value_data, wmi_namespace,False,wmi_request=wmi_request % "AntivirusEnabled", only_show_query_output="YES"))
    test.append(make_wmi_query(description % "AntivirusSignatureAge", value_type, value_data, wmi_namespace,False,wmi_request=wmi_request % "AntivirusSignatureAge", only_show_query_output="YES"))
    test.append(make_wmi_query(description % "LastFullScanAge" ,value_type,value_data,wmi_namespace,False,wmi_request=wmi_request % "LastFullScanAge",only_show_query_output="YES"))
    test.append(make_registry_query(description % "Windows Version", "21H1", "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion", "DisplayVersion"))

    contents = write_audit_file_contents(test)
    f = open("testbaseline.audit","w")
    f.write(contents)
    f.close()
    print(contents)