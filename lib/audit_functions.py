from lib.audit_tags import custom_item, REPORT_TAG
from lib.variables import custom_item_type_lookup, value_type_lookup
from lib.audit_types import PolicyTypeError



def getfilecontents(path_to_file:str)->str:
    openfile = open(path_to_file,"r")
    contents = openfile.read()
    openfile.close()
    return contents

def savefile(path_to_file:str,data_to_save:str):
    openfile= open(path_to_file,"w")
    openfile.write(data_to_save)
    openfile.close()

def make_custom_item(kwargs:dict) -> custom_item:
    a = custom_item("description", None, None)
    for k in kwargs:
        a.__dict__[k] = kwargs[k]

    if a.value_data is not None:
        pass
    if _validate(a):
        return a
    else:
        raise TypeError("The following item tag is invalid: %s" %str(a))

def make_report(kwargs:dict) -> REPORT_TAG:
    a = REPORT_TAG(**kwargs)
    a.__dict__ = kwargs
    return a

def _validate(item:custom_item) -> bool :
    if item.type in custom_item_type_lookup.keys():
        if item.value_type in value_type_lookup.keys():
            try:
                a = value_type_lookup[item.value_type](item.value_data)
            except PolicyTypeError:
                return False
            else:
                return True
        else:
            return False
    else:
        return False

if __name__ == '__main__':
    kwargs = {
        "type"			: "SERVICE_POLICY",
        "description"		: "Manage Engine Agent Running",
        "value_type"		: "SERVICE_SET",
        "value_data"		: "Automatic",
        "svc_option"		: "CAN_NOT_BE_NULL",
        "service_name"	: "ManageEngine Desktop Central - Agent",
    }
    a = make_custom_item(kwargs)
    if a.validate():
        print(a)