from lib.audit_tags import custom_item, REPORT_TAG



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
    if a.validate():
        return a
    else:
        raise TypeError("The following item tag is invalid: %s" %str(a))

def make_report(kwargs:dict) -> REPORT_TAG:
    a = REPORT_TAG(**kwargs)
    a.__dict__ = kwargs
    return a
