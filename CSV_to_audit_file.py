from lib import *
import re



class FormatingError(Exception):
    """This error is raised in the event that the CSV file is improperly formatted"""

    def __init__(self, trace_back: tuple, reason:str):
        self.trace = "Col: %d, Row: %d" % trace_back
        self.reason = reason
        super().__init__("The Supplied CSV file is not formatted as Expected\nError Location: [%s]\nReason: %s" % (self.trace, self.reason))



def main(args:list):
    help = """ 
    Sytax: python auditmaker.py -csv [path to csv file]

    This function will take a CSV file and generat an audit file based on the contents of the csv file

    Note:
    the csv file can befound on microsoft's website in the same zip file containing the 
    Microsoft Security Compliance Toolkit (MSCT). If a cell in this sheet contains multiple lines, 
    replace the newline character (ctrl+j) with a semi-colon ';'.
    """
    try:
        if args[1] in ('-h','--help'):
            print(help)
        else:
            path_to_file = args[1]
            csv = getfilecontents(path_to_file).replace("\"", "")
            contents = CHECK_TYPE("Windows\" version:\"2", GROUP_POLICY("Audit file for Windows", BODY(parse_file(csv))))
            savefile(path_to_file.replace("csv", "audit").replace("CSV", "audit"),contents.write())
    except (FileNotFoundError, PermissionError):
        print("%s: is not a valid file path" % path_to_csv_file )
        print("if the file exists make sure you have permission to read it")
        quit()
    except FormatingError as fe:
        print(fe)
        quit()
    except IndexError:
        print(help)
        quit()
    
def parse_file(csv_file_contents:str) -> [Tag]:
    rows = csv_file_contents.split("\n")
    try:
        check_headers(rows[0].split(","))
    except IndexError:
        raise FormatingError((0,0), "The CSV File is empty")
    items = []
    notImplemented = []
    for row_number in range(1,len(rows)-1):
        cells = rows[row_number].split(",")
        if cells[0] in policy_paths:
            """newitem = make_item(cells[0:3])
            items.append(newitem)"""
            try:
                items.append(make_item(cells))
            except (TypeError, PolicyTypeError) as te:
                notImplemented.append( "\n%s::%s\nReason: %s" % (cells[0], cells[1], te))
        else:
            try:
                items.append(make_undefined_item(cells))
            except (TypeError, PolicyTypeError) as te:
                notImplemented.append( "\n%s::%s\nReason: %s" % (cells[0], cells[1], te))
    print("these (%d of %d) Items were not implemented" % (len(notImplemented), len(rows)))
    for i in notImplemented:
        print(i)
    return items
        
def make_item(item_description:[str]) -> Tag: 
    if item_description[0] == "":
        raise TypeError("Blank Line")
    elif item_description[1] in predefined_items[item_description[0]].keys():
        return make_predefined_item(item_description[0:3])
    elif item_description[1] in implemented_classes[item_description[0]].keys():
        return make_custom_item(item_description)
    else:
        return make_undefined_item(item_description)

def make_predefined_item(item_description:[str]) -> item:
    if predefined_items[item_description[0]][item_description[1]] in (POLICY_DWORD,POLICY_DAY,POLICY_KBYTE):
        dword = re.compile("^\\d+$")
        rng = re.compile("^\\[\\d+..\\d+\\]$")
        if dword.match(item_description[2]):
            return item(item_description[1], predefined_items[item_description[0]][item_description[1]](DWORD(item_description[2])))
        elif rng.match(item_description[2]):
            vals = item_description[2].replace("[", "").replace("]", "").split("..")
            value = predefined_items[item_description[0]][item_description[1]](RANGE(*vals))
            return item(item_description[1], value)
        else:
            raise TypeError("%s is not a valid value" % item_description[2])
    else:
        return item(item_description[1],predefined_items[item_description[0]][item_description[1]](item_description[2]))

def make_custom_item(item_description:[str]) -> custom_item:
    custom_item = implemented_classes[item_description[0]][item_description[1]][0]
    val_type = implemented_classes[item_description[0]][item_description[1]][1]
    if val_type in (POLICY_DWORD,POLICY_DAY,POLICY_KBYTE):
        dword = re.compile("^\\d+$")
        rng = re.compile("^\\[\\d+..\\d+\\]$")
        if dword.match(item_description[2]):
            return custom_item(val_type(DWORD(item_description[2])))
        elif rng.match(item_description[2]):
            vals = item_description[2].replace("[", "").replace("]", "").split("..")
            return custom_item(val_type(RANGE(*vals)))
        else:
            raise TypeError("%s is not a valid value" % str(item_description))
    else:
        return custom_item(val_type(item_description[2]))

def make_undefined_item(item_description:[str]) -> custom_item:
    value = None
    for _type in convertable_type_list:
        try:
            val = _type(item_description[2])
        except TypeError:
            continue
        except IndexError:
            raise FormatingError((3,00), "this value does not match the expected value: %s" % item_description)
        else:
            value = POLICY_DWORD(val)
            break
    if value is None:
        value = POLICY_TEXT(item_description[2])
    try:
        registry = [item_description[1], value] + item_description[3].split("!")
        assert isinstance(value, (POLICY_DWORD, POLICY_TEXT))
        assert len(registry) == 4
    except (IndexError, AssertionError):
        raise TypeError("%s::%s is not yet implemented" % (item_description[0], item_description[1]))
    else:
        return make_registry_item(*registry)

def check_headers(header_row:[str]):
    if header_row == "":
        raise FormatingError((0,1),"The Header Row of the CSV File is Empty" )
    expected_headers = (
        "Policy Path",
        "Policy Setting Name",
        "Windows 10"
    )
    for column_number in range(len(expected_headers)):
        if header_row[column_number] != expected_headers[column_number]:
            raise FormatingError((column_number+1,1), "Header [%s] Does not match Expected Value [%s]" % (header_row[column_number], expected_headers[column_number]))



if __name__ == "__main__":
    # default behavior
    from sys import argv 

    main(argv)