from lib import Tag, item, custom_item, IF_TAG, CONDITION_TAG, THEN_TAG, ELSE_TAG, REPORT_TAG,CHECK_TYPE,BODY,GROUP_POLICY, getfilecontents, make_custom_item, make_report
from re import findall, MULTILINE, search

defined_tags = {
    "<check_type":CHECK_TYPE,
    "<group_policy":GROUP_POLICY,
    "<item>": item,
    "<custom_item>": make_custom_item,
    "<if>":IF_TAG,
    "<condition":CONDITION_TAG,
    "<then>":THEN_TAG,
    "<else>":ELSE_TAG,
    "<report":make_report
}

def main(args:str):
    try:
        path = args#[1]
    except IndexError:
        print("You did not supply enough aruments")
        quit()
    try:
        audit = parse_contents(getfilecontents(path))
    except TypeError as te:
        print(te)
        audit = None
    
    if isinstance(audit, CHECK_TYPE):
        print("The file: %s, is correctly formated" % path[-path[::-1].index("\\"):])
    else:
        print("The file: %s, is not formatted correctly. Please attempt to address the preceding error" % path[-path[::-1].index("\\"):])

def check_tag_pairs(opentags:list[str], closedtags:list[str]) -> bool:
    """Returns True if all open tags have a matching close tag"""

    for tag in opentags:
        
        closedtag = "</%s>" % tag.replace("<", "").replace(">", "")

        if opentags.count(tag) != closedtags.count(closedtag):
            a = lambda x: "You forgot a %s" if x else "You have an extra %s"
            print("%s" % (a(opentags.count(tag)>closedtags.count(closedtag)) % closedtag)) 
            return False

    else:
        return len(opentags) == len(closedtags)

def check_tags(tags:[str]) -> bool:
    """returns true if the supplied Tags are valid"""
    def AND(x:[bool]) -> bool:
        return x.count(True) == len(x)
    def OR(x:[bool]) -> bool:
        return True in x
    return AND(list(map(lambda x: OR(map(lambda y: y in x,defined_tags)),tags)))

def parse_contents(contents:str) -> CHECK_TYPE:
    """takes the contents of an audit file and attempts to reconstruct it, 
    if it fails the supplied audit file has an error."""

    tags = findall(r"(<[^/>]*>)", contents, MULTILINE)
    closed = findall(r"(</[^>]*>)", contents, MULTILINE)
    tags = [tag if ":" not in tag else tag.replace(tag[tag.index(":"):],"").split()[0] + ">" for tag in tags]
    once = [i for n, i in enumerate(tags) if i not in tags[:n]]

    if check_tags(once) and check_tag_pairs(tags, closed):
        x = findall(r"((<[^/>]*>)([^<>]*)(</[^>]*>)|<[^/>]*>|</[^>]*>)",contents,MULTILINE)
        tree = make_tree([i[0] if i[1] == "" else i[1:] for i in x ])
        return tree

    else: 
        raise TypeError("all tags valid: %s\nall tags closed: %s" % (check_tags(once),check_tag_pairs(tags, closed)))

def make_tree(x:list, depth = 0)->CHECK_TYPE:
    # print("started function")
    tree = {'BODY': []}
    # print(depth)
    n = 0
    # print(x)
    while len(x)>0:
        tag = x[n]
        # print("loop")
        # print(tag)
        if isinstance(tag, tuple):
            # print("add tag to tree")
            tree["BODY"].append(make_tag(tag[0].replace("\"",""), tag[1].replace("\t","").replace("\"","").split("\n")[1:-1]))
            n += 1
        elif bool(search(r"<[^/>]*>", tag)):
            # print("create Branch")
            new = make_tree(x[n+1:],depth + 1)
            # print(new)
            x = new[1]
            n = 0

            tree["BODY"].append(make_tag(tag.replace("\"",""), new[0]))
        elif bool(search(r"</[^>]*>",tag)):
            # print("closeing branch")
            ret = tree["BODY"]
            return [ret, x[n+1:]]
    # print("left loop")
    return tree["BODY"][0]
          
def make_tag(tag: str, attributes: list) -> Tag:
    
    if tag[1:11] == "check_type":
        if not isinstance(attributes[0],GROUP_POLICY):
            attributes = BODY(attributes)
        else:
            attributes = attributes[0]
        newtag = CHECK_TYPE(tag[13:-1], attributes)

    elif isinstance(attributes, (list,tuple)):
        
        if isinstance(attributes[0],str):
            
            n = map(lambda x: x.split(":"), attributes)
            attr = {}
            for i in n:
                attr[i[0]] = i[1]

            if ":" in tag and " " in tag:
                
                tag, flag = tag.split()
                b = flag.split(":")
                attr = {b[0]:b[1].replace(">",""), **attr}

            newtag = defined_tags[tag](attr)
    
        elif ":" in tag and " " in tag:
            
            tag, flag = tag.split(" ",1)
            b = flag.split(":")
            newtag = defined_tags[tag](b[1].replace(">","").replace(" ",""), attributes)

        elif tag == "<if>":
            newtag = IF_TAG(*attributes)
        
        else:
            newtag = defined_tags[tag](attributes)

    else:
        newtag = defined_tags[tag]([attributes])

    return newtag
    
            

if __name__ == "__main__":
    print(main([0,"WindowsMinimal.audit"]))
