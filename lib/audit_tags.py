from lib.audit_types import VALUE_TYPE, AUDIT_SET, PolicyTypeError, POLICY_TEXT

############# Items

class Tag:
    def write(self) -> str:
        return "\n<tag/>"
    
    def __repr__(self) -> str:
        return self.write()


class item (Tag):
    
    def __init__(self, name: str, value: VALUE_TYPE):
        self.name = name
        self.value = value

    def write(self) -> str:
        return "\n<item>\n\tname: \"%s\"\n\tvalue: %s\n</item>" % (self.name, self.value)


class custom_item(Tag):
    type = ""
    def __init__(self,
    description: str,
    value_type: str,
    value_data: VALUE_TYPE,
    check_type: str=None):
        self.description = description
        self.value_type = value_type
        if isinstance(value_data, VALUE_TYPE) or value_data is None:
            self.value_data = value_data
        else:
            raise PolicyTypeError(value_data, "value_data")
        self.check_type = check_type

    def enumerate_fields(self) -> tuple:
        d = self.__dict__
        fields =  [ "%s: %s" % (str(k),str(d[k])) for k in d if d[k] is not None]
        
        return tuple(fields)

    def validate(self):
        return isinstance(self.value_data, VALUE_TYPE) or self.value_data is None
    
    def write(self) -> str:
        out = "\n<custom_item>"
        for field in self.enumerate_fields():
            out += "\n\t%s" % field
        return out + "\n</custom_item>"


class CONDITION_TAG(Tag):

    def __init__(self,type:str,items:[Tag]):
        if not isinstance(items, (tuple,list,dict)):
            raise TypeError("The CONDITION TAG reuires its items to be contained within an iterable, prefferably a tuple.\nThe supplied value :: %s :: does not meet that criteria" % str(items))
        if type not in ("or","and"):
            raise TypeError("The CONDITION TAG can only be either \"and\" or \"or\". \nThe supplied value :: %s :: does not meet that criteria" % type)
        for i in items:
            if not isinstance(i, Tag):
                raise TypeError("The CONDITION TAG must contain other tags.\nThe supplied value :: %s :: does not meet that criteria" % i)
        self.type = type
        self.items = items

    def write(self) -> str:
        return "\n<condition type: %s>%s\n</condition>" % (self.type, str(list(self.items)).replace("\n", "\n\t").replace("[", "").replace("]", ""))


class THEN_TAG(Tag):
    
    def __init__(self,contents:[Tag]):
        if not isinstance(contents, (list,tuple,dict)):
            raise TypeError
        for i in contents:
            if not isinstance(i, Tag):
                raise TypeError
        self.contents = contents
    
    def write(self) -> str:
        return "\n<then>%s\n</then>" % str(list(self.contents)).replace("\n", "\n\t").replace("[", "").replace("]", "")


class ELSE_TAG(Tag):

    def __init__(self,contents:[Tag]):
        if not isinstance(contents, (list,tuple,dict)):
            raise TypeError
        for i in contents:
            if not isinstance(i, Tag):
                raise TypeError
        self.contents = contents
    
    def write(self) -> str:
        return "\n<else>%s\n</else>" % str(list(self.contents)).replace("\n", "\n\t").replace("[", "").replace("]", "")


class REPORT_TAG(Tag):

    def __init__(self,type:str,description:str):
        self.type = type
        self.description = description

    def write(self) -> str:
        return "\n<report type: \"%s\">\n\tdescription: \"%s\"\n</report>" % (self.type, self.description)


class IF_TAG(Tag):

    def __init__(self,condition:CONDITION_TAG, then:THEN_TAG, _else:ELSE_TAG):
        if not isinstance(condition, CONDITION_TAG):
            raise TypeError
        if not isinstance(then, THEN_TAG):
            raise TypeError
        if not isinstance(_else, ELSE_TAG):
            raise TypeError
        self.condition = condition
        self.then = then
        self.otherwise = _else

    def write(self) -> str:
        return "\n<if>%s\n</if>" % "".join([str(self.condition), str(self.then), str(self.otherwise)]).replace("\n", "\n\t")
   

class BODY(Tag):

    def __init__(self, contents:[Tag]):
        try:
            assert isinstance(contents[0], Tag)
        except (AssertionError, IndexError):
            raise TypeError
        self.contents = contents
    
    def write(self) -> str:
        return str(self.contents).replace("[", "").replace("]", "")


class GROUP_POLICY(Tag):

    def __init__(self, comment:str ,contents:BODY):
        try:
            assert isinstance(contents, BODY)
            assert isinstance(comment, str)

        except AssertionError:
            raise TypeError
        self.comment = comment
        self.contents = contents
    
    def write(self) -> str:
        return "\n<group_policy: \"%s\">%s\n</group_policy>" % (self.comment, self.contents.write().replace("\n", "\n\t"))


class CHECK_TYPE(Tag):

    def __init__(self, check_type: str, contents: Tag):
        try:
            assert isinstance(contents, (BODY, GROUP_POLICY))
            assert check_type in ["Windows\" version:\"2","Unix"]
            if check_type =="\"Windows\" version:\"2\"":
                assert isinstance(contents, GROUP_POLICY)
        except AssertionError:
            raise TypeError
        self.type = check_type
        self.contents = contents
    
    def write(self) -> str:
        return "<check_type: \"%s\">%s\n</checktype>" % (self.type, self.contents.write().replace("\n", "\n\t"))