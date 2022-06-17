import CSV_to_audit_file
import validate
from sys import argv

def main (args):
    help_text = """
        syntax: python auditmaker.py [options] [arguments]

        options:
            -h or --help                        Display this message

            -csv [path to file]                 generate a  audit file from the contents of a csv

            -v or --validate [path to file]     tests the formating of a specified audit file

        License Statement:
            auditmaker.py, Copyright (C) 2022 Anthany Martin 
            
            auditmaker.py comes with ABSOLUTELY NO WARRANTY. This is free software, and you are welcome 
            to redistribute it under certain conditions; see the included license for details.
    """

    if  args [1] in ("-h", "--help"):
        print(help_text)
    
    elif args [1] == "-csv":
        CSV_to_audit_file.main(args[1:])
    
    elif args[1] in ("-v","--validate"):
        validate.main(args[1:])
    
    else:
        print(help_text)



if __name__ == "__main__":
    main(argv)
