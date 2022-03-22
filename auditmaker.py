from lib import *
import CSV_to_audit_file
from sys import argv

def main (args):
    help_text = """
        syntax: python auditmaker.py [options] [arguments]

        options:
            -h or --help            Display this message

            -csv [path to file]     generate a  audit file from the contents of a csv
    """

    if  args [1] in ("-h", "--help"):
        print(help_text)
    
    elif args [1] == "-csv":
        CSV_to_audit_file.main(args[1:])
    
    else:
        print(help_text)



if __name__ == "__main__":
    main(argv)