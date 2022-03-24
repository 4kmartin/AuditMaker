"""
auditmaker.py automate the construction of tenable audit files
    Copyright (C) 2022  Anthany Martin

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 2 as published by
    the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License along
    with this program; if not, write to the Free Software Foundation, Inc.,
    51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
"""


import CSV_to_audit_file
from sys import argv

def main (args):
    help_text = """
        syntax: python auditmaker.py [options] [arguments]

        options:
            -h or --help            Display this message

            -csv [path to file]     generate a  audit file from the contents of a csv

        License Statement:
                auditmaker.py, Copyright (C) 2022 Anthany Martin
            auditmaker.py comes with ABSOLUTELY NO WARRANTY.
            This is free software, and you are welcome to redistribute it
            under certain conditions; see the included license for details.
    """

    if  args [1] in ("-h", "--help"):
        print(help_text)
    
    elif args [1] == "-csv":
        CSV_to_audit_file.main(args[1:])
    
    else:
        print(help_text)



if __name__ == "__main__":
    main(argv)