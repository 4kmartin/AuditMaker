# AuditMaker
Tenable allows you to scan device settings to see if they mach a desired baseline. you define this baseline in the xml based audit file. however crafting audit files can be time consuming. This Script attempts to automate as much of the process as possible.

## import from CSV:
Microsoft produces an xls file that list their reccomended best practices for various policy settings. this is part of the [Microstoft Security Compliance Toolkit (MSCT)](https://www.microsoft.com/en-us/download/details.aspx?id=55319). each sheet of this workbook can be exported to a csv with minimal configuration, and then the script can convert those settings to an audit file. please note that we recomend redirecting all interpretor output to a log file. this makes diagnostics much simpler.

``` $ python auditmaker.py -csv [path-to-csv-file] > error.log ```

## validate
This will read a supplied audit file, and give you its best guess if it is properly formatted.

``` $ python auditmaker.py --validate [path to audit file] > error.log```

``` $ python auditmaker.py -v [path to audit file] > error.log```