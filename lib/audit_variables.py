from lib.Windows.variables import custom_item_type_lookup as Windows
from lib.Unix.variables import custom_item_type_lookup as Unix
from lib.audit_types import *

custom_item_type_lookup = {**Windows, **Unix}
value_type_lookup = {
    
}