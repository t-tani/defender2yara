from typing import Tuple, List, Union
import json
import re
from defender2yara.defender.subrule.hstr import HStrSubRule,HStrExtSubRule
from defender2yara.util import is_printable_ascii, is_printable_utf16_le_ascii

class YaraString:
    def __init__(self,subrule:Union[HStrSubRule,HStrExtSubRule]):
        self.string,\
        self.types,\
        self.is_inaccurate = self.parse_subrule(subrule.rule_bytes)
        self.weight = subrule.rule_weight

    def __repr__(self) -> str:
        if "ascii" in self.types or "wide" in self.types:
            return json.dumps(self.string)
        if "hex" in self.types:
            return f"{{{self.string}}} "

    @staticmethod
    def parse_subrule(data:bytes):
        """
        Converts rule bytes to a YARA string format.

        Args:
        data (bytes): The rule bytes to be converted.

        Returns:
            Tuple[str, List[str], bool]:
                - str: The YARA string.
                - List[str]: The types of YARA strings identified (e.g., 'ascii', 'wide', 'hex').
                - bool: Flag indicating if the YARA string conversion is inaccurate.
        """
        string = ""
        string_types = []
        is_inaccurate = False

        if is_printable_ascii(data):
            string = data.decode('utf-8')
            string_types.append('ascii')
        elif is_printable_utf16_le_ascii(data):
            string = data.decode('utf-16-le')
            string_types.append('wide')
        elif len(data) > 2 and data[-1] == 0x00 and data[-2] == 0x90:
            string, is_inaccurate = YaraString.parse_ext_subrule(data)
            string_types.append('hex')
            is_inaccurate = True
        else:
            string = ' '.join(f'{byte:02x}' for byte in data)
            string_types.append('hex')

        return string, string_types, is_inaccurate

    @staticmethod
    def parse_ext_subrule(data:bytes,is_root:bool=True)->Tuple[str,bool]:
        """
        Converts HStrExt data to a YARA hex string.

        Args:
            data (bytes): The rule bytes stored in HStrExtSubRule.
            is_root (bool): Boolean to control recursive call.

        Returns:
            Tuple[str, bool]:
                - str: The formatted string in YARA hex style.
                - bool: Whether an unimplemented regex-like pattern was encountered.

        Raises:
            ValueError: If the data is too short or contains invalid suffix data.
        """
        is_inaccurate = False
        WILDCARD_MARKER = 0x90

        if len(data) < 3:
            if is_root:
                raise ValueError("Too short data.",data)
            else:
                return  " ".join(f"{c:02x}" for c in data), is_inaccurate
        
        if is_root and (data[-1] != 0x00 or data[-2] != 0x90):
            raise ValueError(f"Invalid suffix data: '{data[-2]:02x} {data[-1]:02x}'")

        p = 0
        hex_string = []
        while p < len(data)-2:
            if data[p] == WILDCARD_MARKER:
                if data[p+1] == 0x01: # static length wildcard
                    wildcard_size = data[p+2]
                    hex_string.extend(["??" for _ in range(wildcard_size)])
                    p += 3

                elif data[p+1] == 0x02: # dynamic length wildcard
                    if is_root:
                        upper_size = data[p+2]
                        hex_string.append(f"[0-{upper_size}]")
                    else:
                        # Nested dynamic length is not supported
                        # e.g.: 
                        #    { aa (de ad be ef|[0-3]) bb } <- [0-3] is Invalid
                        # here we convert hex pattern into following syntax
                        #    { aa (de ad be ef|(?? | ?? ?? | ?? ?? ??) bb }
                        # however this syntax is too complex for yara hex pattern
                        is_inaccurate = True
                        upper_size = data[p+2]
                        if upper_size > 0:
                            _tmp = "("
                            for i in range(1,upper_size):
                                _tmp += " ".join(["??" for _ in range(i)])
                                _tmp += "|"
                            if len(_tmp) > 2:
                                _tmp = _tmp[:-1]+")"
                                hex_string.append(_tmp)
                    p += 3

                elif data[p+1] == 0x03: # two byte sequence patter
                    first_seq_size = data[p+2]
                    second_seq_size = data[p+3]
                    first_bytes = data[p+4:p+4+first_seq_size]
                    second_bytes = data[p+4+first_seq_size:p+4+first_seq_size+second_seq_size]

                    first_bytes_yara_str, _is_inaccurate = YaraString.parse_ext_subrule(first_bytes,False)
                    is_inaccurate |= _is_inaccurate

                    second_bytes_yara_str, _is_inaccurate = YaraString.parse_ext_subrule(second_bytes,False)
                    is_inaccurate |= _is_inaccurate

                    if first_bytes_yara_str and second_bytes_yara_str:
                        hex_string.append(f"({first_bytes_yara_str}|{second_bytes_yara_str})")
                    elif first_bytes_yara_str:
                        hex_string.append(f"{first_bytes_yara_str}")
                    elif second_bytes_yara_str:
                        hex_string.append(f"{second_bytes_yara_str}")

                    p += 4 + first_seq_size + second_seq_size

                elif data[p+1] == 0x04: # case sensitive regex-like style
                    iterate_count = data[p+2]
                    pattern_size = data[p+3]
                    pattern_bytes = data[p+4:p+4+pattern_size]
                    pattern_yara_str = "|".join(f"{c:02x}" for c in pattern_bytes)
                    # reduce regex complexity
                    if iterate_count > 2:
                        hex_string.extend(["??" for _ in range(iterate_count-2)])
                        hex_string.extend([f"({pattern_yara_str})" for _ in range(2)])
                    else:
                        hex_string.extend([f"({pattern_yara_str})" for _ in range(iterate_count)])
                    p += 4 + pattern_size

                elif data[p+1] == 0x05: # case insensitive regex-like style
                    upper_size = data[p+2]
                    pattern_size = data[p+3]
                    pattern_bytes:bytes = data[p+4:p+4+pattern_size]
                    pattern_yara_str = "|".join(f"{c:02x}" for c in pattern_bytes)
                    # hex_string.append(f"({pattern_yara_str})") 
                    ## Since Yara 4.4 or earlier does not have the capability to express "iterate hex pattern"
                    hex_string.append(f"[0-{upper_size*pattern_size}]")
                    p += 4 + pattern_size

                elif data[p+1] <= 0x20:
                    is_inaccurate = True
                    p += 2

                elif data[p+1] == 0x90: # maybe magic byte escape
                    hex_string.append(f"{data[p+1]:02x}")
                    p += 2

                else:
                    is_inaccurate = True
                    hex_string.append(f"{data[p+1]:02x}")
                    hex_string.append(f"{data[p+2]:02x}")
                    p += 2
            else:
                hex_string.append(f"{data[p]:02x}")
                p += 1

        result = " ".join(hex_string)

        # fix unsupported regex-like syntax #@todo make regex-like syntax check
        # e.g.) {57 3e 00 00 02 00 81 [0-3]} <- hex strings ending with "[0-3]" is invalid.
        result = re.sub(r' \[0-\d+\]$', '', result) 
        # e.g.) {[0-3] 57 3e 00 00 02 00 81} <- hex strings starting with "[0-3]" is invalid.
        result = re.sub(r'^\[0-\d+\]', '', result) 

        return result, is_inaccurate
