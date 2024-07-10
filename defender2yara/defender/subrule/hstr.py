import struct
# from defender2yara.utils import hexdump


class HStrSubRule:
    def __init__(self,data:bytes,ptr:int) -> None:
        if len(data[ptr:]) < 3:
            self.rule_weight = 0
            return

        self.rule_weight = struct.unpack('<h',data[ptr+0:ptr+2])[0] # rule weight contains negative numbers

        if self.rule_weight == 0:
            return
        self.rule_size = data[ptr+2]
        self.rule_bytes = data[ptr+3:ptr+3+self.rule_size]

        # Convert rule_bytes to YARA strings.
        # self.yara_str, self.yara_str_type, self.yara_str_inaccurate = rule_bytes_to_yara_string(self.rule_bytes)


class HStrExtSubRule:
    def __init__(self,data:bytes,ptr:int) -> None:
        if len(data[ptr:]) < 4:
            self.rule_weight = 0
            return 

        self.rule_weight = struct.unpack('<h',data[ptr+0:ptr+2])[0] # rule weight contains negative numbers

        if self.rule_weight == 0:
            return

        self.rule_size = data[ptr+2]
        self.unknown_u8_1 = data[ptr+3]

        if self.unknown_u8_1 in [0x80,0x81,0x88]: # unknown flag.
            self.rule_bytes = data[ptr+5:ptr+5+self.rule_size]
            self.rule_size += 1
        elif self.unknown_u8_1 == 0x90: # unknown flag.
            self.rule_size += 1
            self.rule_bytes = data[ptr+5:ptr+5+self.rule_size]
        else:
            self.rule_bytes = data[ptr+4:ptr+4+self.rule_size]

        # Convert rule_bytes to YARA strings.
        # self.yara_str, self.yara_str_type, self.yara_str_inaccurate = rule_bytes_to_yara_string(self.rule_bytes)