import struct
from defender2yara.defender.constant import SIG_TYPES

class BaseSig:
    def __init__(self,data:bytes,ptr:int=0):
        self.parse_common_header(data,ptr)

    def parse_common_header(self,data:bytes,ptr:int=0):
        offset = 4
        self.sig_type_id = data[ptr+0]
        self.sig_type = SIG_TYPES[data[ptr+0]]
        self.size_low = data[ptr+1]
        self.size_high = struct.unpack('<H',data[ptr+2:ptr+4])[0]
        self.size = self.size_low | self.size_high << 8
        if self.size == 0xffffff:
            self.size = struct.unpack('<I',data[ptr+4:ptr+8])[0]
            offset += 4
        self.sig_data = data[ptr+offset:ptr+offset+self.size]