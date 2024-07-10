from typing import Tuple,List
import struct
from .base import BaseSig
from defender2yara.defender.subrule.hstr import HStrSubRule, HStrExtSubRule
from defender2yara.defender.constant import SIG_TYPES


HSTR_EXT_SIGS = [
    "SIGNATURE_TYPE_PEHSTR_EXT",
    "SIGNATURE_TYPE_ELFHSTR_EXT",
    "SIGNATURE_TYPE_MACHOHSTR_EXT",
    "SIGNATURE_TYPE_DOSHSTR_EXT",
    "SIGNATURE_TYPE_MACROHSTR_EXT",
    "SIGNATURE_TYPE_DEXHSTR_EXT",
    "SIGNATURE_TYPE_JAVAHSTR_EXT",
    "SIGNATURE_TYPE_ARHSTR_EXT",
    "SIGNATURE_TYPE_SWFHSTR_EXT",
    "SIGNATURE_TYPE_AUTOITHSTR_EXT",
    "SIGNATURE_TYPE_INNOHSTR_EXT",
    "SIGNATURE_TYPE_CMDHSTR_EXT",
    "SIGNATURE_TYPE_MDBHSTR_EXT",
    "SIGNATURE_TYPE_DMGHSTR_EXT"
]


class HStrSig(BaseSig):
    def __init__(self,data:bytes,ptr:int=0) -> None:
        # parse common header
        self.parse_common_header(data,ptr)
        assert self.sig_type == SIG_TYPES[0x61]

        # parse signature data header
        self.unknown_u16_1 = struct.unpack('<H',self.sig_data[0:2])[0]
        self.threshold = struct.unpack('<H',self.sig_data[2:4])[0]
        self.rule_numbers = struct.unpack('<H',self.sig_data[4:6])[0]
        self.unknown_u8_1 = self.sig_data[6]

        # parse subrules
        self.subrules = []
        pos = 7
        while pos < len(self.sig_data):
            subrule = HStrSubRule(self.sig_data,pos)
            # no more subrule
            if subrule.rule_weight == 0:
                break
            self.subrules.append(subrule)
            pos += 3 + subrule.rule_size


class HStrExtSig(BaseSig):
    def __init__(self,data:bytes,ptr:int=0) -> None:
        # parse common header
        self.parse_common_header(data,ptr)
        assert self.sig_type in HSTR_EXT_SIGS

        # parse signature data header
        self.unknown_u16_1 = struct.unpack('<H',self.sig_data[0:2])[0]
        self.threshold = struct.unpack('<H',self.sig_data[2:4])[0]
        self.rule_numbers = struct.unpack('<H',self.sig_data[4:6])[0]
        self.unknown_u8_1 = self.sig_data[6]

        # parse subrules 
        self.subrules = []
        ptr = 7
        while ptr < len(self.sig_data):
            subrule = HStrExtSubRule(self.sig_data,ptr)
            # no more subrule
            if subrule.rule_weight == 0:
                break
            self.subrules.append(subrule)
            ptr += 4 + subrule.rule_size
