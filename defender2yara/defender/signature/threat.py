import struct

from .base import BaseSig
from defender2yara.defender.constant import SIG_TYPES, THREAT_NAME_PREFIX


class ThreatBeginSig(BaseSig):
    def __init__(self,data:bytes,ptr:int=0) -> None:
        # parse common header
        self.parse_common_header(data,ptr)
        assert self.sig_type == SIG_TYPES[0x5c]

        # parse threat info
        self.threat_id = struct.unpack('<I', self.sig_data[0:4])[0]
        self.unknown_bytes1 = self.sig_data[4:8]
        self.category_id = struct.unpack('<H', self.sig_data[8:10])[0]
        self.size_threat_name = self.sig_data[10]
        self.type_id = self.sig_data[11] # not concrete
        self.raw_threat_name = self.sig_data[12:12+self.size_threat_name]
        
        # parse severity_id
        try:
            self.unknown_bytes2 = self.sig_data[12+self.size_threat_name:16+self.size_threat_name]
            self.severity_id = self.sig_data[16+self.size_threat_name]
            self.unknown_bytes3 = self.sig_data[17+self.size_threat_name:17+self.size_threat_name+4]
        except IndexError:
            self.unknown_bytes2 = None
            self.severity_id = None
            self.unknown_bytes3 = None

        # resolve threat name
        if self.raw_threat_name[0] > 128:
            prefix_id = struct.unpack('<H', self.raw_threat_name[0:2])[0]
            self.threat_name = THREAT_NAME_PREFIX[prefix_id] + self.raw_threat_name[2:].decode('utf-8')
        else:
            self.threat_name = self.raw_threat_name.decode('utf-8')
        


class ThreatEndSig(BaseSig):
    def __init__(self,data:bytes,ptr:int=0) -> None:
        # parse common header
        self.parse_common_header(data,ptr)
        assert self.sig_type == SIG_TYPES[0x5D]

        self.threat_id = struct.unpack('<I', self.sig_data[0:4])[0]
