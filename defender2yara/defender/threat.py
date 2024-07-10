from typing import Tuple,List
import re
from defender2yara.defender.signature.base import BaseSig
from defender2yara.defender.signature.threat import ThreatBeginSig
from defender2yara.defender.signature.hstr import HSTR_EXT_SIGS
from defender2yara.util.utils import is_printable_ascii

MS_CARO_MALWARE_NAMING_PAT = r'^([A-Za-z0-0]+):([A-Za-z0-9_]+)(/([A-Za-z0-9_-]+))?((([\.!][A-Z0-9_]+)|([\.@!][A-Za-z0-9-_#]*))*)?$'

SEVERITY_MAP = {
    1: "Low",
    2: "Mid",
    4: "High",
    5: "Critical",
}

class Threat:
    """
    Manage threat defined by multiple signatures.
    """
    def __init__(self,sig:ThreatBeginSig):
        self.threat_begin_sig = sig
        self.threat_name = sig.threat_name
        self.threat_id = sig.threat_id
        self.category_id = sig.category_id
        
        if sig.severity_id in SEVERITY_MAP.keys():
            self.severity = SEVERITY_MAP[sig.severity_id]
        else:
            self.severity = sig.severity_id

        self.signatures = []
        self.hstr_signatures = []
        self.threat_type,\
        self.threat_platform,\
        self.threat_family,\
        self.threat_variant,\
        self.threat_suffixes = self.parse_threat_name(self.threat_name)

    def add_signature(self,sig:BaseSig):
        self.signatures.append(sig)
        if sig.sig_type == "SIGNATURE_TYPE_PEHSTR" or sig.sig_type in HSTR_EXT_SIGS:
            self.hstr_signatures.append(sig)

    @staticmethod
    def parse_threat_name(threat_name:str) -> Tuple[str,str,str,str,List[str]]:
        threat_type = ""
        threat_platform = ""
        threat_family = ""
        threat_variant = ""
        threat_suffixes = []
        
        if is_printable_ascii(threat_name):
            m = re.findall(MS_CARO_MALWARE_NAMING_PAT,threat_name)

            if not m:
                # print(threat_name)
                return \
                    threat_type,\
                    threat_platform,\
                    threat_family,\
                    threat_variant,\
                    threat_suffixes

            m = m[0]
            threat_type = m[0]
            threat_platform = m[1]
            threat_family = m[3]
            tail = m[4]
            if tail:
                tail_items = re.split(r'[\.@!]+',tail)
                for tail_item in tail_items:
                    if re.match(r'[A-Z0-9_]+',tail_item):
                        if tail_item == 'MSR' or re.match(r'MTB?',tail_item):
                            threat_suffixes.append(tail_item)
                        elif not threat_variant:
                            threat_variant = tail_item
                        else:
                            threat_suffixes.append(tail_item)
                    elif re.match(r'[A-Za-z0-9-_#]+',tail_item):
                        threat_suffixes.append(tail_item)
        
        return \
            threat_type,\
            threat_platform,\
            threat_family,\
            threat_variant,\
            threat_suffixes


