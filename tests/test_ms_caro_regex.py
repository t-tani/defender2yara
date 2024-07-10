import os
import sys
import re
import json
from defender2yara.defender.threat import MS_CARO_MALWARE_NAMING_PAT
from defender2yara.defender.threat import Threat

IGNORE_CASE = ('MagicThreat_7ffe3a4b',"Unknown","FriendlyFiles")

def test_regex(path):
    data = None
    if not os.path.exists(path):
        raise FileExistsError(path)

    with open(path,"r") as f:
        data = json.load(f)

    print("Load threat names from sample json")
    print("Start regex test with following pattern string.")
    print(MS_CARO_MALWARE_NAMING_PAT)

    threat_names = [e['ThreatName'] for e  in data.values()]
    for name in threat_names:
        threat_type,\
        threat_platform,\
        threat_family,\
        threat_variant,\
        threat_suffixes = Threat.parse_threat_name(name)
        print(threat_type,threat_platform,threat_family,threat_variant,threat_suffixes)

    print("All threat name was parsed!")

if __name__ == "__main__":
    test_regex(sys.argv[1])


