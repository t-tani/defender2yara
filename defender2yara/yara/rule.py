from typing import List,Union,Tuple
import json

from defender2yara.defender.threat import Threat
from defender2yara.defender.constant import PLATFORM, SUFFIX
from defender2yara.defender.signature.hstr import HStrExtSig,HStrSig
from defender2yara.defender.subrule.hstr import HStrSubRule, HStrExtSubRule

from .strings import YaraString
from .condition import YaraCondition


class YaraRule:
    def __init__(self,threat:Threat,filesize_check,do_header_check:bool=False):
        self.threat = threat
        self.base_rule_name = self._gen_rule_name()
        self.meta = {}
        self._set_meta()
        self.rules:List[Tuple[Union[HStrSig,HStrExtSig],List[YaraString],YaraCondition]] = []
        
        signature:Union[HStrSig,HStrExtSig]
        for signature in threat.hstr_signatures:
            strings:List[YaraString] = []
            subrule:Union[HStrSubRule,HStrExtSubRule]
            for subrule in signature.subrules:
                rule_string = YaraString(subrule)
                if rule_string.string:
                    strings.append(rule_string)
            condition = YaraCondition(strings,signature,filesize_check,do_header_check)

            self.rules.append((signature,strings,condition))

    def _gen_rule_name(self) -> str:
        items = []
        if self.threat.threat_type:
            items.append(self.threat.threat_type)
        if self.threat.threat_platform:
            items.append(self.threat.threat_platform)
        if self.threat.threat_family:
            items.append(self.threat.threat_family)
        if self.threat.threat_variant:
            items.append(self.threat.threat_variant)
        if items:
            items.append(str(self.threat.threat_id))
            name:str = "_".join(items)
            if name[0].isdigit():
                name = "_" + name
            return name.replace("-","_")
        else:
            name = self.threat.threat_name\
                .replace("!","_")\
                .replace("/","_")\
                .replace("@","_")\
                .replace(":","_")\
                .replace(".","_")\
                .replace("-","_")\
                .replace("#","_")
            if name[0].isdigit():
                name = "_" + name
            return name

    def _set_meta(self):
        self.meta['author'] = "defender2yara"
        self.meta['detection_name'] = self.threat.threat_name
        self.meta['threat_id'] = str(self.threat.threat_id)
        if self.threat.threat_type:
            self.meta['type'] = self.threat.threat_type
        if self.threat.threat_platform:
            self.meta['platform'] = f"{self.threat.threat_platform}: {PLATFORM[self.threat.threat_platform]}"
        if self.threat.threat_family:
            self.meta['family'] = self.threat.threat_family
        if self.threat.severity:
            self.meta['severity'] = f"{self.threat.severity}"
        if self.threat.threat_suffixes:
            self.meta['info'] = []
            for suffix in self.threat.threat_suffixes:
                self.meta['info'].append(f"{suffix}: {SUFFIX[suffix]}")

    def generate_rules(self,add_comment=True):
        rule_idx = 0
        INDENT = " "*4
        for signature,strings,condition in self.rules:
            meta_section = []
            for key,value in self.meta.items():
                if isinstance(value,list):
                    for v in value:
                        meta_section.append(f"{key} = {json.dumps(v)}")
                else:
                    meta_section.append(f"{key} = {json.dumps(value)}")
            # add threshold info to meta section
            meta_section.append(f"signature_type = {json.dumps(signature.sig_type)}")
            meta_section.append(f"threshold = {json.dumps(str(condition.threshold))}")
            # add accuracy of the rule to meta section
            is_inaccurate = any([string.is_inaccurate for string in strings])
            meta_section.append(f"strings_accuracy = {json.dumps('High' if not is_inaccurate else 'Low')}")

            strings_section = []
            var_idx = 1
            for rule_string in strings:
                weight = rule_string.weight
                if add_comment and "hex" in rule_string.types:
                    line = f"${'x' if weight > 0 else 'n'}_{abs(weight)}_{var_idx} = {str(rule_string)} //weight: {weight}, accuracy: {'High' if not rule_string.is_inaccurate else 'Low'}"
                elif "hex" in rule_string.types:
                    line = f"${'x' if weight > 0 else 'n'}_{abs(weight)}_{var_idx} = {str(rule_string)}"
                elif add_comment:
                    line = f"${'x' if weight > 0 else 'n'}_{abs(weight)}_{var_idx} = {str(rule_string)} {' '.join(rule_string.types)} //weight: {weight}"
                else:
                    line = f"${'x' if weight > 0 else 'n'}_{abs(weight)}_{var_idx} = {str(rule_string)} {' '.join(rule_string.types)}"
                strings_section.append(line)
                var_idx += 1

            condition_section = []
            for statement in condition.statements:
                condition_section.append(statement)

            # construct YARA rule.
            rule = []
            rule.append(f"rule {self.base_rule_name}_{rule_idx}")
            rule.append("{")
            # write meta section
            rule.append(INDENT + "meta:")
            for line in meta_section:
                rule.append(INDENT*2 + line)
            # write strings section
            rule.append(INDENT + "strings:")
            for line in strings_section:
                rule.append(INDENT*2 + line)
            # write condition section
            rule.append(INDENT + "condition:")
            for i,statement in enumerate(condition_section):
                if isinstance(statement,str):
                    rule.append(INDENT*2 + "(" +statement + ")")
                
                if isinstance(statement,list):
                    rule.append(INDENT*2 + "(")
                    for j,sub in enumerate(statement):
                        rule.append(INDENT*3 + "(" + sub + ")")
                        if j != len(statement)-1:
                            rule[-1] += " or"
                    rule.append(INDENT*2 + ")")

                if i != len(condition_section)-1:
                    rule[-1] += " and"
            rule.append("}\n\n")
            rule_idx += 1
            yield "\n".join(rule)
