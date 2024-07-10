from typing import List,Dict,Tuple
import os
import sys
import shutil
import yara
from collections import defaultdict

from defender2yara.defender.threat import Threat
from defender2yara.yara.rule import YaraRule
from defender2yara.defender.vdm import Vdm
from defender2yara.defender.download import get_latest_signature_vdm, download_latest_signature, parse_full_engine_exe

from tqdm import tqdm
import logging

logger = logging.getLogger(__package__)

def clean_up_dir(path:str):
    if not os.path.exists(path):
        raise ValueError(f"Path does not exists: {path}")
    
    for root, dirs, files in os.walk(path):
        for file in files:
            file_path = os.path.join(root, file)
            try:
                os.remove(file_path)
            except Exception as e:
                logger.error(f"Failed to delete: {file_path}. Error: {e}")
        
        for dir in dirs:
            dir_path = os.path.join(root, dir)
            try:
                shutil.rmtree(dir_path)
            except Exception as e:
                logger.error(f"Failed to delete directory: {dir_path}. Error: {e}")


def write_rules_to_single_file(path,filename,results:Dict[Threat,List[str]]):
    output = []
    for rules in results.values():
        output.extend(rules)
    # write result
    output_file = os.path.join(path,f"{filename}.yara")        
    with open(output_file,'w') as f:
        f.writelines(output)
        logger.info(f"Write YARA rules to {output_file}")


def write_rules_by_family(path,results:Dict[Threat,List[str]]):
    threat:Threat
    for threat,rules in results.items():
        output_dir = os.path.join(path,threat.threat_platform,threat.threat_type)
        if not threat.threat_family:
            output_file = os.path.join(output_dir,"misc.yara")
        else:
            output_file = os.path.join(output_dir,threat.threat_family+".yara")

        os.makedirs(output_dir, exist_ok=True)
        with open(output_file,'a') as f:
            f.writelines(rules)
    logger.info(f"Write YARA rules to {path}")


def covert_vdm_to_yara(vdm:Vdm,header_check:bool=False) -> Tuple[Dict[Threat,List[str]],int]:
    logger.info(f"Parsing signature database...")
    results:Dict[Threat,List[str]] = defaultdict(list)
    rule_count = 0
    # convert to yara rule
    threats = vdm.get_threats()

    progress_bar = tqdm(
            total=len(threats),
            unit='threat',
            bar_format='{l_bar}{bar:20}{r_bar}',
            colour='green',
            desc="Converting signatures",
            leave=False)

    for threat in threats:
        yara_rules = YaraRule(threat,optional_conditions=header_check)
        if not yara_rules:
            continue
        for yara_rule in yara_rules.generate_rules():
            try:
                yara.compile(source=yara_rule)
            except yara.SyntaxError as e:
                logger.warn(f"Failed to convert {threat.threat_name}: {str(e)}")
                logger.debug("\n"+yara_rule)
                continue
            results[threat].append(yara_rule)
            rule_count += 1
        progress_bar.update(1)

    progress_bar.close()

    return results,rule_count


def main(args):
    cache_dir = args.cache
    signature_version:str = ""
    engine_version:str = ""

    if args.latest_signature_version:
        url, signature_version, engine_version = get_latest_signature_vdm(proxy=args.proxy)
        print(f"{signature_version}")
        sys.exit(0)

    if (args.download or not args.base) and not args.full_engine:
        logger.info("Downloading latest signature database.")
        signature_version, engine_version, use_cache = download_latest_signature(cache_dir,proxy=args.proxy)
        logger.info(f"Complete (use_cache:{use_cache})")
        logger.info(f"Latest Signature Version:{signature_version}")
        logger.info(f"Latest Engine Version   :{engine_version}")

    if args.download:
        sys.exit(0)

    if args.full_engine:
        signature_version, engine_version = parse_full_engine_exe(args.full_engine,cache_path=cache_dir,rm_full_engine=False)
        logger.info(f"Loaded {args.full_engine}")
        logger.info(f"Latest Signature Version:{signature_version}")
        logger.info(f"Latest Engine Version   :{engine_version}")

    base_file:str = ""
    delta_file:str = ""
    results:Dict[Threat,List[str]]

    output_path = os.path.join(args.output,signature_version)
    os.makedirs(output_path, exist_ok=True)
    logger.info(f"Clean up output directory: {output_path}")
    clean_up_dir(output_path)

    if args.base: # use manually specified vdm files.
        logger.info(f"Loading base signature file: {args.base}")
        vdm = Vdm(args.base)
        if args.delta:
            logger.info(f"Applying delta patch: {args.delta}")
            vdm.apply_delta_vdm(args.delta)

        logger.info(f"Target signature version: {vdm.version}")
        logger.info(f"Target signature type   : {vdm.vdm_type}")

        results,rule_counts = covert_vdm_to_yara(vdm,args.header_check)
        logger.info(f"Convert {rule_counts} signatures.")

        if args.single_file:
            write_rules_to_single_file(output_path,vdm.vdm_type,results)
        else:
            write_rules_by_family(output_path,results)
    else: # use vdm files parsed from mpam-fe.exe
        major_version = ".".join(signature_version.split(".")[0:2])
        minor_version = ".".join(signature_version.split(".")[2:4])
        vdm_base_path = os.path.join(cache_dir,"vdm",major_version,'0.0')
        vdm_delta_path = os.path.join(cache_dir,"vdm",major_version,minor_version)
        
        for name in ["mpav","mpas"]:
            base_file = os.path.join(vdm_base_path,name+"base.vdm")
            delta_file = os.path.join(vdm_delta_path,name+"dlta.vdm")
        
            logger.info(f"Loading base signature file: {base_file}")
            vdm = Vdm(base_file)
            if os.path.exists(delta_file):
                logger.info(f"Applying delta patch: {delta_file}")
                vdm.apply_delta_vdm(delta_file)

            logger.info(f"Target signature version: {vdm.version}")
            logger.info(f"Target signature type   : {vdm.vdm_type}")

            results,rule_counts = covert_vdm_to_yara(vdm,args.header_check)
            logger.info(f"Convert {rule_counts} signatures")

            if args.single_file:
                write_rules_to_single_file(output_path,vdm.vdm_type,results)
            else:
                write_rules_by_family(output_path,results)

    logger.info("Complete")
    sys.exit(0)
