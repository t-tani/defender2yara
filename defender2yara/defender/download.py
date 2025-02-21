from typing import Tuple
import platform
import httpx
import re
import time
from tqdm import tqdm
import os
import glob
import shutil

from defender2yara.util.cabarchive import expand_mpam_fe
from defender2yara.defender.vdm import Vdm

import logging

logger = logging.getLogger(__package__)

DOWNLOAD_URL = "https://go.microsoft.com/fwlink/?LinkID=121721&arch=x86"
URL_PATTERN_1 = r'https://definitionupdates\.microsoft\.com/download/DefinitionUpdates/versionedsignatures/[aA][mM]/[0-9.]+/[0-9.]+/x86/mpam-fe\.exe'
URL_PATTERN_2 = r'https://definitionupdates\.microsoft\.com/packages/content/mpam-fe\.exe\?packageType=Signatures&packageVersion=([0-9.]+)&arch=x86&engineVersion=([0-9.]+)'

UPDATE_CATALOG = "https://www.microsoft.com/en-us/wdsi/definitions/antimalware-definition-release-notes?requestVersion={signature_version}"

def check_cached_signature(signature_version,engine_version,cache_dir='cache') -> Tuple[bool,bool,bool]:
    has_base_signature = False
    has_delta_signature = False
    has_engine = False

    major_version = ".".join(signature_version.split('.')[0:2])
    minor_version = ".".join(signature_version.split('.')[2:4])

    base_vdm_dir = os.path.join(cache_dir,"vdm",major_version,"0.0")
    delta_vdm_dir = os.path.join(cache_dir,"vdm",major_version, minor_version)
    engine_dir = os.path.join(cache_dir,"engine",engine_version)

    av_base_path = os.path.join(base_vdm_dir,"mpavbase.vdm")
    as_base_path = os.path.join(base_vdm_dir,"mpasbase.vdm")
    av_delta_path = os.path.join(delta_vdm_dir,"mpavdlta.vdm")
    as_delta_path = os.path.join(delta_vdm_dir,"mpasdlta.vdm")
    mp_engine_path = os.path.join(engine_dir,"mpengine.dll")

    # @todo add exiftool check
    if os.path.exists(av_base_path) and os.path.exists(as_base_path):
        has_base_signature = True
    if os.path.exists(av_delta_path) and os.path.exists(as_delta_path):
        has_delta_signature = True
    if os.path.exists(mp_engine_path):
        has_engine = True
    return has_base_signature,has_delta_signature,has_engine


def download_file(url,cache_dir='cache',proxy=None) -> str:
    with httpx.stream("GET", url, proxy=proxy) as response:
        total = int(response.headers.get('content-length', 0))

        progress_bar = tqdm(
            total=total,
            unit='iB',
            bar_format='{l_bar}{bar:20}{r_bar}',
            colour='green',
            desc="Downloading latest signature",
            leave=False)

        output_path = os.path.join(cache_dir,"mpam-fe.exe")
        with open(output_path,'wb') as file:
            for chunk in response.iter_bytes():
                file.write(chunk)
                progress_bar.update(len(chunk))
        progress_bar.close()
        return output_path


def create_cache_dir(signature_version, engine_version, cache_path='cache')->None:
    os.makedirs(cache_path, exist_ok=True)
    
    major_version = ".".join(signature_version.split('.')[0:2])
    minor_version = ".".join(signature_version.split('.')[2:4])
    
    base_vdm_dir = os.path.join(cache_path,"vdm",major_version,"0.0")
    delta_vdm_dir = os.path.join(cache_path,"vdm",major_version, minor_version)
    engine_dir = os.path.join(cache_path,"engine",engine_version)

    os.makedirs(base_vdm_dir,exist_ok=True)
    os.makedirs(delta_vdm_dir,exist_ok=True)    
    os.makedirs(engine_dir,exist_ok=True)
    return


def move_files(signature_version,engine_version,source_dir,cache_path) -> None:
    major_version = ".".join(signature_version.split('.')[0:2])
    minor_version = ".".join(signature_version.split('.')[2:4])
    
    base_vdm_dir = os.path.join(cache_path,"vdm",major_version,"0.0")
    delta_vdm_dir = os.path.join(cache_path,"vdm",major_version, minor_version)
    engine_dir = os.path.join(cache_path,"engine",engine_version)

    # move base signature vmd
    shutil.move(os.path.join(source_dir,"mpasbase.vdm"),os.path.join(base_vdm_dir,"mpasbase.vdm"))
    shutil.move(os.path.join(source_dir,"mpavbase.vdm"),os.path.join(base_vdm_dir,"mpavbase.vdm"))

    # move delta signature vmd
    shutil.move(os.path.join(source_dir,"mpasdlta.vdm"),os.path.join(delta_vdm_dir,"mpasdlta.vdm"))
    shutil.move(os.path.join(source_dir,"mpavdlta.vdm"),os.path.join(delta_vdm_dir,"mpavdlta.vdm"))

    # move engine
    retry_count = 0
    while retry_count < 5:
        try:
            shutil.move(os.path.join(source_dir,"mpengine.dll"),os.path.join(engine_dir,"mpengine.dll"))
            break
        except PermissionError:
            time.sleep(1)
            retry_count += 1
    if retry_count == 5:
        logger.warning(f"Failed to move {os.path.join(source_dir,'mpengine.dll')}: PermissionError. (maybe due to antivirus scanning?)")
        #os.remove(os.path.join(source_dir,'mpengine.dll'))
    return


def get_latest_signature_vdm(proxy)->Tuple[str,str,str]:
    client = httpx.Client(proxy=proxy)
    res = client.head(DOWNLOAD_URL,follow_redirects=True)
    
    download_url = str(res.url)
    if re.match(URL_PATTERN_1,download_url):
        signature_version = download_url.split("/")[7]
        engine_version = download_url.split("/")[8]
        return download_url, signature_version, engine_version
    elif re.match(URL_PATTERN_2,download_url):
        m = re.match(URL_PATTERN_2,download_url)
        signature_version = m.groups()[0]
        engine_version = m.groups()[1]
        return download_url, signature_version, engine_version
    return None,None,None


def parse_mpam_exe(full_engine_path:str,cache_path:str,rm_mpam:bool) -> Tuple[str,str]:
    if not os.path.exists(full_engine_path):
        raise FileNotFoundError(f"mpam-fe.exe file not found: {full_engine_path}")
    if platform.system() == 'Windows':
        # extract cabarchive with windows expand command
        expand_mpam_fe(full_engine_path)
        source_dir = os.path.dirname(full_engine_path)
    else:
        # extract cabarchive with libarchive
        import libarchive
        libarchive.extract_file(full_engine_path)
        source_dir = os.path.curdir

    vdm_path = os.path.join(source_dir,"mpavdlta.vdm")
    engine_path = os.path.join(source_dir,"mpengine.dll")

    _, signature_version = Vdm.get_meta_info(vdm_path)
    _, engine_version = Vdm.get_meta_info(engine_path)

    # create cache dir
    create_cache_dir(signature_version,engine_version,cache_path)

    # move files
    move_files(signature_version,engine_version,source_dir,cache_path)

    # clean up
    files_to_remove = glob.glob("M?SigStub.exe",root_dir=source_dir)
    for file_path in files_to_remove:
        os.remove(os.path.join(source_dir,file_path))

    if rm_mpam:
        os.remove(full_engine_path)
    
    return signature_version,engine_version


def download_latest_signature(cache_path='cache',proxy=None) -> Tuple[str,str,bool]:
    use_cache = False
    os.makedirs(cache_path, exist_ok=True)
    download_url, signature_version, engine_version = get_latest_signature_vdm(proxy=proxy)
    if not download_url:
        raise ConnectionError(f"Failed to fetch Signature download URL:{DOWNLOAD_URL}")

    # check db files
    has_base_signature,\
    has_delta_signature,\
    has_engine = check_cached_signature(signature_version, engine_version, cache_path)

    if not (has_base_signature and has_delta_signature and has_engine):
        dl_file_path = download_file(download_url,proxy=proxy)
        if not os.path.exists(dl_file_path):
            raise FileNotFoundError(f"Download file not found: {dl_file_path}")
        signature_version,engine_version = parse_mpam_exe(dl_file_path,cache_path,rm_mpam=True)
    else:
        use_cache = True

    return signature_version,engine_version,use_cache
