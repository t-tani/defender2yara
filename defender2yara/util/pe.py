from typing import Tuple
import pefile

import logging

logger = logging.getLogger(__package__)

def format_version(version: int) -> str:
    """
    Format a PE version into a string.

    Args:
        version (int): The PE version to format.

    Returns:
        str: The formatted version string.
    """
    major = version >> 16
    minor = version & 0xFFFF
    return f"{major}.{minor}"

def parse_pe_meta_info(pe_file_path: str) -> Tuple[str,str]:
    """
    Parse the metadata from a PE file.

    Args:
        pe_file_path (str): The path to the PE file.

    Returns:
        Tuple[Optional[str], Optional[str]]: A tuple containing the original filename and product version.
        If an error occurs, returns ("", "").
    """
    try:
        pe = pefile.PE(pe_file_path)
        # get product version info
        if hasattr(pe, 'VS_FIXEDFILEINFO'):
            version_info = pe.VS_FIXEDFILEINFO[0]
            version_data = {
                "ProductVersionMS": version_info.ProductVersionMS,
                "ProductVersionLS": version_info.ProductVersionLS,
            }
            product_version = \
                format_version(version_data["ProductVersionMS"]) + \
                "." + \
                format_version(version_data["ProductVersionLS"])
        else:
            product_version = None
        
        # get original filename
        original_filename = None
        for file_info in pe.FileInfo:
            for entry in file_info:
                if hasattr(entry, "StringTable"):
                    for st_entry in entry.StringTable:
                        for key, entry in list(st_entry.entries.items()):
                            #offsets = st_entry.entries_offsets[key]
                            lengths = st_entry.entries_lengths[key]
                            st_data: str
                            if len(entry) > lengths[1]:
                                st_data = entry.decode("utf-8")
                            else:
                                st_data = entry.decode("utf-8")
                            if st_data.endswith((".exe", ".dll", ".vdm")):
                                original_filename = st_data
        return original_filename, product_version
    except Exception as e:
        logger.warning(f"Failed to parse metadata from PE file. Error: {e}")
        raise e