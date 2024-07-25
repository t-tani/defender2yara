from typing import Tuple
import os
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

def parse_pe_resources(pe_file_path):
    """
    Parses the resources section of a PE file using the pefile library.

    Args:
        pe_file_path (str): The path to the PE file.

    Returns:
        dict: A dictionary containing the parsed resources.

    Raises:
        FileNotFoundError: If the PE file does not exist.
        pefile.PEFormatError: If the file is not a valid PE file.
    """
    resources = {}
    
    if not os.path.isfile(pe_file_path):
        raise FileNotFoundError(f"The PE file '{pe_file_path}' does not exist.")
    
    try:
        pe = pefile.PE(pe_file_path)
    except pefile.PEFormatError as e:
        raise pefile.PEFormatError(f"Error parsing PE file: {e}")
    
    if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            type_name = pefile.RESOURCE_TYPE.get(resource_type.struct.Id, str(resource_type.struct.Id))
            resources[type_name] = []
            
            if hasattr(resource_type, 'directory'):
                for resource_id in resource_type.directory.entries:
                    if hasattr(resource_id, 'directory'):
                        for resource_lang in resource_id.directory.entries:
                            data_rva = resource_lang.data.struct.OffsetToData
                            size = resource_lang.data.struct.Size
                            data = pe.get_memory_mapped_image()[data_rva:data_rva+size]
                            resources[type_name].append({
                                'ResourceId': resource_id.struct.Id,
                                'Language': resource_lang.struct.Id,
                                'Data': data
                            })
    else:
        raise ValueError("No resources found in the PE file.")
    return resources