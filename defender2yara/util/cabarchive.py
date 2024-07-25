import os
import subprocess
from defender2yara.util.pe import parse_pe_resources

CAB_SIGNATURE = b'MSCF'


def expand_cab(cab_file_path):
    """
    Expands a CAB file using the Windows 'expand' command.

    Args:
        cab_file_path (str): The path to the CAB file.

    Raises:
        FileNotFoundError: If the CAB file does not exist.
        subprocess.CalledProcessError: If the expand command fails.
    """
    if not os.path.isfile(cab_file_path):
        raise FileNotFoundError(f"The CAB file '{cab_file_path}' does not exist.")
    
    output_dir = os.path.dirname(cab_file_path)

    command = ['expand', cab_file_path, '-F:*', output_dir]
    
    try:
        result = subprocess.run(command, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        # print(result.stdout.decode("shift-jis"))
    except subprocess.CalledProcessError as e:
        print(f"Error expanding CAB file: {e.stderr.decode()}")
        raise e

def expand_mpam_fe(path):
    """
    Expand mpam-fe.exe using the Windows 'expand' command.

    Args:
        path (str): The path to the mpam-fe.exe file.
    """
    resources = parse_pe_resources(path)
    for resource in resources.values():
        for res in resource:
            if res['Data'][:4] == CAB_SIGNATURE:
                cab_data = res['Data']
    tmp_cab = os.path.join(os.path.dirname(path),"tmp.cab")
    with open(os.path.join(os.path.dirname(path),"tmp.cab"),"wb") as f:
        f.write(cab_data)
    expand_cab(tmp_cab)
    os.remove(tmp_cab)
