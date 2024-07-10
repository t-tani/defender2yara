import sys
from .main import main
import toml
from pathlib import Path

from defender2yara.util.logging import setup_logger, suppress_logging


def get_version():
    pyproject_path = Path(__file__).parent.parent / 'pyproject.toml'
    pyproject_data = toml.load(pyproject_path)
    return pyproject_data['tool']['poetry']['version']

def run():
    import argparse
    parser = argparse.ArgumentParser(
        description="Convert Microsoft Defender Antivirus Signatures(VDM) to YARA rules.",
        usage="defender2yara [options]")

    parser.add_argument('-v', '--version', action='store_true', help="show defender2yara version")
    parser.add_argument('-l','--latest_signature_version', action='store_true', default=False, help="show latest signature version")
    parser.add_argument('-o','--output', default='./rules',help="output directory for YARA rules [default: ./rules]" )
    parser.add_argument('-d','--download',action='store_true' ,required=False,default=False,help="only download the latest signature database")
    parser.add_argument('-c','--cache', default='./cache',help="directory to save signature database(vdm/dll files) [default: ./cache]" )
    parser.add_argument('-s','--single_file',action='store_true',default=False,help="export YARA rules into a single file")
    parser.add_argument('--header_check',action='store_true',default=False,help="add file header check to generated YARA rules")
    parser.add_argument('--full_engine','--fe',required=False,type=str,help="manually specify the path of mpam-fe.exe")
    parser.add_argument('--base',required=False,type=str,help="manually specify the path of mpa{v|s}base.vdm")
    parser.add_argument('--delta',required=False,type=str,help="manually specify the path of mpa{v|s}dlta.vdm")
    parser.add_argument('--proxy',help="use a proxy to download signatures (e.g. http://localhost:8000)")
    parser.add_argument('--debug', action='store_true', default=False, help="print detailed logs")
    parser.add_argument('--suppress', action='store_true', default=False, help="suppress all logs")
    
    args = parser.parse_args()
    
    if args.version:
        print(f"version: {get_version()}")
        sys.exit(0)

    if args.base and args.download:
        sys.stderr.write("[!] --download option and --base option can not use together.")
        parser.print_help()
        sys.exit(1)
    
    if args.download and args.full_engine:
        sys.stderr.write("[!] --download option and --fe option can not use together.")
        parser.print_help()
        sys.exit(1)
    
    if args.full_engine and (args.base or args.delta):
        sys.stderr.write("[!] --fe option and --base or --delta option can not use together.")
        parser.print_help()
        sys.exit(1)
    
    if args.delta and not args.base:
        sys.stderr.write("[!] --delta option requires --base option.")
        parser.print_help()
        sys.exit()

    if args.suppress and args.debug:
        sys.stderr.write("[!] --suppress option and --debug option can not use together.")
        parser.print_help()
        sys.exit(1)

    setup_logger(__package__, args.debug)

    if args.suppress:
        suppress_logging(__package__)

    main(args)


if __name__ == "__main__":
    run()