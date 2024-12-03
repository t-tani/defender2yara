import sys
from defender2yara.defender.download import parse_mpam_exe

def main(full_engine_path):
    parse_mpam_exe(full_engine_path,cache_path="./cache",rm_mpam=False)

if __name__ == "__main__":
    main(sys.argv[1])