import sys
from defender2yara.defender.download import parse_full_engine_exe

def main(full_engine_path):
    parse_full_engine_exe(full_engine_path,cache_path="./cache",rm_full_engine=False)

if __name__ == "__main__":
    main(sys.argv[1])