import sys

from defender2yara.defender.vdm import Vdm


def main(path):
    data = Vdm.extract_vdm_data(path)
    with open(f"{path}.extracted",'wb') as f:
        f.write(data)
        print(f"[+] write data to {path}.extracted")


if __name__ == "__main__":
    main(sys.argv[1])