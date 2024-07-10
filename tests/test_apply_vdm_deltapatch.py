import sys
import struct

from defender2yara.defender.vdm import Vdm

def main(base_path,delta_path):
    print("load base signature data")
    vdm = Vdm(base_path)
    print("start applying delta patch")
    vdm.apply_delta_vdm(delta_path)
    print(len(vdm.get_signatures()))


if __name__ == "__main__":
    main(sys.argv[1],sys.argv[2])