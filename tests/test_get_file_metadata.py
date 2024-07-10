import os
import sys
import exiftool


def main(filepath):

    if not os.path.exists(filepath):
        raise FileNotFoundError

    with exiftool.ExifToolHelper() as ef:
        metadata = ef.get_metadata(filepath)[0]
    print(metadata['EXE:ProductVersion'])
    print(metadata['EXE:OriginalFileName'])


if __name__ == "__main__":
    main(sys.argv[1])