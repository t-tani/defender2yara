from defender2yara.util.pe import parse_pe_meta_info

def main():
    pe_file_paths = [
        './mpam-fe.exe',
        './cache/vdm/1.415/0.0/mpasbase.vdm',
        './cache/vdm/1.415/231.0/mpasdlta.vdm',
        './cache/engine/1.1.14104.0/mpengine.dll'
    ]
    for pe_file_path in pe_file_paths:
        print(pe_file_path)
        original_filename, product_version = parse_pe_meta_info(pe_file_path)
        if product_version:
            print(f"Product Version: {product_version}")
        else:
            print("Version information not found or the PE file is invalid.")
        
        if original_filename:
            print(f"Original Filename: {original_filename}")
        else:
            print("Original filename not found.")
        print("---")


if __name__ == "__main__":
    main()
