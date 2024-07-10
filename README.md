![title](https://raw.githubusercontent.com/t-tani/defender2yara/main/img/logo_with_title_side.svg)

# defender2yara

`defender2yara` is a Python tool that converts Microsoft Defender Antivirus Signatures (VDM) into YARA rules. This tool facilitates the creation of custom YARA rules from the latest signature databases or manually provided .vdm files from Microsoft Defender, allowing for enhanced malware detection,analysis and threat hunting.

This project focuses solely on antivirus signatures and does NOT address EDR signatures or detection logic.

## Features

- Convert Microsoft Defender Antivirus Signatures (VDM) to YARA rules.
  - Supports strings and hex bytes pattern matching with regex-like expression
  - Supports to convert scoring rules into YARA conditions
- Download the latest signature database.
- Export YARA rules into a single file or files per malware family.
- Add file-header checks to the rules to optimize the scan with the generated YARA rules.
- Manually specify the paths for base and delta VDM files.

## Generated YARA rules 

Users can find the generated rules by `defender2yara` in the [*yara-rules*](https://github.com/t-tani/defender2yara/tree/yara-rules) branch.
This branch updates the rules every 30 minutes.

## Installation

Users can install `defender2yara` using `pip` or `Poetry`.

### Using `pip`

Ensure the user has Python 3.10 or later installed on the system. Users can install the tool using `pip`:

```sh
pip install defender2yara
```

### Using `Poetry`

1. Clone the GitHub repository:

```sh
git clone https://github.com/t-tani/defender2yara.git
```

2. Move to the cloned directory:

```sh
cd defender2yara
```

3. Install the dependencies using `Poetry`:

```sh
poetry install
```

## Usage

The following options are available for using `defender2yara`:

```txt
usage: defender2yara [options]

Convert Microsoft Defender Antivirus Signatures(VDM) to YARA rules.

options:
  -h, --help            show this help message and exit
  -v, --version         show defender2yara version
  -l, --latest_signature_version
                        show latest signature version
  -o OUTPUT, --output OUTPUT
                        output directory for YARA rules [default: ./rules]
  -d, --download        only download the latest signature database
  -c CACHE, --cache CACHE
                        directory to save signature database(vdm/dll files) [default: ./cache]
  -s, --single_file     export YARA rules into a single file
  --header_check        add file header check to generated YARA rules
  --full_engine FULL_ENGINE, --fe FULL_ENGINE
                        manually specify the path of mpam-fe.exe
  --base BASE           manually specify the path of mpa{v|s}base.vdm
  --delta DELTA         manually specify the path of mpa{v|s}dlta.vdm
  --proxy PROXY         use a proxy to download signatures (e.g. http://localhost:8000)
  --debug               print detailed logs
  --suppress            suppress all logs
```

## Examples

### Download and Convert the Latest Signatures to YARA Rules

To download the latest signature database and convert it to YARA rules, use the following command:

```sh
defender2yara
```

`defender2yara` generates the following files:

- ./rules/[signature_version]/[platform]/[malware_type]/[family_name].yara

If the user wants to change the directory from .rules, they can use the `--output` or `-o` option to specify the directory.


### Download the Latest Signature

To download the latest signature database, use the following command:

```sh
defender2yara -d
```

`defender2yara` downloads the latest signatures into the following directory:

- ./cache/vdm/[major_version]/0.0/mpa{s,v}base.vdm
- ./cache/vdm/[major_version]/[minor_version]/mpa{s,v}dlta.vdm
- ./cache/engine/[engine_version]/mpengine.dll

If the user wants to change the directory from .cache, they can use the `--cache` or `-c` option to specify their directory.

### Convert Signatures to a Single YARA File

To export the YARA rules into a single file, use the `--single_file` option:

```sh
defender2yara --single_file
```

`defender2yara` generates the following two files:

- ./rules/[signature_version]/anti-virus.yara
- ./rules/[signature_version]/anti-spyware.yara


### Add File Header Check to YARA Rules

To add file header checks to the generated YARA rules, use the `--header_check` option:

```sh
defender2yara --header_check
```

Currently, the `--header_check` option adds the following header checks to YARA rules that aim to detect the following files:

- PE File
- MACH-O File
- ELF File

### Manually Specify Signature Update File(mpam-fe.exe)

If the user wants to manually specify the paths of the mpam-fe.exe, use the `--fe` or `--full_engine` options:

```sh
defender2yara --fe /path/to/mpam-fe.exe
```

### Manually Specify Base and Delta VDM Files

If the user wants to manually specify the paths of the base and delta VDM files, use the `--base` and `--delta` options:

```sh
defender2yara --base /path/to/mpavbase.vdm --delta /path/to/mpavdlta.vdm
```

### Use a Proxy for Downloading Signatures

If the user needs to use a proxy to download the signatures, specify the proxy URL using the `--proxy` option:

```sh
defender2yara --proxy http://localhost:8000
```

### Debugging and Logging

Use the `--debug` option to show detailed logs. Use the `--suppress` option to suppress all logs.

```sh
defender2yara --debug
```

```sh
defender2yara --suppress
```

## Limitations

- Some regex-like pattern matching in Microsoft Defender cannot be fully converted due to:
  - Limitations of the YARA engine
  - Undocumented or unknown implementations within `mpengine.dll`
- Several advanced features of Microsoft Defender are not supported, such as:
  - Emulator engines
  - Logic implemented in Lua
  - Unpacker modules
  - And other proprietary technologies

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for details.

## Contributing

Contributions are welcome. Please submit a pull request or open an issue to discuss changes or improvements.

## Contact

For any questions or issues, please open an issue on [this GitHub repository](https://github.com/t-tani/defender2yara).

## Acknowledgments

This project would not have been possible without the valuable resources and insights provided by the following:

- **GitHub - commial/experiments** and **Windows Defender: Demystifying and Bypassing ASR by Understanding the AVS Signatures**: A special thanks to the author of the [commial/experiments](https://github.com/commial/experiments) repository on GitHub and the insightful paper [Windows Defender: Demystifying and Bypassing ASR by Understanding the AVS Signatures](https://i.blackhat.com/EU-21/Wednesday/EU-21-Mougey-Windows-Defender-demystifying-and-bypassing-asr-by-understanding-the-avs-signatures.pdf), presented at Black Hat Europe 2021. His work and research have significantly aided our understanding of various aspects of antivirus signatures and provided deep insights into the workings of Windows Defender signatures.

- **GitHub—taviso/loadlibrary**: A special thanks to Tavis Ormandy's repository [loadlibrary] (https://github.com/taviso/loadlibrary) on GitHub. This repository provided great insights into Microsoft Defender and was an entry point for reversing `msmpeng.dll`.

- **Retooling Blog**: We also appreciate the author of the Retooling blog for their detailed article [An Unexpected Journey into Microsoft Defender's Signature World](https://retooling.io/blog/an-unexpected-journey-into-microsoft-defenders-signature-world). Their exploration and documentation of Microsoft Defender's signature mechanisms have been invaluable to this project.

- **Threat Name Definitions**: We acknowledge Microsoft for their detailed [Threat Name Definitions](https://learn.microsoft.com/en-us/defender-xdr/malware-naming?view=o365-worldwide). This documentation has been essential in understanding the malware naming conventions used by Microsoft Defender.

Thank you to all these sources for contributing to the field and sharing their knowledge with the community.
