from typing import Union

def hexdump(data, length=16):
    """
    Display a hexadecimal dump of byte data.

    Args:
        data (bytes): The byte data to be displayed.
        length (int): The number of bytes per line (default is 16).
    """
    def format_line(addr, line):
        hex_part = ' '.join(f'{byte:02x}' for byte in line)
        ascii_part = ''.join(chr(byte) if 32 <= byte < 127 else '.' for byte in line)
        return f'{addr:08x}  {hex_part:<{length * 3}}  {ascii_part}'

    for i in range(0, len(data), length):
        line = data[i:i + length]
        print(format_line(i, line))


def is_printable_ascii(data: Union[bytes,str]) -> bool:
    """
    Check if all characters in the byte data are printable ASCII characters.

    Args:
        data (bytes or str): The byte data to check.

    Returns:
        bool: True if all characters are printable ASCII, False otherwise.
    """
    if isinstance(data,bytes):
        return all(32 <= c <= 126 for c in data)
    elif isinstance(data,str):
        return all(32 <= ord(c) <= 126 for c in data)
    else:
        raise ValueError("Not supported type.")


def is_printable_utf16_le_ascii(byte_data:bytes) -> bool:
    """
    Check if the given byte data is encoded as UTF-16-LE and contains only ASCII characters.

    Args:
        byte_data (bytes): The byte data to check.

    Returns:
        bool: True if the byte data is UTF-16-LE encoded and contains only ASCII characters, False otherwise.
    """
    if len(byte_data) % 2 != 0:
        # Length of byte_data must be even for valid UTF-16 encoding
        return False
    try:
        # Decode the byte data using UTF-16-LE
        decoded_str = byte_data.decode('utf-16-le')
        
        # Check if all characters are ASCII
        return all(32 <= ord(c) <= 126 for c in decoded_str)
    except UnicodeDecodeError:
        # If decoding fails, it's not a valid UTF-16-LE encoding
        return False


def is_ascii(c:int) -> bool:
    """
    Check if the given integer value corresponds to an ASCII character.

    Args:
        c (int): The integer value to check.

    Returns:
        bool: True if the integer value corresponds to an ASCII character, False otherwise.
    """
    if c < 128:
        return True
    else:
        return False


def all_elements_equal(lst):
    """Check if all elements in the list are equal.

    Args:
        lst (list): A list of elements to be checked.

    Returns:
        bool: True if all elements are equal or the list is empty, False otherwise.
        
    Examples:
        >>> all_elements_equal([1, 1, 1, 1])
        True
        >>> all_elements_equal([1, 2, 1, 1])
        False
        >>> all_elements_equal([])
        True
    """
    if not lst: 
        return True
    first_element = lst[0]
    return all(element == first_element for element in lst)
