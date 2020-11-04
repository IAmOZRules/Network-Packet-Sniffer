import textwrap

# Returns MAC as string from bytes (ie AA:BB:CC:DD:EE:FF)
def return_mac_address(mac_raw):
    byte_string = map('{:02x}'.format, mac_raw)
    mac = ':'.join(byte_string).upper()
    return mac


# formats the data into multiple-lines to make it easier to read
def format_output(prefix, string, size=80):                 # limits the output perline to 80 characters
    size -= len(prefix)

    # formatting happens here
    if isinstance(string, bytes):
        string = ''.join(r'\x{:02x}'.format(byte) for byte in string)
        if size % 2:
            size -= 1
    
    # returns the properly formatted output to be printed
    return '\n'.join([prefix + line for line in textwrap.wrap(string, size)])
