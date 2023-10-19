import sys

if len(sys.argv) < 2:
    print("Usage: %s <shellcode_file>" % sys.argv[0])
    sys.exit(1) 

key = 0x42  # XOR key

with open(sys.argv[1], "rb") as f:
    chunk = f.read(6)
    print("const MAC: &[&str] = &[")

    while chunk:
        if len(chunk) < 6:
            padding = 6 - len(chunk)
            chunk = chunk + (b"\x90" * padding)
        
        xor_chunk = bytes(b ^ key for b in chunk)
        mac_address = "-".join("{:02X}".format(x) for x in xor_chunk)
        print(f'    "{mac_address}",')

        if len(chunk) < 6:
            break

        chunk = f.read(6)

    print("];")
