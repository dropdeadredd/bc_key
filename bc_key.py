import os
import sys
import struct
import hashlib
import base58

from bsddb3 import db

def open_wallet(path):
    dbp = db.DB()
    dbp.open(path, "main", db.DB_BTREE, db.DB_RDONLY)
    return dbp

def get_size(f):
    magic = ord(f.read(1))
    if magic < 253:
        return magic
    elif magic == 253:
        byte1 = ord(f.read(1))
        byte2 = ord(f.read(1))
        return (byte2 << 8) + byte1
    elif magic == 254:
        byte1 = ord(f.read(1))
        byte2 = ord(f.read(1))
        byte3 = ord(f.read(1))
        byte4 = ord(f.read(1))
        return (byte4 << 24) + (byte3 << 16) + (byte2 << 8) + byte1
    else:
        raise ValueError("Invalid size")

def get_string(f):
    size = get_size(f)
    return f.read(size)

def reverse_string(s):
    return s[::-1]

def sha256(data):
    return hashlib.sha256(data).digest()

def double_sha256(data):
    return sha256(sha256(data))

def ripemd160(data):
    return hashlib.new('ripemd160', data).digest()

def public_key_to_bc_address(key):
    digest1 = sha256(key)
    digest2 = ripemd160(digest1)
    prefix = b'\x00'
    final = prefix + digest2
    checksum = double_sha256(final)
    address = base58.b58encode(final + checksum[:4])
    return address.decode()

if __name__ == "__main__":
    dbp = open_wallet(sys.argv[1])
    cur = dbp.cursor()
    count = 0
    for k, v in cur:
        if k.startswith(b'tx'):
            print(f"Transaction: {k.decode()}")
            data = v[1:]
            offset = 0
            version = struct.unpack('<L', data[offset:offset+4])[0]
            offset += 4
            input_count = get_size(data[offset:])
            offset += 1
            for i in range(input_count):
                prev_output_hash = reverse_string(data[offset:offset+32])
                offset += 32
                prev_output_index = struct.unpack('<L', data[offset:offset+4])[0]
                offset += 4
                script_length = get_size(data[offset:])
                offset += 1 + script_length
                sequence = struct.unpack('<L', data[offset:offset+4])[0]
                offset += 4
            output_count = get_size(data[offset:])
            offset += 1
            for i in range(output_count):
                value = struct.unpack('<Q', data[offset:offset+8])[0]
                offset += 8
                script_length = get_size(data[offset:])
                offset += 1
                script = data[offset:offset+script_length]
                offset += script_length
                address = public_key_to_bc_address(script)
                print(f"Output: {address} {value/1e8} BTC")
                count += 1
    cur.close()
    dbp.close()
    print(f"{count} outputs found")
python
