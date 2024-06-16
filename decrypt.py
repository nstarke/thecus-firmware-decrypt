#!/usr/bin/env python3
import argparse
import binascii
import ctypes
import magic
import pathlib
import sys
import threading

from ctypes.util import find_library

# ------------------------------------------------------------------------------- #

MODELS = [
    "N199",
    "N0204",
    "N299",
    "N0503",
    "N880U",
    "N1200",
    "N2100",
    "N2200",
    "N2200EVO",
    "N2310",
    "N2350",
    "N2520",
    "N2560",
    "N2800",
    "N2810",
    "N3200",
    "N3200XXX",
    "N3800",
    "N4100",
    "N4100EVO",
    "N4200",
    "N4310",
    "N4350",
    "N4510U",
    "N4520",
    "N4560",
    "N4800",
    "N4810",
    "N4820U",
    "N4910U",
    "N5550",
    "N5810",
    "N6850",
    "N7510",
    "N7700",
    "N8800",
    "N8810U",
    "N8850",
    "N8880U",
    "N8900",
    "N8900V",
    "N8910",
    "N10850",
    "N12000",
    "N12000V",
    "N12850",
    "N12850L",
    "N12850RU",
    "N12910",
    "N16000",
    "N16000V",
    "N16850",
    "N16910"
]

PREFIX = 1024 * 32

# ------------------------------------------------------------------------------- #

DES_cblock = ctypes.c_ubyte * 8
DES_LONG = ctypes.c_int

# ------------------------------------------------------------------------------- #

class ks(ctypes.Union):
    _fields_ = [('cblock', DES_cblock), ('deslong', DES_LONG * 2)]

# ------------------------------------------------------------------------------- #

class DES_key_schedule(ctypes.Structure):
    _fields_ = [('ks', ks * 16), ]

# ------------------------------------------------------------------------------- #

if sys.platform.startswith('win'):
    _library = ctypes.util.find_library('libeay32')
else:
    _library = ctypes.util.find_library('crypto')

if _library is None:
    raise OSError("Cannot find OpenSSL crypto library")

libcrypto = ctypes.CDLL(_library)

# ------------------------------------------------------------------------------- #

def des_string_to_key(str_key):
    key = DES_cblock()
    libcrypto.DES_string_to_key(str_key.encode(), ctypes.byref(key))
    return key

# ------------------------------------------------------------------------------- #

def try_decrypt(data, passphrase):
    key = des_string_to_key(passphrase)
    length = len(data)

    dataIN = ctypes.create_string_buffer(data, length)
    dataOUT = ctypes.create_string_buffer(length)

    iv = DES_cblock()
    key_schedule = DES_key_schedule()

    libcrypto.DES_set_odd_parity(ctypes.byref(key))
    libcrypto.DES_set_key_checked(
        ctypes.byref(key),
        ctypes.byref(key_schedule)
    )

    libcrypto.DES_ncbc_encrypt(
        ctypes.byref(dataIN),
        ctypes.byref(dataOUT),
        ctypes.c_int(length),
        ctypes.byref(key_schedule),
        ctypes.byref(iv),
        ctypes.c_int(0)
    )

    result = {
        'success': False,
        'passphrase': passphrase,
        'dataOUT': dataOUT
    }

    if dataOUT and 'gzip compressed data' in magic.from_buffer(dataOUT):
        print(f"Key is: {passphrase}")
        result['success'] = True

    threading.current_thread().result = result
    return result

# ------------------------------------------------------------------------------- #

def main():
    parser = argparse.ArgumentParser(
        prog="ThecusFirmwareDecrypt",
        description="decrypt thecus firmware"
    )
    parser.add_argument('filename')
    parser.add_argument('-t', '--try-key')
    args = parser.parse_args()

    p = pathlib.Path(args.filename)
    with open(p, 'rb') as infile:
        data = infile.read()

    models = list(set(MODELS + p.name.replace('.rom', '').split('_')))  # remove dupes

    # ------------------------------------------------------------------------------- #

    if args.try_key:
        print(f'Trying Passphrase: {args.try_key}')
        result = try_decrypt(data, args.try_key)
        if result['success']:
            print(f"Key: {args.try_key} Successful!")
            with open(f"{p.name}.decrypted.bin", 'wb') as w:
                w.write(result['dataOUT'])
        else:
            print(f"Key: {args.try_key} Unsuccessful.")
        exit(0)

    # ------------------------------------------------------------------------------- #

    partialKeys = []
    print("Trying partial file decrypt")
    for model in models:
        active = [
            threading.Thread(target=try_decrypt, args=(data[:PREFIX], model)),
            threading.Thread(target=try_decrypt, args=(data[:PREFIX], model.lower()))
        ]
        [t.start() for t in active]
        for t in active:
            t.join()
            if t.result['success']:
                partialKeys.append(t.result['passphrase'])

    # ------------------------------------------------------------------------------- #

    if not partialKeys:
        print('Failure to find a suitable key')
        exit(1)

# ------------------------------------------------------------------------------- #

if __name__ == "__main__":
    main()
