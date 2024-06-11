#!/usr/bin/env python3

import pyDes, argparse, pathlib, magic, threading, subprocess, binascii
MODELS = [
    'N2800',
    'N4800' ,
    'N5550' ,
    'N6850' ,
    'N7700' ,
    'N8800' ,
    'N8850'  ,
    'N8900'  ,
    'N8900V'  ,
    'N10850'  ,
    'N12000'  ,
    'N12000V'  ,
    'N16000' ,
    'N16000V' ,
    'N16910' ,
    'N16850' ,
    'N16000' ,
    'N12910' ,
    'N12850L' ,
    'N12850RU' ,
    'N12000' ,
    'N8900' ,
    'N12850' ,
    'N8910' ,
    'N8900' ,
    'N8880U' ,
    'N880U' ,
    'N8810U' ,
    'N4910U' ,
    'N4910U' ,
    'N4820U' ,
    'N5810' ,
    'N5810' ,
    'N4810' ,
    'N2810' ,
    'N2810' ,
    'N4350' ,
    'N2350' ,
    'N2100' ,
    'N3200' ,
    'N199' ,
    'N4100' ,
    'N0204' ,
    'N0503' ,
    'N2200' ,
    'N2200' ,
    'N2200EVO' ,
    'N2520' ,
    'N2560' ,
    'N4310' ,
    'N1200' ,
    'N299' ,
    'N3800' ,
    'N3200' ,
    'N2200' ,
    'N4200' ,
    'N3200XXX' ,
    'N4100EVO' ,
    'N4520' ,
    'N4560' ,
    'N2310' ,
    'N2800' ,
    'N4510U' ,
    'N4800' ,
    'N5550' ,
    'N7510' 
]

PREFIX = 1024 * 32

def des_string_to_key(str_key):
    out = subprocess.check_output("./string2key " + str_key, shell=True, text=True)
    return binascii.unhexlify(out)

def try_decrypt(data, passphrase):
    key = des_string_to_key(passphrase)
    des = pyDes.des(key, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None)
    result = des.decrypt(data)
    mtype = magic.from_buffer(result)
    if result and 'zip' in mtype:
        print("Key is: " + passphrase)
        exit(0)
    return result

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
    name = p.name
    models = MODELS + name.replace('.rom', '').split('_')
    
    if args.try_key:
        print('Trying Passphrase: ' + args.try_key)
        result = try_decrypt(data, args.try_key)
        if 'zip' in magic.from_buffer(result):
            print("Key: " + args.try_key + ' Successful!')
            with open(p.name + ".decrypted.bin", 'wb') as w:
                w.write(result)
            exit(0)
        else:
            print("Key: " + args.try_key + ' Unsuccessful.')
        
    print("Trying partial file decrypt")
    for model in models:
        active = []
        active.append(threading.Thread(target=try_decrypt, args=(data[:PREFIX], model)))
        active.append(threading.Thread(target=try_decrypt, args=(data[:PREFIX], model.lower())))
        for t in active:
            t.start()
        for t in active:
            t.join()
    print("Trying full file decrypt")

    
    for model in models:
        active = []
        print("Trying passphrase: " + model)
        active.append(threading.Thread(target=try_decrypt, args=(data, model)))
        active.append(threading.Thread(target=try_decrypt, args=(data, model.lower())))
        for t in active:
            t.start()
        for t in active:
            t.join()
    print('Failure to find a suitable key')
    exit(1)

if __name__ == "__main__":
    main()
