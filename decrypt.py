#!/usr/bin/env python3

import pyDes, argparse, pathlib, magic, threading

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

PREFIX = 1024 * 1024

def try_decrypt(data, passphrase):
    if len(passphrase) != 8:
        print('Invalid Passphrase')
        return None
    des = pyDes.des(passphrase, pyDes.CBC, b"\0\0\0\0\0\0\0\0", pad=None, padmode=pyDes.PAD_NORMAL)
    result = des.decrypt(data)
    if result and 'zip' in magic.from_buffer(result):
        print("Key is: " + passphrase + ' ljust')
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
        result = try_decrypt(data, args.try_key.rjust(8, '\x00'))
        if magic.from_buffer(result) != 'data':
            print("Key (RJUST): " + args.try_key + ' Successful!')
            with open(p.name + ".decrypted.bin", 'wb') as w:
                w.write(result)
            return
        else:
            print("Key (RJUST): " + args.try_key + ' Unsuccessful.')
        
        result = try_decrypt(data, args.try_key.ljust(8, '\x00'))
        if magic.from_buffer(result) != 'data':
            print("Key (LJUST): " + args.try_key + ' Successful!')
            with open(p.name + ".decrypted.bin", 'wb') as w:
                w.write(result)
            return
        else:
            print("Key (LJUST): " + args.try_key + ' Unsuccessful.')
        return

    print("Trying partial file decrypt")
    active = []
    for model in models:
        print("Trying passphrase: " + model)
        active.append(threading.Thread(target=try_decrypt, args=(data[:PREFIX], model.ljust(8, '\x00'))))
        active.append(threading.Thread(target=try_decrypt, args=(data[:PREFIX], model.rjust(8, '\x00'))))
        active.append(threading.Thread(target=try_decrypt, args=(data[:PREFIX], model.lower().ljust(8, '\x00'))))
        active.append(threading.Thread(target=try_decrypt, args=(data[:PREFIX], model.lower().rjust(8, '\x00'))))
    
    print("Trying full file decrypt")

    for t in active:
        t.join()
    active = []
    for model in models:
        print("Trying passphrase: " + model)
        active.append(threading.Thread(target=try_decrypt, args=(data, model.ljust(8, '\x00'))))
        active.append(threading.Thread(target=try_decrypt, args=(data, model.rjust(8, '\x00'))))
        active.append(threading.Thread(target=try_decrypt, args=(data, model.lower().ljust(8, '\x00'))))
        active.append(threading.Thread(target=try_decrypt, args=(data, model.lower().rjust(8, '\x00'))))
    
    for t in active:
        t.join()
    print('Failure to find a suitable key')
    exit(1)

if __name__ == "__main__":
    main()
