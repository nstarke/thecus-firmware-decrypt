# Introduction

In 2018, I did some research into decrypting [thecus nas devices](https://www.thecus.com/) and posted a [poorly assembled gist](https://gist.github.com/nstarke/eaba741a99049430bdcb74f1b4ebc651).  

This repository contains a more standardized version of the source code.

# Step 1: Build the string2key binary

```
sudo apt install libssl-dev
gcc -o string2key string2key.c -lssl -lcrypto
```

# Step 2: Bruteforce!

```
python3 decrypt.py $FILENAME
```

This will output the proper key, which you will then use in step 3

# Step 3: dump decrypted data

```
python3 decrypt.py -t N16000 $FILENAME
```

Where `N16000` is an example of the key returned in the output of step 2

Enjoy!

# Step 4: decrypt with openssl

The pyDes implementation used in this script is very, very slow.  If you want to decrypt faster, you can use openssl:

```
OPENSSL_CONF=openssl_legacy.cnf openssl des-cbc -d -in $FILENAME -out $FILENAME.decrypted.bin -iv 00000000000000000 -K $(./string2key N16000) -nopad -nosalt
```

The OPENSSL_CONF file provided with this cnf file enables legacy ciphers, such as DES-CBC.  I highly recommend not adding this to your standard openssl.cnf file.