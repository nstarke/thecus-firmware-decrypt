# Introduction

In 2018, I did some research into decrypting [thecus nas devices] and posted a [poorly assembled gist](https://gist.github.com/nstarke/eaba741a99049430bdcb74f1b4ebc651).  

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

Where `N16000` is the key returned in the output of step 2

Enjoy!