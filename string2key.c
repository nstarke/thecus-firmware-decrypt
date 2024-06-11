     /* string2key: String to DES key
  * written by Adrian Sai-wah Tam
  * Thu Aug  9 17:27:33 HKT 2007
  * adapted by nick starke
  * Sun Jan 19 12:17:32 CDT 2020
  * original source from:
  * https://www.adrian.idv.hk/2007-08-08-firmware/
  *
  * Compile with
  *   gcc -o string2key string2key.c -lssl -lcrypto
  */


#include <openssl/des.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char** argv)
{
    DES_cblock key;
    int j;
    if (argc != 2) {
        printf("Synopsis:\n");
        printf("    %s [string]\n",argv[0]);
        printf("It will give the DES key from string using the OpenSSL's DES_string_to_key()\n");
        return 1;
    };
    DES_string_to_key(argv[1], &key);
    for (j=0;j<8;j++) {
        printf("%02x",key[j]);
    };
};
