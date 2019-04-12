#include <stdlib.h>
#include <unistd.h>
#include <strings.h>
#include <openssl/aes.h>
#include "serpent.h"
#include "twofish.h"

void decrypt_serpent_xts(char *key1, char *key2, char *in, char *out, int len, int sector, int cur_block)
{
    uint8_t T[16], tweak[16];
    uint32_t i, m, mo, lim, t, tt;
    uint32_t x;
    SERPENT_KEY skey;

    m  = len >> 4;
    mo = len & 15;
    tweak[0]=(sector&255);
    tweak[1]=(sector>>8)&255;
    tweak[2]=(sector>>16)&255;
    tweak[3]=(sector>>24)&255;
    bzero(tweak+4,12);
    SERPENT_set_key((unsigned char *)key2,256,&skey);
    SERPENT_encrypt(&skey,(char *)tweak, (char *)T);

    if (mo == 0) lim = m;
    else lim = m - 1;

    for (i = 0; i < lim; i++) 
    {
        for (x = 0; x < 16; x += sizeof(uint64_t))
        *((uint64_t*)&out[i*16+x]) = *((uint64_t*)&in[i*16+x]) ^ *((uint64_t*)&T[x]);
        SERPENT_set_key((unsigned char *)key1,256,&skey);
        SERPENT_decrypt(&skey,out+i*16, (char *)out+i*16);
        for (x = 0; x < 16; x += sizeof(uint64_t)) 
        *((uint64_t*)&out[i*16+x]) ^=  *((uint64_t*)&T[x]);
        for (x = t = 0; x < 16; x++) 
        {
            tt = T[x] >> 7;
            T[x] = ((T[x] << 1) | t) & 0xFF;
            t = tt;
        }
        if (tt) 
        {
            T[0] ^= 0x87;
        }
    }
}



void decrypt_twofish_xts(char *key1, char *key2, char *in, char *out, int len, int sector, int cur_block)
{
    uint8_t T[16], tweak[16];
    uint32_t i, m, mo, lim, t, tt;
    uint32_t x;
    TWOFISH_KEY skey[40];

    m  = len >> 4;
    mo = len & 15;
    tweak[0]=(sector&255);
    tweak[1]=(sector>>8)&255;
    tweak[2]=(sector>>16)&255;
    tweak[3]=(sector>>24)&255;
    bzero(tweak+4,12);
    TWOFISH_set_key((unsigned char *)key2,256,skey);
    TWOFISH_encrypt(skey,(char *)tweak, (char *)T);

    if (mo == 0) lim = m;
    else lim = m - 1;

    for (i = 0; i < lim; i++) 
    {
        for (x = 0; x < 16; x += sizeof(uint64_t))
        *((uint64_t*)&out[i*16+x]) = *((uint64_t*)&in[i*16+x]) ^ *((uint64_t*)&T[x]);
        TWOFISH_set_key((unsigned char *)key1,256,skey);
        TWOFISH_decrypt(skey,out+i*16, (char *)out+i*16);
        for (x = 0; x < 16; x += sizeof(uint64_t)) 
        *((uint64_t*)&out[i*16+x]) ^=  *((uint64_t*)&T[x]);
        for (x = t = 0; x < 16; x++) 
        {
            tt = T[x] >> 7;
            T[x] = ((T[x] << 1) | t) & 0xFF;
            t = tt;
        }
        if (tt) 
        {
            T[0] ^= 0x87;
        }
    }
}


void decrypt_aes_xts(char *key1, char *key2, char *in, char *out, int len, int sector, int cur_block)
{
    uint8_t T[16], tweak[16];
    uint32_t i, m, mo, lim, t, tt;
    uint32_t x;
    char zeroiv[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
    AES_KEY aeskey;

    m  = len >> 4;
    mo = len & 15;
    tweak[0]=(sector&255);
    tweak[1]=(sector>>8)&255;
    tweak[2]=(sector>>16)&255;
    tweak[3]=(sector>>24)&255;
    bzero(tweak+4,12);

    AES_set_encrypt_key((unsigned char *)key2,256,&aeskey);
    AES_cbc_encrypt(tweak, T, 16, &aeskey, (unsigned char *)zeroiv, AES_ENCRYPT);

    if (mo == 0) lim = m;
    else lim = m - 1;

    for (i = 0; i < lim; i++) 
    {
        for (x = 0; x < 16; x += sizeof(uint64_t))
        *((uint64_t*)&out[i*16+x]) = *((uint64_t*)&in[i*16+x]) ^ *((uint64_t*)&T[x]);
        AES_set_decrypt_key((unsigned char *)key1,256,&aeskey);
        bzero(zeroiv,16);
        AES_cbc_encrypt((unsigned char *)out+i*16, (unsigned char *)out+i*16, 16, &aeskey, (unsigned char *)zeroiv, AES_DECRYPT);
        for (x = 0; x < 16; x += sizeof(uint64_t)) 
        *((uint64_t*)&out[i*16+x]) ^=  *((uint64_t*)&T[x]);
        for (x = t = 0; x < 16; x++) 
        {
            tt = T[x] >> 7;
            T[x] = ((T[x] << 1) | t) & 0xFF;
            t = tt;
        }
        if (tt)
        {
            T[0] ^= 0x87;
        }
    }
}
