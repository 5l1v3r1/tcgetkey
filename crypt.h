#ifndef _CRYPT_H
#define _CRYPT_H

void decrypt_serpent_xts(char *key1, char *key2, char *in, char *out, int len, int sector, int cur_block);
void decrypt_aes_xts(char *key1, char *key2, char *in, char *out, int len, int sector, int cur_block);
void decrypt_twofish_xts(char *key1, char *key2, char *in, char *out, int len, int sector, int cur_block);

#endif