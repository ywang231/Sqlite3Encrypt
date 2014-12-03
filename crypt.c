#include "crypt.h"
//#include "malloc.h"
//#include "aes.h"
#include "aeslib.h"
#include <stdlib.h>

#define KEY_LENGHT 256
#define BLOCK_SIZE 16

//static aes_context _Gctx;

int My_Encrypt_Func(unsigned char * pData, unsigned int data_len,
                    unsigned char * key, unsigned int len_of_key)
{
    return aes_encrypt(pData, data_len, key, len_of_key);
}

int My_DeEncrypt_Func(unsigned char * pData, unsigned int data_len,
                      
                      unsigned char * key, unsigned int len_of_key)
{
    return aes_decrypt(pData, data_len, key, len_of_key);
}

int aes_encrypt(unsigned char* pData, unsigned int data_len,
                unsigned char* key, unsigned int len_of_key)
{
    encryptECB(pData, data_len, key, len_of_key);
    return 0;
}

int aes_decrypt(unsigned char* pData, unsigned int data_len,
                unsigned char* key, unsigned int len_of_key)
{
    decryptECB(pData, data_len, key, len_of_key);
    return 0;
}

/*int aes_encrypt(unsigned char* pData, unsigned int data_len,
	unsigned char* key, unsigned int len_of_key)
{
	int i, count, offset;
	unsigned char* sour = (unsigned char*)malloc(data_len);
	memcpy(sour, pData, data_len);
    printf("\naes encrypt key:::       %s \n",key);

	count = data_len / BLOCK_SIZE;
	aes_setkey_enc(&_Gctx, key, KEY_LENGHT);
	for(i = 0; i < count; i++)
	{
		offset = i * BLOCK_SIZE;
		if(aes_crypt_ecb(&_Gctx, AES_ENCRYPT, (const unsigned char*)sour + offset, pData + offset))
        {
            printf("aes_ecb_ENCRYPT erro");
        };
	}
	free(sour);
	return 0;
}

int aes_decrypt(unsigned char* pData, unsigned int data_len,
	unsigned char* key, unsigned int len_of_key)
{
	int i, count, offset;
	unsigned char* sour = (unsigned char*)malloc(data_len);
	memcpy(sour, pData, data_len);
    printf("\naes decrypt key:::       %s \n",key);
	count = data_len / BLOCK_SIZE;
	aes_setkey_dec(&_Gctx, key, KEY_LENGHT);
	for(i = 0; i < count; i++)
	{
		offset = i * BLOCK_SIZE;
         if(aes_crypt_ecb(&_Gctx, AES_DECRYPT, (const unsigned char*)sour + offset, pData + offset))
         {
             printf("aes_ecb_decrypt error");
         }
	}
	free(sour);
	return 0;
}*/