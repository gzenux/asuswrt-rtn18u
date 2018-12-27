#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/aes.h>
#include <openssl/md5.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <bcmnvram.h>
#include <shared.h>

#define AES_BITS 256
#define MSG_LEN 256
#define DEBUG_PWENC 0

char *base64(const unsigned char *input_t, int length);

char *base64(const unsigned char *input_t, int length)
{
	BIO *bmem, *b64;
	BUF_MEM *bptr;

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new(BIO_s_mem());
	b64 = BIO_push(b64, bmem);
	BIO_write(b64, input_t, length);
	BIO_flush(b64);
	BIO_get_mem_ptr(b64, &bptr);

	char *buff = (char *)malloc(bptr->length+1);
	memcpy(buff, bptr->data, bptr->length);
	buff[bptr->length] = 0;
	
	BIO_free_all(b64);

	return buff;
}




int aes_encrypt(char* in, char* key, char* out)
{
	int i, len;

	if(!in || !key || !out) return 0;
	unsigned char iv[AES_BLOCK_SIZE];
	for(i=0; i<AES_BLOCK_SIZE; ++i)
		iv[i]=0;
	AES_KEY aes;
	if(AES_set_encrypt_key((unsigned char*)key, 128, &aes) < 0)
	{
	        return 0;
	}
	len = strlen(in);

	AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_ENCRYPT);

	return 1;
}

char *pwenc(const char *input)
{
	unsigned char key[MD5_DIGEST_LENGTH];
	char router_ipaddr[17];
	int len;
	MD5_CTX mdContext;
	int i;

	char sourceStringTemp[MSG_LEN];
	char dstStringTemp[MSG_LEN];
	memset((char*)sourceStringTemp, 0 ,MSG_LEN);
	memset((char*)dstStringTemp, 0 ,MSG_LEN);
	strcpy((char*)sourceStringTemp, input);

	MD5_Init (&mdContext);

	strcpy(router_ipaddr, nvram_safe_get("lan_ipaddr"));
	len = strlen(router_ipaddr);
        MD5_Update (&mdContext, router_ipaddr, len);
	MD5_Final (key,&mdContext);

	if(!aes_encrypt(sourceStringTemp,(char *)key,dstStringTemp))
	{
		printf("encrypt error\n");
		return NULL;
	}
#ifdef DEBUG_PWENC
	printf("enc %d:",strlen((char*)dstStringTemp));
	for(i= 0;dstStringTemp[i];i+=1){
		printf("%x",(unsigned char)dstStringTemp[i]);
	}
		printf("\n");
#endif
	char *output = base64((const unsigned char *)dstStringTemp, strlen((char *)dstStringTemp));

	return output;
}

