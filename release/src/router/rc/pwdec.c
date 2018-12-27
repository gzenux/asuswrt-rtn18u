#define _GNU_SOURCE
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
#include <rc.h>

#define AES_BITS 256
#define MSG_LEN 256
#define DEBUG_PWDEC 0

char *unbase64(unsigned char *input, int length);

char *unbase64(unsigned char *input, int length)
{
	BIO *b64, *bmem;

	char *buffer = (char *)malloc(length);
	memset(buffer, 0, length);

	b64 = BIO_new(BIO_f_base64());
	bmem = BIO_new_mem_buf(input, length);
	bmem = BIO_push(b64, bmem);

	BIO_read(bmem, buffer, length);

	BIO_free_all(bmem);

	return buffer;
}

int aes_decrypt(char* in, char* key, char* out)
{
	int i, len;

	if(!in || !key || !out) return 0;
	unsigned char iv[AES_BLOCK_SIZE];
	for(i=0; i<AES_BLOCK_SIZE; ++i)
		iv[i]=0;
	AES_KEY aes;
	if(AES_set_decrypt_key((unsigned char*)key, 128, &aes) < 0)
	{
        	return 0;
	}
	len = strlen(in);

	AES_cbc_encrypt((unsigned char*)in, (unsigned char*)out, len, &aes, iv, AES_DECRYPT);
	return 1;
}

char *pwdec(const char *input)
{
	unsigned char key[MD5_DIGEST_LENGTH];
	char router_ipaddr[17];
	int len;
	MD5_CTX mdContext;
	int i;

	char *output = unbase64((unsigned char*)input, strlen((char*)input));

	static char sourceStringTemp[MSG_LEN];
	char dstStringTemp[MSG_LEN];
	memset((char*)sourceStringTemp, 0 ,MSG_LEN);
	memset((char*)dstStringTemp, 0 ,MSG_LEN);
	strcpy((char*)dstStringTemp, output);

	MD5_Init (&mdContext);

	strcpy(router_ipaddr, nvram_safe_get("lan_ipaddr"));
	len = strlen(router_ipaddr);
        MD5_Update (&mdContext, router_ipaddr, len);
	MD5_Final (key,&mdContext);

	memset((char*)sourceStringTemp, 0 ,MSG_LEN);
	if(!aes_decrypt(dstStringTemp,(char *)key,sourceStringTemp))
	{
	    	printf("decrypt error\n");
	    	return NULL;
	}
#ifdef DEBUG_PWDEC
	printf("\n");
	printf("dec %d:",strlen((char*)sourceStringTemp));
	printf("%s\n",sourceStringTemp);
	for(i= 0;sourceStringTemp[i];i+=1){
		printf("%x",(unsigned char)sourceStringTemp[i]);
   	}
	printf("\n");
#endif
	return sourceStringTemp;
}

int calcDecodeLength(const char* b64input) { //Calculates the length of a decoded base64 string
  int len = strlen(b64input);
  int padding = 0;
 
  if (b64input[len-1] == '=' && b64input[len-2] == '=') //last two chars are =
    padding = 2;
  else if (b64input[len-1] == '=') //last char is =
    padding = 1;
 
  return (int)len*0.75 - padding;
}
 
int Base64Decode(char* b64message, char** buffer) { //Decodes a base64 encoded string
  BIO *bio, *b64;
  int decodeLen = calcDecodeLength(b64message),
      len = 0;
  *buffer = (char*)malloc(decodeLen+1);
  FILE* stream = fmemopen(b64message, strlen(b64message), "r");
 
  b64 = BIO_new(BIO_f_base64());
  bio = BIO_new_fp(stream, BIO_NOCLOSE);
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL); //Do not use newlines to flush buffer
  len = BIO_read(bio, *buffer, strlen(b64message));
    //Can test here if len == decodeLen - if not, then return an error
  (*buffer)[len] = '\0';
 
  BIO_free_all(bio);
  fclose(stream);
 
  return (0); //success
}

char *pwdec_dsl(char *input)
{

	char* base64DecodeOutput;
  	Base64Decode(input, &base64DecodeOutput);
	
	printf("pwdec_dsl base64DecodeOutput = %s\n",base64DecodeOutput);


	return base64DecodeOutput;
}

