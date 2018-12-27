/**
   @copyright
   Copyright (c) 2007 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/* Perform zero-copying handling of packet data if possible. This define
   should only be enabled on environments where packet data can be assumed
   to be from DMA'able memory. This parameter cannot be enabled on non-Linux
   platforms. */
#undef SSH_SAFENET_PACKET_IS_DMA
#ifdef __linux__
#include "linux_internal.h"
#define SSH_SAFENET_PACKET_IS_DMA
#endif /* __linux__ */

#include "sshincludes.h"
#include "engine_hwaccel.h"
#include "interceptor.h"
#include "kernel_mutex.h"
#include <crypto/cryptodev.h>


#define SSH_DEBUG_MODULE "SshEngineHwaccelOcf"
#define SSH_OCF_DEVICETYPE 0 /* Hardware(1) OR Software(0) device */
#define SSH_OCF_MAX_QUEUED_OPERATIONS 390

#define SSH_OCF_MAX_MODP_INPUT 256
#define SSH_OCF_MAX_MODP_OUTPUT 256
#define BASE 0
#define EXP  1
#define MOD  2
#define RES  3

#define OCF_PK_SUCCESS 0
struct SshOcfPacketOperationRec
{
  SshInterceptorPacket pp;
  SshHWAccelCompletion completion;
  void *completion_context;
  size_t encrypt_iv_offset;
  struct cryptop *crp;
};
typedef struct SshOcfPacketOperationRec *SshOcfPacketOperation;

struct SshHWAccelRec
{
  Boolean for_mac;
  Boolean for_encryption;
  Boolean encrypt;
  size_t iv_len;
  SshUInt64 sid;           /* Session Identifier for the context */
  struct cryptoini crie;   /* OCF initialization structure for ciphers */
  struct cryptoini cria;   /* OCF initialization structure for hash */
  Boolean hardware;        /* Hardware(1) OR Software(0) device */
  SshInterceptor interceptor;
  char enc_key[SSH_IPSEC_MAX_ESP_KEY_BITS];
  char mac_key[SSH_IPSEC_MAX_MAC_KEY_BITS];
};

struct SshOcfPKOperationRec
{
  struct cryptkop krp;
  void *context;
  SshHWAccelModPCompletion callback;
  unsigned char base[SSH_OCF_MAX_MODP_INPUT];
  unsigned char exp[SSH_OCF_MAX_MODP_INPUT];
  unsigned char mod[SSH_OCF_MAX_MODP_INPUT];
  unsigned char res[SSH_OCF_MAX_MODP_OUTPUT];
  struct SshOcfPKOperationRec *next;
  struct SshOcfPKOperationRec *prev;
};

typedef struct SshOcfPKOperationRec *SshOcfPKOperation;

/*********************** LINKED LIST *******************************/
static SshOcfPKOperation ocfpkq_head = NULL;
static SshOcfPKOperation ocfpkq_tail = NULL;
static SshKernelMutex ocfpkq_mutex = NULL;
void ocf_pkq_add_elm(SshOcfPKOperation op)
{

  ssh_kernel_mutex_lock(ocfpkq_mutex);
  if (!ocfpkq_head && !ocfpkq_tail)
    {
      ocfpkq_head = op;
      ocfpkq_tail = op;
      op->prev = NULL; /*1st element therefore no previous element */
    }
  else
    {
      ocfpkq_tail->next = op;
      op->prev = ocfpkq_tail;
      ocfpkq_tail = op;
    }
  op->next = NULL;
  ssh_kernel_mutex_unlock(ocfpkq_mutex);
  return;
}
void ocf_pkq_remove_elm(SshOcfPKOperation op)
{
  SshOcfPKOperation temp1, temp2;

  SSH_ASSERT(op != NULL); /* Element Should be present */
  ssh_kernel_mutex_lock(ocfpkq_mutex);
  temp1 = op->prev;
  temp2 = op->next;
  if (temp2 == NULL)
    {
      if (temp1 == NULL) /* op is the only element in list */
	{
	  ocfpkq_head = NULL;
	  ocfpkq_tail = NULL;
	}
      else /* op is last element in list*/
	{
	  temp1->next = NULL;
	}
    }
  else if ( temp1 == NULL ) /* op is the 1st element in list */
    {
      ocfpkq_head = temp2;
      temp2->prev = NULL ;
    }
  else /*op in middle element in list*/
    {
      temp1->next = temp2;
      temp2->prev = temp1;
    }
  ssh_kernel_mutex_unlock(ocfpkq_mutex);
  SSH_DEBUG(SSH_D_NICETOKNOW,("Ocf PK op element removed successfully"));
  ssh_free(op);
  return;
}


SshOcfPKOperation ocf_pkq_find_elm(struct cryptkop *kop)
{
  SshOcfPKOperation temp;

  ssh_kernel_mutex_lock(ocfpkq_mutex);
  temp = ocfpkq_head;
  if (!temp)
    {
      ssh_kernel_mutex_unlock(ocfpkq_mutex);
      return NULL; /* List is empty */
    }
  while (temp)
    {
      if (kop == &(temp->krp))
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW,("Found the cryptkop element in PKQ"));
	  ssh_kernel_mutex_unlock(ocfpkq_mutex);
	  return temp;
	}
      temp = temp->next;
    }

  ssh_kernel_mutex_unlock(ocfpkq_mutex);
  return NULL; /* Did not find the element */
}

Boolean ocf_pkq_mutex_alloc(void)
{
  ocfpkq_mutex = ssh_kernel_mutex_alloc();
  if (ocfpkq_mutex == NULL)
    return FALSE;
  else
    return TRUE;
}
void ocf_pkq_mutex_free()
{
  if (ocfpkq_mutex)
    ssh_kernel_mutex_free(ocfpkq_mutex);
}


static void endian_swap(unsigned char *to, const unsigned char *from,
                        int len)
{
  int i;

  for (i = 0; i < len; i++)
    {
      *(to + i) = *(from + len - 1 - i);
    }
}

/*********************** FREE LIST *******************************/
static SshOcfPacketOperation op_freelist = NULL;
static SshKernelMutex op_freelist_mutex;
static SshHWAccel accel_freelist = NULL;
static SshKernelMutex accel_freelist_mutex;

void ocf_freelist_free(void *list)
{
  void *next;

  SSH_DEBUG(SSH_D_HIGHOK, ("Entered"));

  while (list)
    {
      next = *((void **)list);
      ssh_free(list);
      list = next;
    }
}

void *ocf_freelist_alloc(int number_of, int size)
{
  void *list = NULL;
  void *item;
  int i;

  SSH_DEBUG(SSH_D_HIGHOK, ("Entered"));

  for (i = 0; i < number_of; i++)
    {
      item = ssh_calloc(1, size);
      if (!item)
        {
          ocf_freelist_free(list);
          return NULL;
        }

      *((void **)item) = list;
      list = item;
    }

  return list;
}

#define OCF_FREELIST_GET_NO_LOCK(item, list)            \
do                                                      \
  {                                                     \
    (item) = (void *)(list);                            \
    if (list)                                           \
      (list) = *((void **)(item));                      \
  }                                                     \
while (0)

#define OCF_FREELIST_GET(item, list, mutex)             \
do                                                      \
  {                                                     \
    ssh_kernel_mutex_lock(mutex);                       \
    OCF_FREELIST_GET_NO_LOCK(item, list);               \
    ssh_kernel_mutex_unlock(mutex);                     \
  }                                                     \
while (0)

#define OCF_FREELIST_PUT_NO_LOCK(item, list)            \
do                                                      \
  {                                                     \
    *((void **)(item)) = (list);                        \
    (list) = (void *)(item);                            \
  }                                                     \
while (0)

#define OCF_FREELIST_PUT(item, list, mutex)             \
do                                                      \
  {                                                     \
    ssh_kernel_mutex_lock(mutex);                       \
    OCF_FREELIST_PUT_NO_LOCK(item, list);               \
    ssh_kernel_mutex_unlock(mutex);                     \
  }                                                     \
while (0)

void ocf_operation_freelist_free()
{
  ocf_freelist_free(op_freelist);

  if (op_freelist_mutex)
    ssh_kernel_mutex_free(op_freelist_mutex);
}

Boolean ocf_operation_freelist_alloc()
{
  op_freelist_mutex = ssh_kernel_mutex_alloc();
  if (op_freelist_mutex == NULL)
    return FALSE;

  op_freelist = (struct SshOcfPacketOperationRec *)ocf_freelist_alloc(
    SSH_OCF_MAX_QUEUED_OPERATIONS, sizeof(struct SshOcfPacketOperationRec));

  if (op_freelist == NULL)
    {
      ssh_kernel_mutex_free(op_freelist_mutex);
      return FALSE;
    }
  else
    {
      return TRUE;
    }
}

#define OCF_OPERATION_FREELIST_GET(op)                 \
  OCF_FREELIST_GET(op, op_freelist, op_freelist_mutex)

#define OCF_OPERATION_FREELIST_PUT(op)                 \
  OCF_FREELIST_PUT(op, op_freelist, op_freelist_mutex)

void ocf_hwaccel_freelist_free(void)
{
  ocf_freelist_free(accel_freelist);

  if (accel_freelist_mutex)
    ssh_kernel_mutex_free(accel_freelist_mutex);
}

Boolean ocf_hwaccel_freelist_alloc(void)
{
  accel_freelist_mutex = ssh_kernel_mutex_alloc();

  if (accel_freelist_mutex == NULL)
    return FALSE;

  accel_freelist = (struct SshHWAccelRec *)ocf_freelist_alloc(
    SSH_ENGINE_MAX_TRANSFORM_CONTEXTS, sizeof(struct SshHWAccelRec));

  if (accel_freelist == NULL)
    {
      ssh_kernel_mutex_free(accel_freelist_mutex);
      return FALSE;
    }
  else
    {
      return TRUE;
    }
}

#define OCF_HWACCEL_FREELIST_GET(accel)                         \
  OCF_FREELIST_GET(accel, accel_freelist, accel_freelist_mutex)

#define OCF_HWACCEL_FREELIST_PUT(accel)                         \
  OCF_FREELIST_PUT(accel, accel_freelist, accel_freelist_mutex)

/*******************************************************/
/* Allocates a hardware acceleration context for IPSEC transformations
   (or more generally, encryption and/or message authentication
   transformations).  The allocated context can be used for
   encryption/decryption, message authentication, or both in a single
   operation.  If both are performed in a single operation, encryption
   is always performed before message authentication, and decryption
   after message authentication. */
SshHWAccel ssh_hwaccel_alloc_ipsec(SshInterceptor interceptor,
                                   Boolean  encrypt,
                                   const char *cipher_name,
                                   const unsigned char *cipher_key,
                                   size_t cipher_key_len,
                                   const unsigned char *cipher_iv,
                                   size_t cipher_iv_len,
                                   Boolean ah_style_mac,
                                   const char *mac_name,
                                   const unsigned char *mac_key,
                                   size_t mac_key_len)
{
  SshHWAccel accel = (SshHWAccel) NULL;
  SshUInt16 ciph_alg = 0; /* contains CIPHER + MODE as well */
  SshUInt16 hash_alg = 0;
  Boolean error = 1;

  if (!interceptor)
    return NULL;

  /* Allocate the acceleration (session) context */
  OCF_HWACCEL_FREELIST_GET(accel);
  if (!accel)
    {
      SSH_DEBUG(SSH_D_FAIL, ("unable to allocate accel."));
      return NULL;
    }

  memset(accel, 0, sizeof(*accel));
  accel->interceptor = interceptor;
  accel->iv_len = 0;

  /* Get the ESP cipher algorithm */
  if (cipher_name && strcmp(cipher_name, "none"))
    {
      if (!strcmp(cipher_name, "3des-cbc"))
	{
	  ciph_alg = CRYPTO_3DES_CBC;
	  accel->iv_len = 8;
	}
      else if (!strcmp(cipher_name, "des-cbc"))
	{
	  ciph_alg = CRYPTO_DES_CBC;
	}
      else if (!strcmp(cipher_name, "aes-cbc"))
	{
	  ciph_alg = CRYPTO_AES_CBC;
	  accel->iv_len = 16;
	}
      else
	{
	  SSH_DEBUG(SSH_D_FAIL, ("Unsupported Cipher algorithm %s",
				 cipher_name));
	  goto fail;
	}

      accel->crie.cri_alg = ciph_alg;
      accel->crie.cri_klen = cipher_key_len * 8; /* Key Len is in Bits */

      if (cipher_key != NULL)
	{
	  memcpy(accel->enc_key,cipher_key,cipher_key_len);
	  accel->crie.cri_key = accel->enc_key;
	}

      if (cipher_iv_len)
	{
	  accel->iv_len = cipher_iv_len;
	  memcpy(accel->crie.cri_iv, cipher_iv, cipher_iv_len);
	}
    }
  else
    {
      ciph_alg = 0;
    }

  /* Get the mac algorithm */
  if (mac_name)
    {
      if (!strcmp(mac_name, "hmac-sha1"))
	{
	  hash_alg = CRYPTO_SHA1;
	  accel->cria.cri_mlen = 0;  /* Byte to copy from entire Hash,
					0 means all */
	}
      else if (!strcmp(mac_name, "hmac-sha1-96"))
	{
	  hash_alg = CRYPTO_SHA1_HMAC;
	  accel->cria.cri_mlen = 12;  /* Bytes to copy from entire Hash */
	}
      else if (!strcmp(mac_name, "hmac-md5-96"))
	{
	  hash_alg = CRYPTO_MD5_HMAC;
	  accel->cria.cri_mlen = 12; /* Bytes to copy from entire Hash */
	}
      else if (!strcmp(mac_name, "none"))
	{
	  hash_alg = 0;
	}
      else
     	{
	  SSH_DEBUG(SSH_D_FAIL, ("Unsupported MAC algorithm %s", mac_name));
	  goto fail;
	}

      accel->cria.cri_alg = hash_alg;
      accel->cria.cri_klen = mac_key_len * 8; /* Key Len is in Bits */

      if (mac_key != NULL)
	{
	  memcpy(accel->mac_key, mac_key, mac_key_len);
	  accel->cria.cri_key = accel->mac_key;
	}
    }

  /* Verify we don't have both null cipher and null mac */
  if (hash_alg == 0 && ciph_alg == 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("Cannot have both null cipher and null mac"));
      ssh_free(accel);
      return NULL;
    }

  if (hash_alg != 0)
    accel->for_mac = TRUE;
  else
    accel->for_mac = FALSE;

  if (ciph_alg != 0)
    {
      accel->encrypt = TRUE;

      if (encrypt)
        accel->for_encryption = TRUE;
      else
	accel->for_encryption = FALSE;
    }
  else
    {
      accel->encrypt = FALSE;
    }

  if (ciph_alg != 0 && hash_alg != 0)
    {
      accel->crie.cri_next = &(accel->cria);
      accel->cria.cri_next = NULL;
      error = crypto_newsession(&(accel->sid), &(accel->crie),
				SSH_OCF_DEVICETYPE);
    }
  else if (ciph_alg != 0)
    {
      accel->crie.cri_next = NULL;
      error = crypto_newsession(&(accel->sid), &(accel->crie),
				SSH_OCF_DEVICETYPE);
    }
  else if (hash_alg != 0)
    {
      accel->cria.cri_next = NULL;
      error = crypto_newsession(&(accel->sid), &(accel->cria),
				SSH_OCF_DEVICETYPE);
    }

  if (error)
    {
      accel->sid = 0;
      SSH_DEBUG(SSH_D_FAIL, ("crypto_newsession failed %d\n", error));
      goto fail;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW, ("New Session created SID = %d\n", accel->sid));

  return accel;

 fail:
  SSH_DEBUG(SSH_D_FAIL, ("Alloc ipsec failed"));
  ssh_hwaccel_free(accel);

  return NULL;
}

/* Allocates a hardware acceleration context for
   compression/decompression using algorithm specified at
   `compression_name' This context is assumed to be used for the
   IPCOMP transformation. */
SshHWAccel ssh_hwaccel_alloc_ipcomp(SshInterceptor interceptor,
                                    Boolean compress,
                                    const char *compression_name)
{
  return NULL;
}

static int ocf_operation_complete(void *cop, SshUInt32 handle)
{
  struct cryptop *crp = (struct cryptop *) cop;
  SshOcfPacketOperation op = (SshOcfPacketOperation)crp->crp_opaque;
  unsigned char *temp;

#ifdef SSH_SAFENET_PACKET_IS_DMA
  temp=((struct sk_buff *) crp->crp_buf)->data;
#else
  temp=crp->crp_buf;
#endif

  SSH_DEBUG(SSH_D_NICETOKNOW, ("Result from sid = %d", crp->crp_sid));

  if (crp->crp_etype == 0) /* Operation Successful */
    {

      SSH_DEBUG(SSH_D_NICETOKNOW, ("Successful Operation"));
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("packet after:"),
			temp, crp->crp_ilen);

#ifndef SSH_SAFENET_PACKET_IS_DMA
      if (!ssh_interceptor_packet_copyin(op->pp,0,
					 crp->crp_buf, crp->crp_ilen))
	{
	  SSH_DEBUG(SSH_D_FAIL, ("copyin failed, dropping packet"));
	  op->pp = NULL;

	  goto fail;
	}

      ssh_free(crp->crp_buf);
#endif /* SSH_SAFENET_PACKET_IS_DMA */

      (*(op->completion))(op->pp, SSH_HWACCEL_OK, (op->completion_context));

      crypto_freereq(crp);

      if (op != NULL)
	OCF_OPERATION_FREELIST_PUT(op);
    }
  else if (crp->crp_etype == EAGAIN)
    {
      SSH_DEBUG(SSH_D_ERROR, ("Result EAGAIN from sid = %d", crp->crp_sid));
      goto fail;
    }
  else
    {
      SSH_DEBUG(SSH_D_ERROR, ("ERROR %d from sid = %d",
			      crp->crp_etype,crp->crp_sid));
      goto fail;
    }

   return 0;

 fail:
   if (op->pp != NULL)
     ssh_interceptor_packet_free(op->pp);

#ifndef SSH_SAFENET_PACKET_IS_DMA
   ssh_free(crp->crp_buf);
#endif /* SSH_SAFENET_PACKET_IS_DMA */

   crypto_freereq(crp);

   OCF_OPERATION_FREELIST_PUT(op);

   (*op->completion)(NULL, SSH_HWACCEL_CONGESTED, op->completion_context);

   return 0;
}

/*
   Callback function from OCF for symmetric key operations.
*/
void ocf_cb(struct cryptop *crp)
{
  SSH_DEBUG(SSH_D_NICETOKNOW, ("callback from OCF(symmetric key operations)"));

  ocf_operation_complete((void *)crp, 0);
  return;
}

/* Performs `hardware-accelerated' processing for an IPSEC
   transformation.  */
void ssh_hwaccel_perform_ipsec(SshHWAccel accel,
                               SshInterceptorPacket pp,
                               size_t encrypt_iv_offset,
                               size_t encrypt_len_incl_iv,
                               size_t mac_start_offset,
                               size_t mac_len,
                               size_t icv_offset,
                               SshHWAccelCompletion completion,
                               void *completion_context)
{
  unsigned char *packet = NULL;
  size_t packet_len;
  int result = 1;
  SshOcfPacketOperation op = NULL;
  struct cryptop *crp = NULL;
  struct cryptodesc *crde = NULL, *crda = NULL;

  OCF_OPERATION_FREELIST_GET(op);
  if (!op)
    {
      SSH_DEBUG(SSH_D_FAIL, ("OCF_OPERATION_FREELIST_GET() failed"));
      goto fail;
    }

  if (accel->encrypt)
    {
      if (accel->for_encryption)
	{
	  if (accel->for_mac)
	    {
	      crp = crypto_getreq(2);
	      if (!crp)
		goto fail;

	      op->crp = crp;
	      crde = crp->crp_desc;
	      crda = crde->crd_next;
	      crda->crd_next = NULL;
	    }
	  else
	    {
	      crp = crypto_getreq(1);
	      if (!crp)
		goto fail;

	      op->crp = crp;
	      crde = crp->crp_desc;
	      crde->crd_next = NULL;
	    }
	}
      else
	{
	  if (accel->for_mac)
	    {
	      crp = crypto_getreq(2);
	      if (!crp)
		goto fail;

	      op->crp = crp;
	      crda = crp->crp_desc;
	      crde = crda->crd_next;
	      crde->crd_next = NULL;
	    }
	  else
	    {
	      crp = crypto_getreq(1);
	      if (!crp)
		goto fail;

	      op->crp = crp;
	      crde = crp->crp_desc;
	      crde->crd_next = NULL;
	    }
	}
    }
  else
    {
      if (accel->for_mac)
	{
	  crp = crypto_getreq(1);
	  if (!crp)
	    goto fail;

	  op->crp = crp;
	  crp = op->crp;
	  crda = crp->crp_desc;
	  crda->crd_next = NULL;
	}
      else
	{
	  SSH_DEBUG(SSH_D_FAIL, ("No operation for acceleration"));
	  goto fail;
	}
    }

  packet_len = ssh_interceptor_packet_len(pp);
  packet = NULL;

  /* Get contiguous packet */
#ifdef SSH_SAFENET_PACKET_IS_DMA
  {
    SshInterceptorInternalPacket ipp = (SshInterceptorInternalPacket)pp;

    SSH_ASSERT(packet_len == ipp->skb->len);
    packet = (unsigned char *)ipp->skb;
  }
#else /* SSH_SAFENET_PACKET_IS_DMA */
  if ((packet = (unsigned char *) ssh_malloc(packet_len)) == NULL)
    goto fail;

  ssh_interceptor_packet_copyout(pp, 0, packet, packet_len);
#endif /* SSH_SAFENET_PACKET_IS_DMA */

  op->pp = pp;
  op->completion = completion;
  op->completion_context = completion_context;

  if (accel->encrypt)  /* operation is encryption/decryption  */
    {
      if (accel->for_encryption)
	{
	  crde->crd_flags = CRD_F_KEY_EXPLICIT | CRD_F_ENCRYPT;
	  crde->crd_skip = encrypt_iv_offset + accel->iv_len;

	  /* Bytes to process after skip */
	  crde->crd_len = encrypt_len_incl_iv - accel->iv_len;
	  crde->crd_inject = encrypt_iv_offset; /* Where to inject the IV */
	  crde->crd_alg = accel->crie.cri_alg;
	  crde->crd_key = accel->crie.cri_key;
	  crde->crd_klen = accel->crie.cri_klen;

	  if (accel->for_mac)
	    {
	      crda->crd_skip = mac_start_offset;
	      crda->crd_flags = CRD_F_KEY_EXPLICIT;
	      crda->crd_len = mac_len;
	      crda->crd_inject = icv_offset; /* Offset to inject the digest */
	      crda->crd_alg = accel->cria.cri_alg;
	      crda->crd_key = accel->cria.cri_key;
	      crda->crd_klen = accel->cria.cri_klen;
	    }
	}
      else
	{
	  crde->crd_flags = CRD_F_KEY_EXPLICIT;
	  crde->crd_skip = encrypt_iv_offset + accel->iv_len;

	  /* Bytes to process after skip */
	  crde->crd_len = encrypt_len_incl_iv - accel->iv_len;
	  crde->crd_inject = encrypt_iv_offset; /* Where to inject the IV */
	  crde->crd_alg = accel->crie.cri_alg;
	  crde->crd_key = accel->crie.cri_key;
	  crde->crd_klen = accel->crie.cri_klen;

	  if (accel->for_mac)
	    {
	      crda->crd_skip = mac_start_offset;
	      crda->crd_flags = CRD_F_KEY_EXPLICIT;
	      crda->crd_len = mac_len;
	      crda->crd_inject = icv_offset; /* Offset to inject the digest */
	      crda->crd_alg = accel->cria.cri_alg;
	      crda->crd_key = accel->cria.cri_key;
	      crda->crd_klen = accel->cria.cri_klen;
	    }
	}
    }
  else /* operation is not encryption/decryption */
    {
      if (accel->for_mac)
	{
	  crda->crd_skip = mac_start_offset;
	  crda->crd_flags = CRD_F_KEY_EXPLICIT;
	  crda->crd_len = mac_len;
	  crda->crd_inject = icv_offset;
	  crda->crd_alg = accel->cria.cri_alg;
	  crda->crd_key = accel->cria.cri_key;
	  crda->crd_klen = accel->cria.cri_klen;
	}
    }

  crp->crp_ilen = packet_len; /* Input data total length */
  crp->crp_flags = 0;

#ifdef SSH_SAFENET_PACKET_IS_DMA
  SSH_DEBUG(SSH_D_NICETOKNOW, ("Data passed as SKBUF"));
  crp->crp_flags |= CRYPTO_F_SKBUF;
#endif

  crp->crp_buf = packet;
  crp->crp_callback = (void *)ocf_cb;
  crp->crp_sid = accel->sid;
  crp->crp_opaque = (caddr_t) op;

#ifdef SSH_SAFENET_PACKET_IS_DMA
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("packet before :"),
		    ((struct sk_buff *)crp->crp_buf)->data,
		    crp->crp_ilen);
#else
  SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("packet before :"),
		    crp->crp_buf,
		    crp->crp_ilen);
#endif

  result = crypto_dispatch(crp);

  if (result != 0)
    {
      SSH_DEBUG(SSH_D_FAIL, ("crypto_dispatch fail"));
      goto fail;
    }

  return;

 fail:
  if (pp != NULL)
    ssh_interceptor_packet_free(pp);

  crypto_freereq(crp);
  if (op != NULL)
    OCF_OPERATION_FREELIST_PUT(op);

#ifndef SSH_SAFENET_PACKET_IS_DMA
  if (packet != NULL)
    ssh_free(packet);
#endif /* SSH_SAFENET_PACKET_IS_DMA */

  (*completion)(NULL, SSH_HWACCEL_CONGESTED, completion_context);
  return;
}

/*  Performs hardware-accelerated compression/decompression.  This
    function compresses/decompresses a portion of `pp' as specified by
    the hardware acceleration context.  */
void ssh_hwaccel_perform_ipcomp(SshHWAccel accel,
                                SshInterceptorPacket pp,
                                size_t offset,
                                size_t len,
                                SshHWAccelCompletion completion,
                                void *completion_context)
{
  SSH_NOTREACHED;
}


/* Allocates a hardware acceleration context for combination of IPsec
   transformations. The `flags' determines whether the instance is to
   be used for decapsulation or encapsulation, as well as the types of
   transforms to perform. Ther order of transforms is fixed, in
   decryption order AH->ESP->IPcomp->IPIP (and reverse encryption order).
   The {ah,esp,ipcomp,ipip}_ parameters should be only used
   if the relevant bit is set in the `flags' bitmask.
*/
SshHWAccel
ssh_hwaccel_alloc_combined(SshInterceptor interceptor,
                           SshUInt32 requested_ops,
			   SshUInt32 *provided_ops,
                           SshUInt32 ah_spi,
                           const char *ah_macname,
                           const unsigned char *ah_authkey,
                           size_t ah_authkeylen,
                           SshUInt32 esp_spi,
                           const char *esp_macname,
                           const char *esp_ciphname,
                           const unsigned char *esp_authkey,
                           size_t esp_authkeylen,
                           const unsigned char *esp_ciphkey,
                           size_t esp_ciphkeylen,
                           const unsigned char *esp_iv,
                           size_t esp_ivlen,
                           SshUInt32 ipcomp_cpi,
                           const char *ipcomp_compname,
                           SshIpAddr ipip_src, SshIpAddr ipip_dst,
                           SshUInt32 seq_num_low,
                           SshUInt32 seq_num_high,
			   SshUInt16 natt_remote_port,
			   const unsigned char *natt_oa_l,
			   const unsigned char *natt_oa_r)
{
  *provided_ops = 0;

  return NULL;
}

void ssh_hwaccel_perform_combined(SshHWAccel accel,
                                  SshInterceptorPacket pp,
                                  SshHWAccelCompletion completion,
                                  void *completion_context)
{
  SSH_NOTREACHED;
}

SshHWAccelResultCode
ssh_hwaccel_update_combined(SshHWAccel accel,
                            SshIpAddr ipip_src,
                            SshIpAddr ipip_dst,
			    SshUInt16 natt_remote_port)
{
  SSH_NOTREACHED;

  return SSH_HWACCEL_UNSUPPORTED;
}


void ssh_hwaccel_free_combined(SshHWAccel accel)
{
  SSH_NOTREACHED;
}

/* Callback from public key operations */
static int ocf_koperation_complete(void *cop,SshUInt32 handle)
{
  struct cryptkop *kop=(struct cryptkop *) cop;
  SshOcfPKOperation op=NULL;
  SshHWAccelBigIntStruct result;
  unsigned char result_temp[SSH_OCF_MAX_MODP_OUTPUT];
  op = ocf_pkq_find_elm(kop);

  SSH_ASSERT(op != NULL); /*This should always be the case. ocf_pkq_find_elm
			    should return a valid SshOcfPkOperation */

 switch (kop->krp_status)
    {
    case OCF_PK_SUCCESS: /* Success */
      memset(result_temp,0,SSH_OCF_MAX_MODP_OUTPUT);
      endian_swap(result_temp,kop->krp_param[RES].crp_p,
		  (kop->krp_param[RES].crp_nbits+7)/8);
      memcpy(kop->krp_param[RES].crp_p,result_temp,
	     (kop->krp_param[RES].crp_nbits+7)/8);
      result.v = (SshUInt32 *)kop->krp_param[RES].crp_p;
      result.size_in_bits = kop->krp_param[RES].crp_nbits;
      result.size = (result.size_in_bits +7) / 8;
      SSH_DEBUG(SSH_D_NICETOKNOW,("Result Size: %d %d",
				  result.size,result.size_in_bits));
      SSH_DEBUG_HEXDUMP(SSH_D_NICETOKNOW, ("Result Value :"),
			(unsigned char *)result.v,result.size);
      SSH_DEBUG(SSH_D_NICETOKNOW,("Public Key Operation Successful"));
      (*op->callback)(&result,op->context);
      break;

    case EINVAL: /*Invalid argument */
      SSH_DEBUG(SSH_D_FAIL,("Public Key Operation Failed EINVAL"));
      goto fail;

    case EOPNOTSUPP:  /*Operation not supported */
      SSH_DEBUG(SSH_D_FAIL,("Public Key Operation Failed EOPNOTSUPP"));
      goto fail;

    case ENOMEM: /*Out of Memory*/
      SSH_DEBUG(SSH_D_FAIL,("Public Key Operation Failed ENOMEM"));
      goto fail;

    case E2BIG:
      SSH_DEBUG(SSH_D_FAIL,("Public Key Operation Failed E2BIG"));
      goto fail;

    case ERANGE:
      SSH_DEBUG(SSH_D_FAIL,("Public Key Operation Failed ERANGE"));
      goto fail;

    case EDOM:
      SSH_DEBUG(SSH_D_FAIL,("Public Key Operation Failed EDOM"));
      goto fail;

    default:
      SSH_DEBUG(SSH_D_FAIL,("Public Key Operation Failed %d",kop->krp_status));
      goto fail;
    }

  ocf_pkq_remove_elm(op);

  return 0;
 fail:
  (*op->callback)(NULL, op->context);
  ocf_pkq_remove_elm(op);
  return 0;
}

/* Callback function for publickey operations */
void ocf_kcb(struct cryptkop *kop)
{
  SSH_DEBUG(SSH_D_NICETOKNOW,("callback from OCF(publickey operations)"));

  ocf_koperation_complete((void *)kop, 0);
  return;
}
void ssh_hwaccel_perform_modp(const SshHWAccelBigInt base,
                              const SshHWAccelBigInt exp,
                              const SshHWAccelBigInt mod,
                              SshHWAccelModPCompletion callback,
                              void *callback_context)
{
  SshOcfPKOperation ocf_kop =  NULL;
  if ((base->size > SSH_OCF_MAX_MODP_INPUT) ||
      (exp->size > SSH_OCF_MAX_MODP_INPUT)  ||
      (mod->size > SSH_OCF_MAX_MODP_INPUT))
    {
      SSH_DEBUG(SSH_D_FAIL,("MODP operation input size exceeded"));
      goto fail;
    }

  SSH_DEBUG(SSH_D_NICETOKNOW,("Performing Modp operation"));
  ocf_kop = ssh_malloc(sizeof(struct SshOcfPKOperationRec));
  if (!ocf_kop)
    goto fail;
  ocf_pkq_add_elm(ocf_kop);

  /* fix the length in bits information */
  base->size_in_bits = base->size * 8;
  exp->size_in_bits = exp->size * 8;
  mod->size_in_bits = mod->size * 8;
  /* cryptokop */
  ocf_kop->krp.krp_op= CRK_MOD_EXP;
  ocf_kop->krp.krp_iparams = 3;
  ocf_kop->krp.krp_oparams = 1;
  /*Use hardware to accelerate*/

  ocf_kop->krp.krp_crid = CRYPTOCAP_F_HARDWARE;
  /*copy the size in bits*/
  ocf_kop->krp.krp_param[BASE].crp_nbits = base->size_in_bits;
  ocf_kop->krp.krp_param[EXP].crp_nbits = exp->size_in_bits;
  ocf_kop->krp.krp_param[MOD].crp_nbits = mod->size_in_bits;
  ocf_kop->krp.krp_param[RES].crp_nbits = mod->size_in_bits;

  memset(ocf_kop->base,0,SSH_OCF_MAX_MODP_INPUT);
  memset(ocf_kop->exp,0,SSH_OCF_MAX_MODP_INPUT);
  memset(ocf_kop->mod,0,SSH_OCF_MAX_MODP_INPUT);
  memset(ocf_kop->res,0,SSH_OCF_MAX_MODP_OUTPUT);
  /*copy the buffers*/
  endian_swap(ocf_kop->base,(unsigned char *)base->v,base->size);
  endian_swap(ocf_kop->exp,(unsigned char *)exp->v,exp->size);
  endian_swap(ocf_kop->mod,(unsigned char *)mod->v,mod->size);

  ocf_kop->krp.krp_param[BASE].crp_p = ocf_kop->base;
  ocf_kop->krp.krp_param[EXP].crp_p = ocf_kop->exp;
  ocf_kop->krp.krp_param[MOD].crp_p = ocf_kop->mod;
  ocf_kop->krp.krp_param[RES].crp_p = ocf_kop->res;

  ocf_kop->krp.krp_callback = (void *)ocf_kcb;
  ocf_kop->context = callback_context;
  ocf_kop->callback = callback;
  ocf_kop->krp.krp_flags = 0;
  ocf_kop->krp.krp_flags = CRYPTO_KF_CBIMM ;
  ocf_kop->krp.krp_status = 0;

  if (crypto_kdispatch(&(ocf_kop->krp)))
    {
      ocf_pkq_remove_elm(ocf_kop);
      SSH_DEBUG(SSH_D_FAIL,("crypto_kdispatch fail"));
      goto fail;
    }
  return;

 fail:
  (*callback)(NULL, callback_context);
  return;
}

void ssh_hwaccel_get_random_bytes(size_t bytes_requested,
                                  SshHWAccelRandomBytesCompletion callback,
                                  void *callback_context)
{
  (*callback)(NULL, 0, callback_context);
}

/* Create a HwAccel and operation freelist */
Boolean ssh_hwaccel_init()
{
  if (!ocf_operation_freelist_alloc())
    goto fail;

  if (!ocf_hwaccel_freelist_alloc())
    goto fail;

  if (!ocf_pkq_mutex_alloc())
    goto fail;

  return TRUE;

 fail:
  printk("Hardware acceleration initialization failed, using software "
	 "crypto\n");

  ssh_hwaccel_uninit();
  return FALSE;
}

void ssh_hwaccel_uninit()
{
  ocf_operation_freelist_free();
  ocf_hwaccel_freelist_free();

  ocf_pkq_mutex_free();
  ocfpkq_mutex=NULL;

  return;
}

/* Frees the hardware acceleration context.  The engine guarantees
   that no operations will be in progress using the context when this
   is called. */
void ssh_hwaccel_free(SshHWAccel accel)
{
  if (accel != NULL)
    {
      if (accel->sid != 0)
	{
	  SSH_DEBUG(SSH_D_NICETOKNOW, ("Accel Sid = %d", accel->sid));
	  crypto_freesession(accel->sid);
	}

      OCF_HWACCEL_FREELIST_PUT(accel);
    }

  return;
}
