/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   CEP enrollment client.
*/

typedef struct SshEcCepCertRec
{
  Boolean data_is_state;
  unsigned char *data;
  size_t len;
} *SshEcCepCert, SshEcCepCertStruct;

typedef enum { SSH_EC_CA_TYPE_RA, SSH_EC_CA_TYPE_CA } SshEcCepCAIdType;

typedef struct SshEcCepCARec
{
  SshEcCepCAIdType identity_type;
  SshEcCepCertStruct certs[2];

#define ca_cert     certs[0].data
#define ca_cert_len certs[0].len

#define ra_sign     certs[0].data
#define ra_sign_len certs[0].len
#define ra_encr     certs[1].data
#define ra_encr_len certs[1].len

  unsigned char *address;
  unsigned char *socks;
  unsigned char *proxy;
  char *name;

  /* Optional state, contains address, socks, proxy and message used
     for restarting. */
  char *state;
} *SshEcCepCA, SshEcCepCAStruct;

typedef struct SshEcCepAuthRec
{
  struct
  {
    unsigned char *key;
    size_t key_len;
  } psk;
#define id_key     psk.key
#define id_key_len psk.key_len
} *SshEcCepAuth, SshEcCepAuthStruct;

typedef struct SshEcCepKeyPairRec
{
  SshPrivateKey prvkey;
  SshPublicKey pubkey;
} *SshEcCepKeyPair, SshEcCepKeyPairStruct;

typedef void
(*SshEcCepCB)(SshX509Status status,
              SshEcCepCert certs, unsigned int ncerts,
              void *context);

/* Input structures are stolen (and eventually freed) by the
   library. */
SshOperationHandle
ssh_ec_cep_enroll(SshEcCepCA ca,
                  SshEcCepAuth authenticator,
                  SshEcCepKeyPair keypair,
                  SshX509Certificate certtemp,
                  SshEcCepCB callback, void *callback_context);

SshOperationHandle
ssh_ec_cep_poll(SshEcCepCA ca,
                SshEcCepKeyPair keypair,
                char *state,
                SshEcCepCB callback, void *callback_context);

SshOperationHandle
ssh_ec_cep_authenticate(SshEcCepCA ca,
                        SshEcCepCB callback, void *context);
