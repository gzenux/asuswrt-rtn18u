/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   CMP enrollment client library.
*/

typedef enum {
  SSH_EC_CA_ID_NAME,
  SSH_EC_CA_ID_CERT,
  SSH_EC_CA_ID_RA_CERT  /* not yet */
} SshEcCAIdType;

/* ASN.1 encoded x509 certificate, which is added to the PKIMessage.
   This data is not modified or verified by the library. */
typedef struct SshEcCertRec
{
  const unsigned char * ber;
  size_t ber_len;
} SshEcCertStruct, *SshEcCert;

typedef struct SshEcCmpCARec
{
  SshCmpVersion protocol_version;
  Boolean transport_level_poll;
  SshEcCAIdType identity_type;
  union
  {
    unsigned char *name;
    struct {
      unsigned char *data; size_t len;
    } cert;
  } identity;

  char *address;
  char *socks;
  char *proxy;

  /* Try to be compatible with older servers. */
  Boolean rfc2511_compatibility;

  /* Prefer SHA-256 over SHA-1 where applicable. */
  Boolean prefer_sha256;
} *SshEcCmpCA, SshEcCmpCAStruct;

typedef enum {
  SSH_EC_EE_ID_PSK,
  SSH_EC_EE_ID_CERT,
  SSH_EC_EE_ID_RA       /* No EE pop, send in RA signed envelope. */
} SshEcEEIdType;
typedef struct SshEcCmpAuthRec
{
  SshEcEEIdType identity_type;
  union {
    struct
    {
      unsigned int count;
      unsigned char *kid, *key;
      size_t kid_len, key_len;
      char *name; /* optional */
    } psk;
#define id_count identity.psk.count
#define id_kid identity.psk.kid
#define id_key identity.psk.key
#define id_kid_len identity.psk.kid_len
#define id_key_len identity.psk.key_len
#define id_name identity.psk.name
    struct
    {
      unsigned char *data; size_t len;
      SshPrivateKey prvkey;
    } cert;
#define id_cert identity.cert.data
#define id_cert_len identity.cert.len
#define id_prvkey identity.cert.prvkey
  } identity;
} *SshEcCmpAuth, SshEcCmpAuthStruct;

typedef struct SshEcCmpKeyPairRec
{
  SshPrivateKey prvkey;
  SshPublicKey pubkey;
} *SshEcCmpKeyPair, SshEcCmpKeyPairStruct;

typedef void (*SshEcCmpCertRepCB)(SshCmpStatus *accept_or_reject,
                                  void *context);

typedef SshOperationHandle
(*SshEcCmpCB)(SshCmpStatus status,
              SshCmpCertStatusSet certs, unsigned int ncerts,
              SshCmpCertSet extra, unsigned int nextra,
              SshEcCmpCertRepCB reply, void *reply_context,
              void *context);

/* Error and pending replies are received via this callback. */
typedef void (*SshEcCmpErrorCB)(SshCmpStatus status,
                                unsigned int pollid, unsigned int pollwhen,
                                SshStr status_string,
                                SshStr error_reason,
                                SshStr human_instructions,
                                void *context);

typedef void (*SshEcCmpDoneCB)(void *context);

/*
  num_extra_certs, extra_certs

  Extra certificates to send to server, which may or may not be used to
  authenticate or otherwise aid in the processing of the request.
  Implementations have been known to require sending root CA and
  intermediate CA certificates when sending an initialization request,
  or the original certificate when requesting a new certificate with key
  update -- both requirements are part of the 3GPP specification "ETSI
  TS 133 310 V9.7.0 (2011-10)",
  http://www.etsi.org/deliver/etsi_ts/133300_133399/133310/09.07.00_60/
    ts_133310v090700p.pdf (URL split to fit to line).

*/

SshOperationHandle
ssh_ec_cmp_enroll(SshCmpBodyType which,
                  SshEcCmpCA ca,
                  SshEcCmpAuth authenticator,
                  SshEcCmpKeyPair keypair,
                  Boolean backup,
                  Boolean encrypt_pop,
                  SshX509Certificate certtemp,
                  size_t num_extra_certs,
                  SshEcCertStruct *extra_certs,
                  SshEcCmpCB callback,
                  SshEcCmpDoneCB done,
                  SshEcCmpErrorCB error,
                  void *callback_context);

SshOperationHandle
ssh_ec_cmp_recover(SshEcCmpCA ca,
                   SshEcCmpAuth authenticator,
                   SshX509Certificate certtemp,
                   SshPublicKey protocol_encryption_key,
                   SshEcCmpCB callback, SshEcCmpDoneCB done,
                   SshEcCmpErrorCB error,
                   void *callback_context);

typedef void
(*SshEcCmpRevokeCB)(SshCmpRevokedSet certs, unsigned int ncerts,
                    void *context);

SshOperationHandle
ssh_ec_cmp_revoke(SshEcCmpCA ca,
                  SshEcCmpAuth authenticator,
                  SshX509Certificate certtemp,
                  SshEcCmpRevokeCB callback,
                  SshEcCmpDoneCB done,
                  SshEcCmpErrorCB error,
                  void *callback_context);

SshOperationHandle
ssh_ec_cmp_poll(SshEcCmpCA ca,
                SshEcCmpAuth authenticator,
                SshUInt32 nreq, SshMPInteger reqs,
                SshEcCmpCB callback,
                SshEcCmpDoneCB done,
                SshEcCmpErrorCB error,
                void *callback_context);
