/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   sshtlsi.h
*/

#ifndef SSHTLSI_H_INCLUDED
#define SSHTLSI_H_INCLUDED

#include "sshtls.h"
#include "sshtlsextra.h"
#include "sshbuffer.h"
#include "sshstream.h"
#include "sshgetput.h"
#include "sshadt.h"
#include "sshadt_list.h"
#ifdef SSHDIST_VALIDATOR
#include "x509.h"
#endif /* SSHDIST_VALIDATOR */

/* Include the multi hash table implementation header. */

#include "tls_multihash.h"

#define SSH_TLS_SSL_3_0_COMPAT  /* Compile SSL 3.0 compatibility in. */
#define SSH_TLS_SSL_2_0_COMPAT  /* Compile SSL 2.0 handshake start
                                   compatibility in. */
#define SSH_TLS_EXTRAS          /* Compile in certain extra code that is
                                   actually necessary for running the
                                   regression tests. */

/* Eternal constants dictated by the standard. */

#define SSH_TLS_MAX_RECORD_LENGTH 16384

/* Other eternal constants. */

#define SSH_TLS_MAGIC_NUMBER ((SshUInt32) 0x19750224)
                                /* The author's date of birth. */

/* Generic macros. */

#define SSH_TLS_IS_FAILED_STATUS(x) (x == SSH_TLS_FAILED)

/** TLS protocol versions
*/
typedef enum {
  SSH_TLS_VER_UNKNOWN  = -2,
  SSH_TLS_VER_SSL2     = -1,
  SSH_TLS_VER_SSL3     = 0,
  SSH_TLS_VER_TLS1_0   = 1,
  SSH_TLS_VER_TLS1_1   = 2
} SSH_TLS_PROTOCOL_VER;


/* Rekeying types */
typedef enum {
  SSH_TLS_REKEY_FAST,
  SSH_TLS_REKEY_FULL
} SshTlsRekeyingMode;

/* Different content types enumerated. */

typedef enum
{
  SSH_TLS_CTYPE_CHANGE_CIPHER = 20,
  SSH_TLS_CTYPE_ALERT = 21,
  SSH_TLS_CTYPE_HANDSHAKE = 22,
  SSH_TLS_CTYPE_APPDATA = 23
}
SshTlsContentType;

/* Alert messages */

#define SSH_TLS_ALERT_CLOSE_NOTIFY               0
#define SSH_TLS_ALERT_UNEXPECTED_MESSAGE        10
#define SSH_TLS_ALERT_BAD_RECORD_MAC            20
#define SSH_TLS_ALERT_DECRYPTION_FAILED         21
#define SSH_TLS_ALERT_RECORD_OVERFLOW           22
#define SSH_TLS_ALERT_DECOMPRESSION_FAILURE     30
#define SSH_TLS_ALERT_HANDSHAKE_FAILURE         40
#ifdef SSH_TLS_SSL_3_0_COMPAT
#define SSH_TLS_ALERT_NO_CERTIFICATE            41
#endif
#define SSH_TLS_ALERT_BAD_CERTIFICATE           42
#define SSH_TLS_ALERT_UNSUPPORTED_CERTIFICATE   43
#define SSH_TLS_ALERT_CERTIFICATE_REVOKED       44
#define SSH_TLS_ALERT_CERTIFICATE_EXPIRED       45
#define SSH_TLS_ALERT_CERTIFICATE_UNKNOWN       46
#define SSH_TLS_ALERT_ILLEGAL_PARAMETER         47
#define SSH_TLS_ALERT_UNKNOWN_CA                48
#define SSH_TLS_ALERT_ACCESS_DENIED             49
#define SSH_TLS_ALERT_DECODE_ERROR              50
#define SSH_TLS_ALERT_DECRYPT_ERROR             51
#define SSH_TLS_ALERT_EXPORT_RESTRICTION        60
#define SSH_TLS_ALERT_PROTOCOL_VERSION          70
#define SSH_TLS_ALERT_INSUFFICIENT_SECURITY     71
#define SSH_TLS_ALERT_INTERNAL_ERROR            80
#define SSH_TLS_ALERT_USER_CANCELED             90
#define SSH_TLS_ALERT_NO_RENEGOTIATION         100

#define SSH_TLS_ALERT_WARNING           1
#define SSH_TLS_ALERT_FATAL             2

/* Miscallenous definitions. */

#define SSH_TLS_HEADER_SIZE 5

/* The protocol version structure. */

typedef struct
{
  unsigned char major;
  unsigned char minor;
}
SshTlsProtocol;

/* Version comparison. */
#define SSH_TLS_VERSION_LEQ(amaj,amin,bmaj,bmin) \
  (((amaj * 256) + amin) <= ((bmaj * 256) + bmin))

/* Handshake messages */

typedef enum
{
  SSH_TLS_HS_HELLO_REQUEST = 0,
  SSH_TLS_HS_CLIENT_HELLO = 1,
  SSH_TLS_HS_SERVER_HELLO = 2,
  SSH_TLS_HS_CERT = 11,
  SSH_TLS_HS_SERVER_KEX = 12,
  SSH_TLS_HS_CERT_REQ = 13,
  SSH_TLS_HS_SERVER_HELLO_DONE = 14,
  SSH_TLS_HS_CERT_VERIFY = 15,
  SSH_TLS_HS_CLIENT_KEX = 16,
  SSH_TLS_HS_FINISHED = 20
} SshTlsHandshakeType;

/* ClientCertificateTypes */
typedef enum {
  SSH_TLS_CERTTYPE_RSA_SIGN = 1,
  SSH_TLS_CERTTYPE_DSS_SIGN = 2,
  SSH_TLS_CERTTYPE_RSA_FIXED_DH = 3,
  SSH_TLS_CERTTYPE_DSS_FIXED_DH = 4
} SshTlsClientCertificateType;

/* Flags that are a part of the key exchange state. */

#define SSH_TLS_KEX_CLIENT_CERT_REQUESTED       0x0001
                                /* Set if server requests the
                                   client to send a certificate. */

#define SSH_TLS_KEX_ANONYMOUS_SERVER            0x0002
                                /* True if the server did not send a
                                   certificate/the key exchange method
                                   is anonymous. In that case, the
                                   server is not allowed to ask for a
                                   client certificate. */

#define SSH_TLS_KEX_CONVERTED_CLIENT_HELLO      0x0004
                                /* True if the ClientHello message received
                                   was actually converted from a v 2.0
                                   one. In this case the original message
                                   has been added already to the history
                                   buffer and the converted message should
                                   not be added there. */

#define SSH_TLS_KEX_CERT_VERIFIED               0x0008
                                /* Set in a client's kex state when
                                   the server certificate chain has been
                                   verified succesfully. */

#define SSH_TLS_KEX_NEW_SESSION                 0x0010
                                /* Set if the master secret has been
                                   freshly negotiated, i.e. if this
                                   session is not a resumed one. This
                                   information is used to decide
                                   whether or not the new security
                                   association should be cached at the
                                   end of the transport session. */

#define SSH_TLS_KEX_WAITING_CERT_CB             0x0020
                                /* Set if we are currently waiting for
                                   the application to give a decision
                                   upon a certificate that could not
                                   be verified by the certificate
                                   manager. */

#define SSH_TLS_KEX_CERT_VERIFIED_CM            0x0040
                                /* Set if the certificate manager was
                                   able to verify the peer
                                   certificate. */

#define SSH_TLS_KEX_TIMEOUT_COMING              0x0080
                                /* Set if a key exchange timeout
                                   has been scheduled. */
#define SSH_TLS_KEX_VIRGIN_AFTER_FAST_REKEY     0x0100
                                /* Set after a fast key re-exchange has
                                   been finished and unset when any
                                   application data is transferred.
                                   This is used to optimize
                                   unnecessary rekeyings out. */

#define SSH_TLS_KEX_VIRGIN_AFTER_FULL_REKEY     0x0100
                                /* Set after a full key re-exchange has
                                   been finished and unset when any
                                   application data is transferred.
                                   This is used to optimize
                                   unnecessary rekeyings out. */
#define SSH_TLS_KEX_NO_CACHING                  0x0200
                                /* Set in a server's key exchange
                                   state if the client is not allowed
                                   to resume an old session. This is
                                   used to implement full rekeying. */
#define SSH_TLS_KEX_GRABBED_CERTS               0x0400
                                /* Set if the application has grabbed
                                   the X509 certificate chain by calling
                                   ssh_tls_grab_certs. */
#define SSH_TLS_KEX_CM_INFO_VALID               0x0800
                                /* Set if the certificate info structure
                                   has some intelligent contents. */
#define SSH_TLS_KEX_REJECT_NEW_CONNECTION_REQUEST 0x1000
                                /* Set if the application rejects a new
                                   connection request. */
#define SSH_TLS_KEX_KEYOP_FAILED                0x2000
                                /* Set if crypto operation failed. */

#define SSH_TLS_KEX_HAVE_MASTER_SECRET          0x4000
                                /* Set if master secret is generated */
#define SSH_TLS_KEX_INITIAL_FLAGS               0x0000
                                /* Initial flags when a new protocol
                                   instance is created. */
/* The distinct key exchange states. */

typedef enum
{
  SSH_TLS_KEX_CLEAR,            /* No key exchange in process. */

  /* Client path */

  SSH_TLS_KEX_SEND_C_HELLO,     /* Send the client hello message. */
  SSH_TLS_KEX_WAIT_S_HELLO,     /* Wait for a server hello message. */
  SSH_TLS_KEX_WAIT_S_CERT,      /* Wait for a server certificate. */
  SSH_TLS_KEX_WAIT_S_KEX,       /* Wait for a server key exchange. */
  SSH_TLS_KEX_WAIT_S_CERTREQ,   /* Wait for a server certificate request. */
  SSH_TLS_KEX_WAIT_S_HELLODONE, /* Wait for a server hello done message. */

  SSH_TLS_KEX_SEND_C_CERT,      /* Send the client certificate. */
  SSH_TLS_KEX_SEND_C_KEX,       /* Send the client kex data. */
  SSH_TLS_KEX_SEND_C_CERTVERIFY,
                                /* Send the certificate verify message. */
  SSH_TLS_KEX_SEND_C_CC,        /* Send the cipher change message. */
  SSH_TLS_KEX_SEND_C_FINISHED,  /* Send the finished messaged. */

  SSH_TLS_KEX_WAIT_S_CC,        /* Wait for the server cipher change. */
  SSH_TLS_KEX_WAIT_S_FINISHED,  /* Wait for the server finished message. */

  /* Server path */

  SSH_TLS_KEX_WAIT_C_HELLO,     /* Wait for a client hello message. */
  SSH_TLS_KEX_SEND_S_HELLO,     /* Send the server hello message. */

  SSH_TLS_KEX_SEND_S_CERT,      /* Send the server certificate. */
  SSH_TLS_KEX_SEND_S_KEX,       /* Send the server kex data. */
  SSH_TLS_KEX_SEND_S_CERTREQ,   /* Send a certificate request. */
  SSH_TLS_KEX_SEND_S_HELLODONE, /* Send the hello done message. */

  SSH_TLS_KEX_WAIT_C_CERT,      /* Wait for a client certificate. */
  SSH_TLS_KEX_WAIT_C_KEX,       /* Wait for a client kex message. */
  SSH_TLS_KEX_WAIT_C_CERTVERIFY,
                                /* Wait for a client certificate verify. */
  SSH_TLS_KEX_WAIT_C_CC,        /* Wait for the cipher change message. */
  SSH_TLS_KEX_WAIT_C_FINISHED,  /* Wait for the client finished message. */

  SSH_TLS_KEX_SEND_S_CC,        /* Send the cipher change message. */
  SSH_TLS_KEX_SEND_S_FINISHED,  /* Send the finished messaged. */

  /* [Shared] continuations */
  SSH_TLS_KEX_WAIT_CM_CERT_VERIFY,
                                /* Wait for the peer certificate to
                                   have been verified by the certificate
                                   manager. */
  SSH_TLS_KEX_WAIT_APP_CERT_DECIDE,
                                /* Wait for the application's decision
                                   concerning the peer certificate. */
  SSH_TLS_KEX_WAIT_CM_OWN_CERTS,
                                /* Wait for the certificate manager
                                   to get our own certificates. */
  SSH_TLS_KEX_WAIT_AUTH_DECISION,
                                /* Wait for the client to decide if
                                   authentication should be actually
                                   performed. */
  SSH_TLS_KEX_WAIT_KEYOP_COMPLETION,
                                /* Wait asynchronous key operation to
                                   complete. */
#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
  SSH_TLS_KEX_WAIT_OUT_CRYPTO_COMPLETION,
                                /* Wait outgoing crypto ops to
                                   complete. */
#endif
  /* For testing */

  SSH_TLS_KEX_VOID,             /* Do nothing */

  SSH_TLS_NUM_KEX_STATES
} SshTlsKexStateID;

/* Initial states. */

#define SSH_TLS_KEX_S_INITIAL   SSH_TLS_KEX_WAIT_C_HELLO
#define SSH_TLS_KEX_C_INITIAL   SSH_TLS_KEX_SEND_C_HELLO

/* The key exchange protocol state structure. */

typedef struct {
  SshTlsKexStateID state;

  SshTlsKexStateID next_state; /* Utilized to avoid different continuation
                                  function for all private and public key
                                  asyncronous completions. */
  SshUInt32 alert;             /* Same purpose as previous, only used if
                                  flag indicates error */
  const char *alert_text;

  SshUInt32 flags;

  /* Encryption-related values. */
  unsigned char client_random[32];
                                /* The client's random value. */
  unsigned char server_random[32];
                                /* The server's random value. */
  unsigned char master_secret[48];
                                /* The master secret. Must be stored
                                   because it is used for rekeying. */
  SshTlsCipherSuite cipher_suite;
                                /* The negotiated cipher suite. */
  SshTlsCipherSuite client_cipher_suites[SSH_TLS_NUM_CIPHERSUITES];
                                /* An array containing the cipher suites
                                   supported by the client. */
  int num_client_cipher_suites; /* Length of the array. */

  /* Certificates. */
  SshTlsBerCert peer_certs;     /* The peer certificates BER-encoded. */

#ifdef SSHDIST_VALIDATOR
  SshCMCertList own_certificate_list;
                                /* The list of my own certificates.
                                   For a server, the list of
                                   certificates certifying our private
                                   key, and for a client similarly. */

  struct SshCMSearchInfoRec cm_info;
                                /* The info record returned from the
                                   last verification attempt. */
#else /* SSHDIST_VALIDATOR */
  SshTlsBerCert own_certs;      /* Our certificates BER-encoded. */
#endif /* SSHDIST_VALIDATOR */

  SshTlsCertQueryResult query_status;
                                /* What to return if
                                   ssh_tls_get_cert_chain is called. */


  unsigned char *encoded_ca_list;
                                /* The list of suggested CA's from the
                                   other party in the TLS packet
                                   encoding. */

  /* PKCS keys. */
  SshPrivateKey temporary_private_key;
                                /* The temporary private key obtained
                                   from a shared temporary key object
                                   [for a server]. */
  SshPublicKey her_public_key;
                                /* The public key of the peer. */
  SshPublicKey server_temporary_key;
                                /* The temporary key sent by the server.
                                   Used only by clients. */
  SshTlsTemporaryKey locked_temporary_key;
                                /* The shared temporary key object
                                   used by this protocol instance. */

  /* Sessions. */
  unsigned char session_id[32];
                                /* The session identifier of the current
                                   session.*/
  int id_len;                   /* The length of the session
                                   identifier.  Zero denotes that no
                                   identifier is associated with the
                                   current session. */

  /* Miscellaneous */
  SshBuffer handshake_history; /* The handshake history. */

  SshTlsProtocol client_version;
                                /* Server: the *original* protocol
                                   version from the client's key
                                   exchange packet. Client: the
                                   highest protocol version to be
                                   supported. */
  SshUInt64 fast_rekey_data_limit;
  SshUInt64 full_rekey_data_limit;
                                /* Limits on the data transferred
                                   until the next rekey will take
                                   place. These values are to be
                                   compared with those stored in
                                   SshTlsProtocolState.stats. */
} SshTlsKexState;

/* Sequence numbers handling (implement 64-bit sequence numbers using
   32-bit types when necessary). */

#ifdef SSHUINT64_IS_64BITS
#define SSH_TLS_INCREMENT_SEQ(s) do { s++; } while(0)
#define SSH_TLS_IS_ZERO_SEQ(s) ((s) == (SshUInt64)0)
#define SSH_TLS_ZERO_SEQ(s) do { s = 0; } while(0)
#define SSH_TLS_PUT_SEQ(ptr, s) SSH_PUT_64BIT(ptr, s)
#else /* SSHUINT64_IS_64BITS */
#define SSH_TLS_INCREMENT_SEQ(s) do { (s).lo++; \
    if ((s).lo == 0) (s).hi++; } while(0)
#define SSH_TLS_IS_ZERO_SEQ(s) ((s).lo == 0 && (s).hi == 0)
#define SSH_TLS_ZERO_SEQ(s) do { (s).hi = 0; (s).lo = 0; } while(0)
#define SSH_TLS_PUT_SEQ(ptr, s) do { SSH_PUT_32BIT((ptr), (s).hi); \
    SSH_PUT_32BIT((ptr) + 4, (s).lo); } while(0)
#endif /* SSHUINT64_IS_64BITS */

/* The state of the record layer protocol in one direction. */

#define SSH_TLS_DECRYPT_DONE    0x1 /* Set when decrypt is completed */
#define SSH_TLS_DECRYPT_PAD_ERR 0x2 /* Set on decrypt padding error */

typedef struct {
  Boolean is_stream_cipher; /* Stream cipher? */
  int block_length;         /* Block length in bytes if a block cipher. */
  int mac_length;           /* MAC length in bytes. */
  SshCipher cipher;         /* Cipher state */
  SshMac    mac;            /* MAC state */

  int flags;                /* encoding/decoding flags */
  int current_len;          /* current length for incoming/outgoing packet */
#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
  int ops_pending;          /* number of operations waiting for completion */
  void *accel_ctx;          /* TLS hardware acceleration context */
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

#ifdef SSHUINT64_IS_64BITS
  SshUInt64 seq;                /* Sequence number */
#else
  struct {
    SshUInt32 hi, lo;
  } seq;
#endif
} SshTlsUnidirectionalState;

/* The state of a record layer protocol in the both directions. */

typedef struct {
  SshTlsUnidirectionalState incoming;
                                /* State for incoming data */
  SshTlsUnidirectionalState outgoing;
                                /* State for outgoing data */
} SshTlsBidirectionalState;

/* A structure for implementing higher-layer protocols over the TLS
   record protocol. (There are currently four: application, key
   exchange, alert and cipher change.) */

struct ssh_tls_higher_protocol;
struct ssh_tls_protocol_state;

/* Functions of this type are called when new data has been received
   for a particular higher-level protocol. The functions returns the
   number of bytes consumed from the protocol-specific `data' buffer
   or a negative number to denote a fatal error. In that case, the
   process function has already called `ssh_tls_immediate_kill'. */
typedef int (* SshTlsProtocolProcessFunc)(struct ssh_tls_protocol_state *s,
                                          struct ssh_tls_higher_protocol *p);

typedef struct ssh_tls_higher_protocol {
  SshTlsContentType type;       /* The content type corresponding to this
                                   protocol. */
  SshBuffer data;              /* incoming data */
                                /* There is no buffer for outgoing
                                   data. Instead, data is written
                                   directly to the lower layer's buffer. */
  SshTlsProtocolProcessFunc func;

  struct ssh_tls_higher_protocol *next;
} *SshTlsHigherProtocol;

struct SshTlsExtraRec {
  SshTlsGenericNotification deleted_notify;
  void *deleted_notify_context;

  SshUInt32 flags;
};

/* Miscallenous flags used in the TLS state. */

#define SSH_TLS_FLAG_STREAM_EOF                 0x0001
                                /* Set if the underlying stream has
                                   given EOF to us. */
#define SSH_TLS_FLAG_STREAM_WRITE_CLOSED        0x0002
                                /* Set if the underlying stream has
                                   notified use of a closen output
                                   channel. */
#define SSH_TLS_FLAG_SENT_CLOSE_NOTIFY          0x0004
                                /* Set if we have sent the TLS close
                                   notify alert. */
#define SSH_TLS_FLAG_GOT_CLOSE_NOTIFY           0x0008
                                /* Set if we have received the TLS
                                   close notify alert.*/
#define SSH_TLS_FLAG_EXPECT_READ_NOTIFY         0x0010
                                /* Set if we expect to get a read
                                   notification from the underlying
                                   stream. */
#define SSH_TLS_FLAG_EXPECT_WRITE_NOTIFY        0x0020
                                /* Set if we expect to get a write
                                   notification from the underlying
                                   stream. */
#define SSH_TLS_FLAG_REQUESTED_TIMEOUT          0x0040
                                /* Set if we have requested a timeout
                                   for sending a packet. */
#define SSH_TLS_FLAG_GIVE_READ_NOTIFY           0x0080
                                /* Set if we should give read
                                   notification to the application
                                   layer when there is something to be
                                   read. */
#define SSH_TLS_FLAG_GIVE_WRITE_NOTIFY          0x0100
                                /* Set if we should give write
                                   notification to the application
                                   layer when there is room for
                                   writing. */
#define SSH_TLS_FLAG_DELETED                    0x0200
                                /* True if the protocol context has
                                   been killed, i.e. scheduled for
                                   deletion. When the output buffer
                                   has been drained the protocol
                                   stream is actually closed. The
                                   input buffer does not need to be
                                   drained because the application
                                   cannot read it anyway as the stream
                                   has been deleted already.

                                   This flag is also consulted when
                                   external callbacks --- e.g. from
                                   the certificate manager --- are
                                   received.
                                   */
#define SSH_TLS_FLAG_INITIAL_KEX_DONE           0x0400
                                /* Set after the initial key exchange
                                   has been succesfully finished and
                                   application data can be begun to
                                   send. */

#define SSH_TLS_FLAG_DESTROY_SCHEDULED          0x0800
                                /* True after the actual destroy
                                   function has been scheduled to be
                                   called. Used to ensure that it is
                                   not scheduled multiple times. */
#define SSH_TLS_FLAG_READING_CEASED             0x1000
                                /* Set if we have ceased reading
                                   the underlying stream because an
                                   internal buffer has been filled. */
#define SSH_TLS_FLAG_OUTPUT_EOF                 0x2000
                                /* Set if the application stream
                                   has called the output EOF method. */
#define SSH_TLS_FLAG_VERSION_FIXED              0x4000
                                /* Set after the protocol version
                                   number has been decided. Prior to
                                   that the version number in the
                                   record layer headers is not checked
                                   too strictly. */
#define SSH_TLS_FLAG_FROZEN                     0x8000
                                /* Set when ssh_tls_frreze is called.
                                   While the protocol is in the frozen
                                   state basically nothing happens. */
#define SSH_TLS_INITIAL_FLAGS   (SSH_TLS_FLAG_GIVE_WRITE_NOTIFY | \
                                 SSH_TLS_FLAG_GIVE_READ_NOTIFY)
                                /* The initial flags when a protocol
                                   starts. */

typedef struct ssh_tls_protocol_state {
  SshUInt32 magic;              /* Used for checking that users of the
                                   TLS library do not make stupid
                                   mistakes :) */
  SshStream app_stream;         /* The application data stream ---
                                   a backpointer so that the stream
                                   can be given, for convenience, to the
                                   application in application
                                   notifications. */
  SshTlsProtocol protocol_version;
                                /* Protocol version used.  Initially
                                   0, 0. */
  SshBuffer incoming_raw_data; /* Buffer where raw data coming from
                                   the lower layer is stored. */
  SshBuffer outgoing_raw_data; /* Buffer where data to be sent back
                                   to the lower layer is stored. */

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS

  /* Length of TLS records in outgoing_raw_data that are waiting for
     crypto operation to complete */
  int pend_len;

  /* With hardware acceleration, use fixed size raw data buffers to prevent
     them to be reallocated while hw-assisted crypto operations are in
     progress. */
  unsigned char *incoming_raw_data_buff;
  unsigned char *outgoing_raw_data_buff;

  /* Extra room to fit key exchange and alert messages */
#define SSH_TLS_EXTRA_RAW_DATA_ROOM 0x400

  /* Callback to call when all encrypt operations have completed */
  void (*outgoing_all_complete_cb)(struct ssh_tls_protocol_state *);
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

  /* Length of the last data packet in outgoing_raw_data that is only
     partially built, i.e. that does not have a MAC nor is encrypted
     yet.  From this information the exact pointer where the data
     starts can be calculated. This length contains the room that is
     allocated for the record layer header. */
  int built_len;

  SshTlsContentType built_content_type;
                                /* The content type of the currently
                                   built packet.*/

  SshStream stream;             /* The underlying stream. */

  SshUInt32 flags;              /* Flags. See above. */

  /* The data to be sent to the upper layer is actually stored in the
     incoming_raw_data (all cipher transforms are done inplace). If
     packet_feed_len > 0, data is being fed to the upper layer from
     the beginning of the incoming_raw_data buffer.

     This because it is expected that application data is the most
     frequently encountered content type and its therefore useful
     to optimize memory usage for this type of data. */

  int packet_feed_len;
                                /* Amount of data to be sent
                                   to the upper layer. */

  int trailer_len;              /* Amount of data in the current packet
                                   that comes after the content.
                                   This contains the MAC and the padding
                                   for a block cipher. */

  SshTlsBidirectionalState conn;
                                /* Current connection state. */

  SshTlsKexState kex;           /* WState of the key exchange. */

  SshTlsConfigurationStruct conf;
                                /* Copy of the configuration. */

  SshStreamCallback stream_callback;
                                /* The user-defined stream callback. */

  void *stream_callback_context;
                                /* The associated context. */

  SshTlsStatus status;          /* The current status. */
  SshTlsFailureReason failure_reason;
                                /* The failure reason when
                                   status == SSH_TLS_FAILED. */

  SshTlsHigherProtocol protocols;
                                /* The higher-layer protocol records
                                   save for the application data
                                   `protocol'. */

  Boolean tls_error_app_hook_sent; /* TRUE is the app hook is called for
                                      SSH_TLS_ERROR */


  /* Some statistics */

  SshTlsStatisticsStruct stats;

  /* Some function pointers etc. that are used for testing and such
     purposes but are not part of the TLS implementation per se. */

  struct SshTlsExtraRec extra;
} *SshTlsProtocolState;

/* Functions of type SshTlsReadTransition are used to process a key
   exchange state where we are waiting for a packet.  When a kex
   packet arrives, the ReadTransition corresponding to the current
   state is invoked.

   The transition function must set the new state identifier to
   s->kex.state. Returning TRUE means that the same packet must be
   processed by the new state; returning FALSE means that the packet
   has been consumed. */

typedef struct {
  SshTlsKexStateID id;          /* The corresponding SshTlsKexStateID */
  const char *description;      /* English description of the state */
  Boolean waiting;              /* TRUE if in this state we are waiting
                                   for a packet and FALSE if we are
                                   sending one. */

  void *trans;                  /* This contains a ReadTransition or a
                                   WriteTransition, depending on
                                   whether `waiting' is TRUE or FALSE,
                                   respectively. */
} SshTlsKexStateInfo;

/* Table of state info elements. */

extern const SshTlsKexStateInfo
ssh_tls_kex_state_info[SSH_TLS_NUM_KEX_STATES];

/* Session caches */

struct SshTlsSessionCacheRec;

typedef struct SshTlsCachedSessionRec {
  SshTlsProtocol protocol_version;
                                /* The protocol version corresponding
                                   to this session. */
  unsigned char session_id[32]; /* Session ID */
  char *group_name;             /* The name of the connection group
                                   that is using this context;
                                   applicable only on the client side.
                                   This field is dynamically allocated
                                   because it is not always used. */
  size_t id_len;                /* ID length */
  unsigned char master_secret[48];
                                /* The master secret of the session */
  SshTlsCipherSuite cipher_suite;
                                /* The chosen cipher suite */

  SshTlsBerCert peer_certs;
                                /* The certificates of the peer or
                                   NULL if no certificate was presented. */
  struct SshTlsSessionCacheRec *backptr;

  SshADTListHeaderStruct adt_header;
} *SshTlsCachedSession;

#define CACHE_ID_LEN 32

struct SshTlsSessionCacheRec {
  /* Configuration */
  int max_connections;
  int alive_time;

  /* Actual contents, pointers to SshTlsCachedSessionRecs, hashed using
     the session identifiers. */
  SshTlsMultiHashTable table;

  /* Pointers to SshTlsCachedSessionRecs, but now hashed using the
     group names. */
  SshTlsMultiHashTable ids;

  /* Number of aging timeouts that have been scheduled but have not
     been received yet. */
  int pending_timeouts;

  /* List of the cached connection records. */
  SshADTContainer list;

  /* Number of currently cached records. */
  int num_cached;

  /* The static cache identifier, used for creating session ids. */
  char identifier[CACHE_ID_LEN];

  /* Counter */
  int counter;

  /* Lazy destroy */
  Boolean destroyed;
};


/* Transition functions. */

typedef enum {
  SSH_TLS_TRANS_OK,             /* Transition done, or perhaps frozen.
                                   Must check the SSH_TLS_FLAG_FROZEN
                                   flag. */
  SSH_TLS_TRANS_FAILED,         /* Fatal failure, shut the protocol down. */
  SSH_TLS_TRANS_REPROCESS       /* The key exchange state has changed,
                                   dispatch again. This is used e.g. to
                                   skip transitions when the corresponding
                                   packet is optional and has been
                                   omitted. */
} SshTlsTransStatus;

typedef SshTlsTransStatus (* SshTlsReadTransition)(SshTlsProtocolState s,
                                                   SshTlsHandshakeType type,
                                                   unsigned char *data,
                                                   int data_len);

/* Analogous, expect that there is no return value.
   Write transitions always succeed (or kill the protocol). */

typedef SshTlsTransStatus (* SshTlsWriteTransition)(SshTlsProtocolState s);
typedef SshTlsTransStatus (* SshTlsContTransition)(SshTlsProtocolState s);

/* The temporary key object. */

struct SshTlsTemporaryKeyRec {
  /* The current private key and the corresponding public key. */
  SshPrivateKey private_key;
  SshPublicKey  public_key;

  int private_key_locks;        /* Number of sessions that need to refer
                                   to the current private key later. */

  Boolean deleted;              /* True if the object has been deleted
                                   (actually, dereferenced). */

  /* In the TLS protocol, the temporary public key is first sent and
     later the private key is used for decryption. It is possible that
     the shared temporary RSA key is regenerated between this interval
     for some session. In such cases we cannot delete the
     corresponding private key until it has been used. Upon
     regeneration, the old private key is stored into the field
     `old_private_key'.

     If the interval lasts longer than `regeneration_interval' a major
     problem takes place: the private key that the session tries to
     use is actually freed! Therefore the protocol must timeout faster
     than `regeneration_interval'. This is taken care of in the
     implementation. */

  SshPrivateKey old_private_key;

  int old_private_key_locks;    /* Locks for the old private key.
                                   Will be copied from `private_key_locks'
                                   upon regeneration. */

  int regeneration_interval;    /* Number of seconds one key is allowed
                                   to live. */

  Boolean used;                 /* True if the current key has been
                                   sent to the remote part at least once.
                                   This field is used to avoid regenerating
                                   a key that has not been used at all. */

  int locks;                    /* Locks on the generic temporary key
                                   object. */
};

/** Prototypes for our internal functions. **/

/** Operating with the application **/
/** Implemented in tls_appstream.c **/

/* Inform the application that there's some data that can be read. */
void ssh_tls_ready_for_reading(SshTlsProtocolState s);

/* Inform the application that there's room for more data to be written. */
void ssh_tls_ready_for_writing(SshTlsProtocolState s);

/* The write method of the TLS stream.

   The application data is appended to `outgoing_raw_data'.  Prior to
   that, a TLS appdata packet header is written if there isn't one
   already. There is a header exactly if `built_len' > 0.  Adjust
   `built_len' to match the combined header and payload length of the
   appdata packet that is being built.

   Then request a timeout after `conf.unfragment_delay' microseconds
   so that the application data packet that is being formed gets
   encrypted and on its way. */
int ssh_tls_stream_write(void *context, const unsigned char *buf, size_t size);

/* The read method of the TLS stream.  This reads application data
   that is found from the `incoming_raw_data' buffer spanning the
   first `packet_feed_len' bytes.  Return EOF if the underlying stream
   has signalled EOF and `packet_feed_len' is zero. Return -1 if
   `packet_feed_len' is zero otherwise.

   Otherwise move some data from `incoming_raw_data' to `buf'.  If
   `packet_feed_len' becomes zero, consume `trailer_len' extraneous
   bytes from `incoming_raw_data' (this is used to get rid of the
   padding and MAC fields of the appdata packet after the payload has
   been processed). */
int ssh_tls_stream_read(void *context, unsigned char *buf, size_t size);

/* The destroy method of the TLS stream. Schedules the TLS stream
   for immediate destroying, which happens next time we fall
   to the bottom of the event loop. */
void ssh_tls_stream_destroy(void *context);

/* The output EOF method of the TLS stream. Schedules the close notify
   packet to be sent. */
void ssh_tls_stream_output_eof(void *context);

/* Function that sets the application's callbacks. */
void ssh_tls_stream_set_callback(void *context, SshStreamCallback callback,
                                 void *callback_context);

#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
/* Get number of bytes application can write to a stream */
int ssh_tls_appstream_can_write_bytes(SshTlsProtocolState s);
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

/** Operating with the underlying stream. **/
/** Implemented in tls_downstream.c **/

/* The stream callback which is called by the underlying stream. */
void ssh_tls_stream_callback(SshStreamNotification notification,
                             void *context);

/* Read some data in from the underlying stream. */
void ssh_tls_read_in(SshTlsProtocolState s);

/* Read some data in from the underlying stream unless we are
   expecting to get an explicit read notification from the stream. */
void ssh_tls_try_read_in(SshTlsProtocolState s);

/* Write some data out to the underlying stream. */
void ssh_tls_write_out(SshTlsProtocolState s);

/* Write some data out to the underlying stream unless we are
   expecting to get an explicit write notification from the stream. */
void ssh_tls_try_write_out(SshTlsProtocolState s);


/** Key exchange **/

/** Key exchange transition functions **/
/** Implemented in tls_kextrans.c and the files corresponding to individual
    transitions. **/

#define DCT(x) SshTlsTransStatus ssh_tls_trans_cont_ ## x\
                    (SshTlsProtocolState s)

SshTlsTransStatus ssh_tls_trans_write_client_hello(SshTlsProtocolState s);
SshTlsTransStatus ssh_tls_trans_write_client_cert(SshTlsProtocolState s);
SshTlsTransStatus ssh_tls_trans_write_client_kex(SshTlsProtocolState s);
SshTlsTransStatus ssh_tls_trans_write_client_certverify(SshTlsProtocolState s);

SshTlsTransStatus ssh_tls_trans_write_server_hello(SshTlsProtocolState s);
SshTlsTransStatus ssh_tls_trans_write_server_cert(SshTlsProtocolState s);
SshTlsTransStatus ssh_tls_trans_write_server_kex(SshTlsProtocolState s);
SshTlsTransStatus ssh_tls_trans_write_server_certreq(SshTlsProtocolState s);
SshTlsTransStatus ssh_tls_trans_write_server_hellodone(SshTlsProtocolState s);

SshTlsTransStatus ssh_tls_trans_write_change_cipher(SshTlsProtocolState s);
SshTlsTransStatus ssh_tls_trans_write_finished(SshTlsProtocolState s);

SshTlsTransStatus ssh_tls_trans_read_server_hello(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len);

SshTlsTransStatus ssh_tls_trans_read_server_cert(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len);

SshTlsTransStatus ssh_tls_trans_read_server_kex(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len);

SshTlsTransStatus ssh_tls_trans_read_server_certreq(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len);

SshTlsTransStatus ssh_tls_trans_read_server_hellodone(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len);

SshTlsTransStatus ssh_tls_trans_read_client_hello(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len);

SshTlsTransStatus ssh_tls_trans_read_client_cert(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len);

SshTlsTransStatus ssh_tls_trans_read_client_kex(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len);

SshTlsTransStatus ssh_tls_trans_read_client_certverify(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len);

SshTlsTransStatus ssh_tls_trans_read_change_cipher(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len);

SshTlsTransStatus ssh_tls_trans_read_finished(
  SshTlsProtocolState s, SshTlsHandshakeType type,
  unsigned char *data, int data_len);

SshTlsTransStatus ssh_tls_trans_cont_cert_verify(SshTlsProtocolState s);
SshTlsTransStatus ssh_tls_trans_cont_cert_decide(SshTlsProtocolState s);
SshTlsTransStatus ssh_tls_trans_cont_got_own_certs(SshTlsProtocolState s);
SshTlsTransStatus ssh_tls_trans_cont_auth_decide(SshTlsProtocolState s);
SshTlsTransStatus ssh_tls_trans_cont_keyop_completion(SshTlsProtocolState s);
#ifdef SSH_IPSEC_HWACCEL_SUPPORT_TLS
SshTlsTransStatus ssh_tls_trans_cont_out_crypto_completion(
  SshTlsProtocolState s);
#endif /* SSH_IPSEC_HWACCEL_SUPPORT_TLS */

void ssh_tls_send_hello_request(SshTlsProtocolState s);

/** Other generic kex functions from tls_kextrans.c **/

/* Start running the protocol engine again, beginning from the kex
   dispatch. This is called when we have been waiting for an external
   callback and then have got it. */
void ssh_tls_revive_kex(SshTlsProtocolState s);

/* Add `length' bytes of data starting from `data' to the buffer that
   is used to calculate the key exchange verification hashes. This
   increases also `built_len' accordingly. */
void ssh_tls_add_to_kex_history(SshTlsProtocolState s,
                                const unsigned char *data,
                                int length);

/* This appends `data' to the outgoing raw data and also adds it to
   the key exchange hashes.

   This function also modifies `built_len'. */
void ssh_tls_add_to_kex_packet(SshTlsProtocolState s,
                               const unsigned char *data,
                               int length);

/* Start building a handshake-type packet and write the four-byte
   handshake packet header. Add the header also to the handshake
   history buffer. */
void ssh_tls_make_hs_header(SshTlsProtocolState s,
                            SshTlsHandshakeType type,
                            int length);

/* This is like ssh_tls_make_hs_header but do not add to the handshake
   history. Used for writing packets that are not part of the
   handshake history. Actually there is only one such packet, the
   HelloRequest. */
void ssh_tls_make_hs_header_no_history(SshTlsProtocolState s,
                                       SshTlsHandshakeType type,
                                       int length);

/* Cache the current session context when the Finished messages
   have been sent and received. */
void ssh_tls_cache_current_session(SshTlsProtocolState s);

/* This is called when the key exchange has been succesfully finished.
   Change the TLS status, cancel key exchange timeouts, clear key
   exchange state, cache the current session if possible and notify
   the application of the possibility to write application data. */
void ssh_tls_kex_finished(SshTlsProtocolState s);

/* Called by the server, choose the cipher suite to use from the list
   of suites presented by client. That is, from the array
   s->kex.client_cipher_suites[].

   This either writes a valid, supported ciphersuite to
   s->kex.cipher_suite and returns SSH_TLS_TRANS_OK, write
   SSH_TLS_CIPHERSUITE_NOT_AVAILABLE to s->kex.cipher_suite and
   returns SSH_TLS_TRANS_FAILED. */
SshTlsTransStatus ssh_tls_choose_suite(SshTlsProtocolState s);

/* Send the hello request handshake message. */

/** Other key exchange functions **/
/** Implemented in tls_kex.c **/

/* The dispatcher of the key exchange implementation. It is called
   whenever a kex packet is received, or whenever we are in a kex
   state where a packet should be sent. If `data' is NULL, then this
   call corresponds to the latter case. Exception is the very start of
   the key exchange, where ssh_tls_kex_dispatch is called with data
   `NULL' in any case.

   Returns TRUE if everything went well and FALSE if the protocol has
   been shut down due to an error (in that case the
   `ssh_tls_immediate_kill' function has been already called).

   */
Boolean ssh_tls_kex_dispatch(SshTlsProtocolState s,
                             SshTlsHandshakeType type,
                             unsigned char *data,
                             int data_len);

/* Initialize the key exchange state at the beginning of the protocol. */
Boolean ssh_tls_initialize_kex(SshTlsProtocolState s);

/* Re-initialize the key exchange state at the beginning of a rekeying
   procedure. */
void ssh_tls_initialize_new_kex(SshTlsProtocolState s);

/* The function that is called from ssh_tls_parse_incoming for the
   key exchange protocol. */
int ssh_tls_kex_process(SshTlsProtocolState s, SshTlsHigherProtocol p);

/* Finalize those parts of the key exchange state that are time
   critical. Currently, free the temporary key object if it is
   present. */
void ssh_tls_cancel_kex(SshTlsProtocolState s);

/* A timeout callback to be called when a key exchange has timed out.
   This calls the ssh_tls_cancel_kex function. */
void ssh_tls_kex_timeout(void *context);

/* Install key exchange timeout. */
void ssh_tls_install_kex_timeout(SshTlsProtocolState s);

/* Cancel the key exchange timeout. */
void ssh_tls_cancel_kex_timeout(SshTlsProtocolState s);

/* Clear those fields of the key exchange state that do not need to
   be preserved between several key exchanges. */
void ssh_tls_clear_kex_state(SshTlsProtocolState s);

#ifdef SSHDIST_VALIDATOR

/* The callback that will be got from the certificate manager after it
   has finished with trying to verify a certificate chain. */
void ssh_tls_cert_verify_callback(void *context,
                                  SshCMSearchInfo info,
                                  SshCMCertList list);

/* Try to verify the certificate that has the id `id' in the
   certificate manager's local database. The CM will call
   ssh_tls_cert_verify_callback when the verification result is known.
   This calls ssh_tls_async_freeze to freeze the protocol until the
   callback has been actually got. */
Boolean ssh_tls_verify_certificate(SshTlsProtocolState state, int id);

/* Get the own certificates from the certificate manager. This calls
   ssh_tls_async_freeze(...) when the CM search starts and later
   ssh_tls_async_continue(...) from the CM callback. */
SshTlsTransStatus ssh_tls_get_own_certificates(SshTlsProtocolState s);

#endif /* SSHDIST_VALIDATOR */

/** Change cipher spec protocol **/
/** Implemented in tls_kex.c **/

/* The function that is called from ssh_tls_parse_incoming for the
   key exchange protocol. */
int ssh_tls_cc_process(SshTlsProtocolState s, SshTlsHigherProtocol p);

/* Change the cipher context. */
Boolean ssh_tls_change_cipher_context(SshTlsProtocolState s,
                                      Boolean from_us);

/* Revive processing the handshake protocol data that is in the HS
   protocol buffer. */
void ssh_tls_kex_revive_processing(SshTlsProtocolState s);

/* Rekeying functions. */

/* Reset the rekeying counters. If `also_full_rekey' is FALSE, reset
   only the fast rekeying counters, otherwise all. */
void ssh_tls_reset_rekeying_counters(SshTlsProtocolState s,
                                     Boolean also_full_rekey);

/* Start rekeying procedure. `mode' chooses whether to run fast or
   full rekey. If the local party is a server then this reduces mainly
   to sending a HelloRequest message to the other side. */
void ssh_tls_start_rekey(SshTlsProtocolState s,
                         SshTlsRekeyingMode mode);

/* Cancel all possibly coming rekeying timeous. */
void ssh_tls_cancel_rekeying_timeouts(SshTlsProtocolState s);

/* The timeout functions. */
void ssh_tls_fast_rekey_timeout(void *context);
void ssh_tls_full_rekey_timeout(void *context);


/** Alert protocol **/
/** Implemented in tls_alert.c **/

/* The function that is called from ssh_tls_parse_incoming for the
   key exchange protocol. */
int ssh_tls_alert_process(SshTlsProtocolState s, SshTlsHigherProtocol p);

/* Send an alert message. */
void ssh_tls_send_alert_message(SshTlsProtocolState s,
                                int level, int description);


/** Record layer **/
/** Implemented in tls_record.c **/

/* Parse incoming data. Decrypt full record layer packets and copy
   their contents to the buffers of the associated higher-layer
   protocol buffers. Then call the protocol-specific procedure that
   processes the newly received data. An exception is the application
   data which is not copied; application data is handled directly in
   this function. */
void ssh_tls_parse_incoming(SshTlsProtocolState s);

/** Return the amount of extra bytes needed due to MAC, padding and IV when
   a packet whose payload content is `payload_len' bytes long is
   encrypted. Parameter iv_len is IV for CBC under TLS1.1
*/
int ssh_tls_extra_room(SshTlsProtocolState s,
                       int payload_len, int iv_len);

/* Encrypt the packet whose header starts at `packet' and whose header
   and content lengths sum up to `packet_len'.  The packet must reside
   in the `s->outgoing_raw_data' buffer an be its last contents.

   There MUST be at least `ssh_tls_extra_room(s, packet_len)' extra
   bytes available starting at &packet[packet_len].  The packet
   expands there when MAC and padding are added.

   The length of the whole packet is returned in `result_len'.
   This length includes the header.

   This function never fails.

   The sequence number used for MAC computation is
   `s->conn.outgoing.seq'. It is NOT incremented by this function. */
Boolean ssh_tls_encrypt_make_mac(SshTlsProtocolState s,
                                 unsigned char *packet,
                                 int packet_len,
                                 int *result_len);

/* Decrypt the packet that starts at `packet' and whose length field
   had the value `packet_len'. This means that the whole TLS packet
   including the header and the MAC starts from `packet' and ends at
   `packet + (packet_len + SSH_TLS_HEADER_SIZE)'.

   After decryption and MAC checking the plaintext payload starts at
   `packet'. Upon returning, `content_len' contains the length of the
   plaintext payload. The payload starts at `packet +
   SSH_TLS_HEADER_SIZE'. The sequence number used in MAC verification
   is `s->conn.incoming.seq'. It is NOT incremented by this function.

   If decryption fails or the MAC cannot be verified an alert message
   number (non-zero) is returned. If everything went well, 0 is
   returned. (!= 0 denotes a fatal error: the protocol must be
   terminated.) */
int ssh_tls_decrypt_check_mac(SshTlsProtocolState s,
                              unsigned char *packet,
                              int packet_len,
                              int *content_len);

/* Start building a new outgoing packet for the content type `type'.
   This checks that if there is a packet being currently built it has
   the content type `type'. Otherwise if there is a currently built
   packet it is encrypted and scheduled for sending.  This allocates
   room for the TLS record layer header but does not write anything to
   it. The header is only when the length of the packet is known,
   i.e. when it is actually sent. */
void ssh_tls_start_building(SshTlsProtocolState s, SshTlsContentType type);


/* Flush the currently built packet: encrypt it and schedule for
   being sent.

     ssh_tls_flush(c); ssh_tls_start_building(s, type);

   is equivalent to

     ssh_tls_start_building(s, type);

   unless there is currently a packet of type `type' being already built.

   This explanation was a bit weird.
   */

void ssh_tls_flush(SshTlsProtocolState s);

/* The timeout that will cause `ssh_tls_flush' to be called. */
void ssh_tls_unfragment_timeout(void *context);

/* This can be used to cancel the timeout. This must be done when
   the protocol is scheduled for deletion. */
void ssh_tls_cancel_unfragment_timeout(SshTlsProtocolState s);

/** Temporary public/private key pairs. **/
/** Implemented in tls_tempkey.c **/

/* Lock the temporary key object `key'. In essence, increment a
   reference count field inside the object so that even if `key' is
   scheduled for deletion via `ssh_tls_destroy_temporary_key', it will
   persist until it is released by calling
   `ssh_tls_release_temporary_key'. */
void ssh_tls_lock_temporary_key(SshTlsTemporaryKey key);

/* See the previous function. */
void ssh_tls_release_temporary_key(SshTlsTemporaryKey key);

/* Get the temporary public and private keys. This will cause the
   returned private key `private' to be locked inside the temporary
   key object so that it will not be deleted until the private key has
   been released by calling `ssh_tls_release_private_key'.  The caller
   must not free neither `public' nor `private'.  The public key
   `public' is valid immediately after `ssh_tls_get_temporary_keys'
   returns but it can become invalidated when the bottom of the event
   loop is reached next. */
void ssh_tls_get_temporary_keys(SshTlsTemporaryKey key,
                                SshPublicKey *publicp,
                                SshPrivateKey *privatep);

/* Release a private key that was supplied by
   `ssh_tls_get_temporary_keys' previously.

   NOTE: If the private keys are not released the TLS protocol
   implementation will eventually detect an internal error and call
   ssh_fatal(). */
void ssh_tls_release_private_key(SshTlsTemporaryKey key,
                                 SshPrivateKey private_key);

/** Miscellaneous */
/** Implemented in tls_main.c **/

/* The actual implementation of ssh_tls_server_wrap and
   ssh_tls_client_wrap. */
SshStream ssh_tls_generic_wrap(SshStream stream,
                               SshTlsConfiguration configuration);

/* Timeout callback that actually releases a TLS protocol context. */
void ssh_tls_actual_destroy(void *context);

/* Kill the connection immediately due to an error condition.
 * Invalidate cache session */
void ssh_tls_immediate_kill(SshTlsProtocolState s,
                SshTlsFailureReason reason);

/* Kill the connection immediately due to an error condition.
 * Do not validate cached session*/
void ssh_tls_kill_failed_state(SshTlsProtocolState s,
                SshTlsFailureReason reason);

/* Send an alert message and then call ssh_tls_immediate_kill with
   `reason' == `alert_message'. */
void ssh_tls_alert_and_kill(SshTlsProtocolState s, int alert_message);

/* Destroy the protocol context `s' if there is no KEX transition in
   progress, the outgoing_raw_data buffer contains no data and no
   unfragment timeout has been registered. This function may not be
   called unless the SSH_TLS_FLAG_DELETED is set; this is SSH_ASSERTed
   in the function. */
void ssh_tls_destroy_if_possible(SshTlsProtocolState s);

/* A timeout callback that will be called after N seconds since a
   protocol context has been destroyed by the application, if it has
   not been actually freed yet. */
void ssh_tls_hanging_delete_callback(void *context);

/* Return TRUE if the version number major.minor is supported by the
   current implementation and the configuration, otherwise FALSE. */
Boolean ssh_tls_supported_version(SshTlsProtocolState s,
                                  unsigned char major, unsigned char minor);

/* Degrade the version *major.*minor to the highest version supported
   locally. */
void ssh_tls_degrade_version(SshTlsProtocolState s,
                             unsigned char *major, unsigned char *minor);

/** Return SSH_TLS_PROTOCOL_VER from values in protocol version in
 * SSL protocol state. This function will return unknown version value
 * for SSL2 and unknown versions
 * @params  SshTlsProtocolState instance
 * @return  SSH_TLS_PROTOCOL_VER enum value
 */
SSH_TLS_PROTOCOL_VER ssh_tls_version(SshTlsProtocolState s);

/* Cast an SshStream to SshTlsProtocolState s, verifying that the
   stream was indeed a TLS stream. */
SshTlsProtocolState ssh_tls_cast_stream(SshStream stream);

/* Call the application hook if it has been defined. */
void ssh_tls_call_app_hook(SshTlsProtocolState s,
                           SshTlsAppNotification notification);

/** Debugging-related functions **/

/* Return English name of the given content type.
   Implemented in tls_main.c. **/
const char *ssh_tls_content_type_str(SshTlsContentType type);

/** CipherSuite related functions **/
/** Implemented in tls_suites.c **/

/* Sort [destructively] the cipher suites given in the array `suites'
   according to the preference list `prefs'. `prefs' is an array of
   CipherSuites ends with the item SSH_TLS_NO_CIPHERSUITE.

   After calling this functions, `suites' contains only those
   ciphersuites that are present in `prefs', and contains them in the
   same relative order in which they are in `prefs'.

   Duplicates are NOT removed from `suites'.
   Originally the `suites' array must contain `*number_suites' elements;
   after the function returns the new (not larger) number of suites
   is returned in `*number_suites'. */
void ssh_tls_sort_suites(SshTlsCipherSuite *suites, int *number_suites,
                         SshTlsCipherSuite *prefs);

/** Cryptographic Computations **/
/** Implemented in tls_crypto.c **/

/* The TLS pseudo-random function. Calculates `return_len' bytes
   to the buffer `return_buf'. */
Boolean
ssh_tls_prf(const unsigned char *key, int key_len,
            const unsigned char *label, int label_len,
            const unsigned char *seed, int seed_len,
            unsigned char *return_buf, int return_len);

/* The SSL 3.0 pseudo-random function.
   `return_len' must be divisible by 16. */
Boolean
ssh_tls_ssl_prf(const unsigned char *secret, int secret_len,
                const unsigned char *random_1, int random_1_len,
                const unsigned char *random_2, int random_2_len,
                unsigned char *return_buf, int return_len);

/* The SSL 3.0 `Finished' digest.  There must be room for 36 bytes in
   `buf'. */
Boolean ssh_tls_ssl_finished_digest(unsigned char *secret, int secret_len,
                                    unsigned char *handshake_messages,
                                    int handshake_messages_len,
                                    Boolean is_client,
                                    unsigned char *buf);

/* The digesting method for certificate verifying in SSL3. Interface
   is identical to that above. */
Boolean ssh_tls_ssl_certverify_digest(unsigned char *secret,
                                      int secret_len,
                                      unsigned char *handshake_messages,
                                      int handshake_messages_len,
                                      Boolean is_client,
                                      unsigned char *buf);

/** Session caching **/
/** Implemented in tls_cache.c **/

/* Cache the parameters of a succesfully terminated session. `cache'
   is the cache object, `name' is the session identifier which is
   `name_len' bytes long, `master_secret' is the master secret of the
   session to cache and `cipher_suite' denotes the cipher suite.
   `peer_cert' is the certificate of the peer or NULL if the peer does
   not have one. The certificate is copied if it is given so that the
   original can be freed by the caller later. */
void ssh_tls_cache_session(SshTlsSessionCache cache,
                           SshTlsProtocol *protocol_version,
                           const unsigned char *name, int name_len,
                           const unsigned char *master_secret, /* 48 bytes */
                           SshTlsCipherSuite cipher_suite,
                           SshTlsBerCert peer_cert_chain);

/* Associate a given session with a given group. */
void ssh_tls_associate_with_group(SshTlsSessionCache cache,
                                  unsigned char *name, int name_len,
                                  const char *group_name);

/* Find a cached session parameter set from the given cache with the
   given session id. Return NULL if cached values were not found,
   otherwise a pointer to SshTlsCachedSessionRec.

   The pointer returned remains valid until the program control falls
   to the event loop. After that, it is possible that the `cache'
   object is freed. */
SshTlsCachedSession ssh_tls_find_cached_session(SshTlsSessionCache cache,
                                                unsigned char *id,
                                                int id_len);

/* Find a cached session for a given group, if any exists. */
SshTlsCachedSession ssh_tls_find_cached_by_group(SshTlsSessionCache cache,
                                                 const char *group_name);

/* Create a unique session identifier. `buf' must pointer to a region
   at least 32 bytes long. The length of the created identifier is
   returned in *id_len. */
void ssh_tls_create_session_id(SshTlsSessionCache cache,
                               unsigned char *buf,
                               int *id_len);

/** Generic async operations support **/
/** Implemented in tls_async.c **/

/* ssh_tls_async_freeze and ssh_tls_async_continue are the internal
   counterparts of ssh_tls_freeze and ssh_tls_continue, which take an
   SshStream argument instead of an SshTlsProtocolState. */

/* Set the FROZEN flag. */
void ssh_tls_async_freeze(SshTlsProtocolState s);

/* Continue the protocol execution after the state has been frozen for
   a while. This schedules an event that will revive the protocol from
   the bottom of the event loop. ssh_tls_async_freeze must have been
   called prior to this! */
void ssh_tls_async_continue(SshTlsProtocolState s);

/** Some utilities **/
/** Implemented in tls_util.c **/

/* Create a newly allocated BER-encoded certificate that contains data
   `data' that is `len' bytes long. This sets the `next' pointer to
   NULL. */
SshTlsBerCert ssh_tls_create_ber_cert(unsigned char *data,
                                      size_t len);

/* Duplicate a BER-encoded certificate chain. Return NULL if `cert'
   is NULL. */
SshTlsBerCert ssh_tls_duplicate_ber_cert_chain(SshTlsBerCert cert);

#endif /* SSHTLSI_H_INCLUDED */
