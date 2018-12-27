/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Public interface to the SSL2/SSL3/TLS implementation.
*/

#ifndef SSHTLS_H_INCLUDED
#define SSHTLS_H_INCLUDED

#include "sshstream.h"
#include "sshcrypt.h"
#include "sshcryptoaux.h" /* ssh_hash_of_buffer used */

#ifdef SSHDIST_VALIDATOR
#include "cmi.h"
#endif /* SSHDIST_VALIDATOR */

/* Bit masks for server and client wrap flags. */

/* Protocol versions. */
#define SSH_TLS_SSL2            0x0001 /** Support SSL2 compatibility. */
#define SSH_TLS_SSL3            0x0002 /** Support SSL3 compatibility. */
#define SSH_TLS_TLS             0x0004 /** Support TLS compatibility.  */
#define SSH_TLS_TLS1_1          0x0008 /** Support TLS1.1 compatibility. */

/* Cipher suites. */
#define SSH_TLS_WEAKCIPHERS     0x0010 /** Allow for export-crippled
                                           weak ciphers (DES-40, RC4-40). */
#define SSH_TLS_NULLCIPHER      0x0020 /** Allow the null cipher.      */
#define SSH_TLS_SINGLEDES       0x0040 /** Allow the single
                                           (non-export-crippled) DES cipher. */

/* Authentication. */
#define SSH_TLS_ANONSERVER      0x0080 /** Allow anonymous servers
                                           (affects also security level!). */

#define SSH_TLS_CLIENTAUTH      0x0100 /** Ask for cert-based client auth.   */
#define SSH_TLS_STRICTAUTH      0x0200 /** Reject unauthenticated clients
                                           without questioning. */

/* Optional vulnerability fix */
#define SSH_TLS_FIX_IV_LEAK     0x0400 /** Send an empty appdata packet
                                           before each real appdata packet in
                                           order to thwart the CBC IV attack -
                                           this is allowed by the standard but
                                           breaks some applications, including
                                           some versions of Microsoft Internet
                                           Explorer. */


/** Default flags for server and client wrap (suitable for most
    applications). */
#define SSH_TLS_DEFAULTS (SSH_TLS_TLS1_1 | SSH_TLS_SSL3 | SSH_TLS_TLS | \
                SSH_TLS_SSL2)

/** Cipher suite definitions. */
typedef enum {
  SSH_TLS_RSA_WITH_NULL_MD5                     = 0x0001,
  SSH_TLS_RSA_WITH_NULL_SHA                     = 0x0002,
  SSH_TLS_RSA_EXPORT_WITH_RC4_40_MD5            = 0x0003,
  SSH_TLS_RSA_WITH_RC4_128_MD5                  = 0x0004,
  SSH_TLS_RSA_WITH_RC4_128_SHA                  = 0x0005,
  SSH_TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5        = 0x0006,
  SSH_TLS_RSA_WITH_IDEA_CBC_SHA                 = 0x0007,
  SSH_TLS_RSA_EXPORT_WITH_DES40_CBC_SHA         = 0x0008,
  SSH_TLS_RSA_WITH_DES_CBC_SHA                  = 0x0009,
  SSH_TLS_RSA_WITH_3DES_EDE_CBC_SHA             = 0x000A,

  SSH_TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA      = 0x000B,
  SSH_TLS_DH_DSS_WITH_DES_CBC_SHA               = 0x000C,
  SSH_TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA          = 0x000D,
  SSH_TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA      = 0x000E,
  SSH_TLS_DH_RSA_WITH_DES_CBC_SHA               = 0x000F,
  SSH_TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA          = 0x0010,

  SSH_TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA     = 0x0011,
  SSH_TLS_DHE_DSS_WITH_DES_CBC_SHA              = 0x0012,
  SSH_TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA         = 0x0013,
  SSH_TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA     = 0x0014,
  SSH_TLS_DHE_RSA_WITH_DES_CBC_SHA              = 0x0015,
  SSH_TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA         = 0x0016,

  SSH_TLS_DH_ANON_EXPORT_WITH_RC4_40_MD5        = 0x0017,
  SSH_TLS_DH_ANON_WITH_RC4_128_MD5              = 0x0018,
  SSH_TLS_DH_ANON_EXPORT_WITH_DES40_CBC_SHA     = 0x0019,
  SSH_TLS_DH_ANON_WITH_DES_CBC_SHA              = 0x001A,
  SSH_TLS_DH_ANON_WITH_3DES_EDE_CBC_SHA         = 0x001B,

  /* A point of discontinuity */
  SSH_TLS_RSA_WITH_AES_128_CBC_SHA              = 0x002F,
  SSH_TLS_DH_DSS_WITH_AES_128_CBC_SHA           = 0x0030,
  SSH_TLS_DH_RSA_WITH_AES_128_CBC_SHA           = 0x0031,
  SSH_TLS_DHE_DSS_WITH_AES_128_CBC_SHA          = 0x0032,
  SSH_TLS_DHE_RSA_WITH_AES_128_CBC_SHA          = 0x0033,
  SSH_TLS_DH_ANON_WITH_AES_128_CBC_SHA          = 0x0034,

  SSH_TLS_RSA_WITH_AES_256_CBC_SHA              = 0x0035,
  SSH_TLS_DH_DSS_WITH_AES_256_CBC_SHA           = 0x0036,
  SSH_TLS_DH_RSA_WITH_AES_256_CBC_SHA           = 0x0037,
  SSH_TLS_DHE_DSS_WITH_AES_256_CBC_SHA          = 0x0038,
  SSH_TLS_DHE_RSA_WITH_AES_256_CBC_SHA          = 0x0039,
  SSH_TLS_DH_ANON_WITH_AES_256_CBC_SHA          = 0x003A,

#define SSH_TLS_NUM_CIPHERSUITES                 0x0028
#define SSH_TLS_MAX_CIPHERSUITE SSH_TLS_DH_ANON_WITH_AES_256_CBC_SHA

  SSH_TLS_CIPHERSUITE_NOT_AVAILABLE             = 0xffffff,

  SSH_TLS_NO_CIPHERSUITE                        = 0x0000
} SshTlsCipherSuite;


/** Return TRUE if the cipher suite 'suite' is supported by the
    implementation in general and the configuration flags set by the
    user. */
Boolean ssh_tls_supported_suite(SshUInt32 configuration_flags,
                                SshTlsCipherSuite suite);


/** Returns a colon-separated list of ASCII strings describing the
    supported ciphersuites allowed by 'protocol flags'.
    Implemented in tls_suites.c. */
char *ssh_tls_get_supported_suites(SshUInt32 protocol_flags);

/** Return the name of the given ciphersuite as an constant ASCII string.
    Implemented in tls_suites.c. */
const char *ssh_tls_format_suite(SshTlsCipherSuite suite);

/** Reverse of ssh_tls_format_suite().
    Return the ciphersuite, the name of which is given as an ASCII string.
    Implemented in tls_suites.c. */
SshTlsCipherSuite ssh_tls_parse_suite(const char *suite_name);

/** Return an ssh_malloced array of SshTlsCipherSuites parsed
    from string 'suite_names', which contains names of ciphersuites
    separated with colons. Ciphersuites which are unrecognized,
    unsupported, or not allowed by 'protocol_flags' are silently
    discarded. Implemented in tls_suites.c. */
SshTlsCipherSuite *ssh_tls_parse_suitelist(const char *suite_names,
                                           SshUInt32 protocol_flags);


/* Session caches. */

typedef struct SshTlsSessionCacheRec *SshTlsSessionCache;

/** Create a connection cache object. Connection caches implement the
    connection resuming feature of the TLS protocols. Connection cache
    objects can be given as arguments to the functions starting a TLS
    protocol session.

    The random state `state' is used only in this function; after the
    function returns, the state can be freed as far as the session
    cache is concerned. The state is needed to create a (hopefully)
    unique identifier that will be used to name the sessions associated
    with this cache.

    @param max_connections
    The maximum number of connections that can be simultaneously kept
    in the cache; this parameter exists to prevent unbounded memory
    consumption.

    @param alive_time
    The maximum time (seconds) a connection is kept in the cache. Time
    starts running from the time a connection is initiated for the
    first time. Thus, even connections that are reused all the time
    eventually disappear from the cache.

    */
SshTlsSessionCache ssh_tls_create_session_cache(int max_connections,
                                                int alive_time);

/** Destroy a connection cache object. This does not necessarily free
    any data immediately, but after calling this function the 'cache'
    object may no longer be referenced. In particular, it may not be
    given as a part of the TLS configuration when _new_ protocol
    instances are created.

    It is permissible to destroy a connection cache object while it is
    perhaps used by some old TLS protocol instance. The TLS
    implementation automatically reference counts the connection caches
    and keeps them around for long enough. */
void ssh_tls_destroy_session_cache(SshTlsSessionCache cache);

/** Flush a session cache object - meaning that after returning from
    this, the session cache contains no entries.

    It is permissible to flush a connection cache object while it is
    used by a TLS protocol instance.
*/
void ssh_tls_flush_session_cache(SshTlsSessionCache cache);

/** Temporary key handlers. */

typedef struct SshTlsTemporaryKeyRec *SshTlsTemporaryKey;

/** Create a temporary key object. A temporary key object is used by
    the TLS library to share a temporary RSA key between TLS protocol
    instances. It is needed only by a TLS server that wants to support
    crippled suites and has a public key whose size is over 512 bits.

    @param life_span
    The key regeneration interval, expressed in seconds. That is, the
    actual RSA key represented by the key object will be regenerated
    after every 'life_span' seconds. 'life_span' must be greater than
    zero.

    When a temporary key object is used with TLS protocol, the TLS
    protocol key exchange timeout *must be* smaller than the life span
    of the temporary key. This is checked for. */
SshTlsTemporaryKey ssh_tls_create_temporary_key(int life_span);

/** Destroy a temporary key object. Semantics of destruction are
    analogous to those for 'ssh_tls_destroy_session_cache'. */
void ssh_tls_destroy_temporary_key(SshTlsTemporaryKey temporary_key);

/** The application notifications. */

typedef enum {
  /** A new connection request has been received; the application can
      at this point decide whether to proceed with the connection or
      not by calling the function
      ssh_tls_decide_new_connection_request; if memory is low, a
      denial of service attack is suspected, or for some other
      reason, the application can refuse the connection at this
      point before the key exchange begins; the application can
      use the statistics structure (obtained by by calling
      ssh_tls_get_statistics) to determine the IP address and
      port number of the remote party to aid its decision in
      whether to allow the connection. */

  SSH_TLS_NEW_CONNECTION_REQUEST = 0,

  /** The peer certificates have been received and optionally presented
      to the certificate manager; the certificate chain can be accessed
      by using ssh_tls_get_cert_chain and the CM status queried by
      ssh_tls_chain_verified_by_cm and ssh_tls_get_cm_status;
      when this notification is receivec, the certificates can be rejected
      by calling ssh_tls_decide_certs(..., FALSE) and accepted by
      calling ssh_tls_decide_certs(..., TRUE) - these decision override
      any decision by the certificate manager; otherwise the raw CM
      result is used; it is not allowed to call the
      ssh_tls_decide_certs callback in any other context, with the
      exception of using ssh_tls_freeze. */

  SSH_TLS_PEER_CERTS = 1,

  /** The server requests client authentication but we have not sent
      the authentication data yet; when this notification is received
      the server certificates are available for inspection and they have
      already been accepted; the authentication can be denied by
      calling ssh_tls_set_private_key with NULL as the private key
      argument; similarly, authentication can be allowed by calling
      the same function with a non-NULL argument, even if originally
      the private key was configured to be NULL; the private key can
      also be changed. */

  SSH_TLS_AUTH_REQUEST = 2,

  /* Some auditing events. */

  /** Initial key exchange done; when the negotiated and renegotiation
      callbacks are given the possible certificates are still
      available. */
  SSH_TLS_NEGOTIATED = 3,

  /** Renegotiation done. */
  SSH_TLS_RENEGOTIATED = 4,

  /** Protocol context destroyed; this will give NULL as 'tls_stream';
      the application knows if it has requested this notification so it
      can also ensure that app_context is still valid in any sense it
      wants it to be - together with SSH_TLS_NEW_CONNECTION this can be
      used to determine the number of active TLS sessions. */
  SSH_TLS_VANISHED = 5,

  /** An error state has been encountered; the application can request
      more detailed information on the reason for failure by calling
      ssh_tls_get_failure_reason. */
  SSH_TLS_ERROR = 6

} SshTlsAppNotification;


/** CRL policy used in certificate validation. */
typedef enum {
  /** Don't make the CM perform any CRL checks; default. */
  SSH_TLS_CRL_CHECK_NEVER = 1,

  /** If the certificate under validation contains a CRL distribution
      point extension, force the CM to fetch and check the CRL. */
  SSH_TLS_CRL_CHECK_IF_CRLDP = 2,

  /** Always force the CM to fetch and check the CRL; if the
      certificates under validation don't contain a CRL distribution
      point extension, the CM cannot automatically fetch CRLs, so the
      application must feed the CRLs to the CM by some other means.
   */
  SSH_TLS_CRL_CHECK_ALWAYS = 3
} SshTlsCrlCheckPolicy;

/** The application hook callback. */
typedef void (* SshTlsAppHook)(SshStream tls_stream,
                               SshTlsAppNotification notification,
                               void *app_context);

typedef struct ssh_tls_ber_cert {
  unsigned char *ber_data;
  size_t ber_data_len;
  struct ssh_tls_ber_cert *next;
} *SshTlsBerCert;

/* Configuration record. */

/** Configuration record, to be given as an argument to the wrapper
    functions.

    All fields may be modified between calls to the _*_wrap functions;
    the _*_wrap functions make a copy of the configuration record.
    Moreover, the 'private_key' object is copied if it is present.

    None of the objects given in a configuration record will be
    implicitly freed. Thus, disposing the random state, the
    certificate manager and the connection cache is upon the
    discretion of the caller. The objects must remain valid until the
    protocol instance that was given the objects has terminated, i.e.
    the corresponding stream has been closed.

    @param cert_manager
    The 'cert_manager' object should be an initialized certificate
    manager. Before calling this function, it should have been
    initialized with trusted CA certificates and with the host's own
    certificate for 'private_key'. There is no requirement that CA
    certificates be specified at the server if no client
    authentication is to be used (SSH_TLS_CLIENTAUTH was not in
    FLAGS). The CA certificates are used to determine which client
    certificates are accepted for authentication. This function does
    not copy or free 'cert_manager'; it must remain valid until the
    stream is destroyed. After that destroying the object is the
    caller's responsibility.

    If 'cert_manager' is NULL, no certificate checking can be made.
    Also, only anonymous key exchange can be used because it is
    impossible to get a certificate for the local-side key.

    @param private_key
    The 'private_key' argument specifies the server's or the client's
    own key. At least one certificate for the key should have been
    inserted into the certificate manager before calling this. (A
    fatal error will be triggered if there are no matching
    certificates in the cache.)

    @param private_key
    If 'private_key' is NULL, no self-authentication will be made.

    @param sessionc_cache
    If 'session_cache' is NULL, connections are not cached. Otherwise
    the given cache is used to try to optimise the handshake phase.

    @param group_name
    If 'session_cache' is used and the configuration is used for
    client-side connections, 'group_name' can be set to a non-NULL
    pointer that must point to a NUL-terminated string. Then those
    connections that have the same group name are assumed to be to the
    same server, and those connections try to share the same security
    contexts. If `group_name' is NULL, then connection caching is
    limited to rekeying, i.e. all new sessions always perform full
    handshake.

    @param flags
    The 'flags' argument controls the operation of the protocol. For
    most applications, SSH_TLS_DEFAULTS is a good choice.
    SSH_TLS_WEAKCIPHERS should also be specified in applications where
    compatibility with crippled 40-bit/512-bit encryption that is due
    to export controls is required.

    At least one of SSH_TLS_SSL2, SSH_TLS_SSHL3, SSH_TLS_TLS and
    SSH_TLS_TLS1_1 must be specified (a fatal error will be triggered
    if none of them is specified).

    For a server, certificate-based client authentication will be
    _required_ if SSH_TLS_CLIENTAUTH is specified.

    For a client, SSH_TLS_CLIENTAUTH has no meaning and it must be
    unset. Whether the client may perform client authentication or not
    is controlled by the 'private_key' field. If 'private_key' is
    NULL, not self-authentication will be made. If 'private_key' is
    non-NULL then self-authentication will be tried upon request.

    @param is_server
    'is_server' must be TRUE when ssh_tls_server_wrap is called and
    FALSE when ssh_tls_client_wrap is called. This flag exists mainly
    for ensuring internal consistency.

    @param unfragment_delay
    'unfragment_delay' is used to control the time application data is
    stored inside the protocol implementation's internal buffer before
    it is actually sent. By setting the delay to some reasonable
    value, small packets may be coalesced into larger ones, thus
    improving efficiency. On the other hand, large values of
    'unfragment_delay' can cause slightly larger response times. Even
    if 'unfragment_delay' is 0L, still all application data sent
    before the program falls back to the event loop are typically
    coalesced into one packet. The unit of 'unfragment_delay' is
    microseconds (10^-6 s).

    @param preferred_suites
    'preferred_suites' must be either NULL or an array of
    SshTlsCipherSuites that ends with SSH_TLS_NO_CIPHERSUITE. A
    non-NULL array represents the exact set of acceptable ciphersuites
    in the order of their preference. For a server, the first suite
    supported by the client that appears in 'preferred_suites' is
    accepted for protecting the session. For a client, the ordering of
    'preferred_suites' will be reflected in the list of ciphersuites
    sent to the server for selecting one of them.

    If 'preferred_suites' is non-NULL, the array 'preferred_suites'
    points to must remain valid until ssh_stream_destroy(...) has been
    called upon the wrapped TLS stream.

@param suggested_ca_distinguished_names
    'suggested_ca_distinguished_names' must be either NULL, or a
    dynamically allocated array of strings that ends with NULL
    pointer. This array is eventually freed by the library. The
    default value is NULL.  The array is used only by a server that
    requests client authentication; it is the list of distinguished CA
    names that are suggested to the client as the roots the server
    trusts. However, when the client certificate is actually verified,
    the array is not consulted. The actual validity of the client
    certificate depends solely upon on the trusted roots in the
    certificate manager 'cert_manager'.

@param crl_check_policy
    'crl_check_policy' controls whether and when a certificate
    revocation list (CRL) is required when the certificate manager is
    validating a certificate received from the peer while negotiating
    the connection. Must be one of:

     - SSH_TLS_CRL_CHECK_NEVER:     Do not perform any CRL checks

     - SSH_TLS_CRL_CHECK_IF_CRLDP:  Fetch (if necessary) and check a CRL
                                    if the certificate contains a CRL
                                    distribution point extension.

     - SSH_TLS_CRL_CHECK_ALWAYS:    Always fetch (if necessary) and check
                                    a CRL when validating the certificate.
                                    If the certificate does not contain
                                    a CRLDP extension, the certificate manager
                                    must have been configured to use a
                                    fixed set of LDAP servers where to find
                                    the CRLs, or the application must
                                    explicitly feed the CRLs to the
                                    certificate manager.

    @param max_buffered_data
    'max_buffered_data' is the limit on the number of bytes that can
    be stored in intermediate buffers. This controls both the bytes
    read from the remote party and those written by the local
    application.

    @param fast_rekey_interval
    If 'fast_rekey_interval' is non-zero, then fast rekeying (i.e.
    rekeying without public-key operations) is performed every
    'fast_rekey_interval' seconds, except if absolutely no application
    data has been sent during the whole interval. If
    'fast_rekey_bytes' is non-zero, then fast rekeying will be also
    performed whenever 'fast_rekey_bytes' application data bytes have
    been transferred in either direction. When rekeying is done due to
    interval timeout, the byte counter is zeroed. Similarly, when
    rekeying is done due to the data amount limit the interval clock
    is resetted.

    @param full_rekey_interval
    'full_rekey_interval' and 'full_rekey_bytes' are analogous but
    they cause full rekeying to take place, i.e. rekeying ''from
    scratch''. Normally full rekeying is not necessary. Full rekeying
    resets fast rekeying byte counter and clock. This does not hold in
    the other direction.

    NOTE: The key exchange timeout applies to rekeys also.

    Of course, it is impossible to guarantee that the remote TLS
    implementation actually supports rekeying. If you encounter
    problems with rekeying you could try disabling it. If the remote
    host is also running SafeNet TLS, you should not encounter any
    problems.

    @param full_rekey_bytes
    (See the description of full_rekey_interval.)

    */

typedef struct {
#ifdef SSHDIST_VALIDATOR
  SshCMContext cert_manager;
  SshMPInteger trusted_set_peer_validation;
  SshMPInteger trusted_set_own_root;
#else /* SSHDIST_VALIDATOR */
  SshTlsBerCert own_certs;
#endif /* SSHDIST_VALIDATOR */

  SshPrivateKey private_key;
  unsigned char *id_data;
  size_t id_data_size;

  SshTlsSessionCache session_cache;
  const char *group_name;

  SshTlsTemporaryKey temporary_key;

  SshTlsAppHook app_callback;
  void *app_callback_context;

  SshUInt32 flags;
  Boolean is_server;

  SshUInt64 unfragment_delay;

  SshTlsCipherSuite *preferred_suites;

  unsigned char **suggested_ca_distinguished_names;
  SshTlsCrlCheckPolicy crl_check_policy;

  int max_buffered_data;

  SshUInt64 fast_rekey_interval;
  SshUInt64 fast_rekey_bytes;
  SshUInt64 full_rekey_interval;
  SshUInt64 full_rekey_bytes;

  int key_exchange_timeout;

} *SshTlsConfiguration, SshTlsConfigurationStruct;

/** Allocate a configuration record and fill it with defaults. */
SshTlsConfiguration ssh_tls_allocate_configuration(void);

/** Fill the configuration record with default parameters.
    The default parameters are the following:

    - 'random_state', 'cert_manager', 'private_key' and
    'session_cache' are set to NULL.

    - 'unknown_cb' and 'unknown_cb_context' are set to NULL.

    - 'flags' are set to enable compatibility with TLS1.0 and SSL3.0
    to and disable export control cripped ciphers.

    - 'is_server' is set to false.

    - 'unfragment_delay' is set to 0L.

    */

void ssh_tls_configuration_defaults(SshTlsConfiguration configuration);

/** Destroy a configuration. */
void ssh_tls_destroy_configuration(SshTlsConfiguration configuration);

/* Wrapping functions. */

/** Wraps a server-side network stream into the SSL/TLS protocol, and
    returns a stream that can be used to communicate plain-text data.

    This takes control of the old stream, and it will be destroyed
    when the returned stream is destroyed (and after buffers have
    drained).

    This returns a new stream that can be used for plaintext
    communication.  If the session negotiation fails, EOF will be
    returned from the stream, and ssh_tls_get_ciphersuite will return
    SSH_TLS_FAILED. */

SshStream ssh_tls_server_wrap(SshStream stream,
                              SshTlsConfiguration configuration);

/** Wraps a client-side network stream into the SSL/TLS protocol, and
    returns a stream that can be used to communicate plain-text data.

    This takes control of the old stream, and it will be destroyed when
    the returned stream is destroyed (and after buffers have drained).

    @return
    This returns a new stream that can be used for plaintext
    communication.  If the session negotiation fails, EOF will be
    returned from the stream, and ssh_tls_get_ciphersuite will return
    SSH_TLS_FAILED. */

SshStream ssh_tls_client_wrap(SshStream stream,
                              SshTlsConfiguration configuration);

/** The dynamic control interface. */

typedef enum {
  /** The protocol is in its initial negotiation phase - in this phase,
      the certificate and ciphersuite are not yet available. */
  SSH_TLS_STARTING_UP = 0,

  /** The connection has been successfully set up, and can be used for
      communication; the ssh_tls_get_ciphersuite and
      ssh_tls_get_peer_cert functions can be used; the read function
      will return EOF when the peer has closed the stream or an error
      occurs. */
  SSH_TLS_READY = 1,

  /** The connection has been gracefully terminated; the certificate
      and ciphersuite are not available; the stream should be
      destroyed, and any reads or writes will return EOF. */
  SSH_TLS_TERMINATED = 2,

  /** The protocol is in error condition and should be destroyed;
      reads and writes will return EOF. */
  SSH_TLS_FAILED = 100
} SshTlsStatus;

/* Get protocol information. */

/** Request the status of the TLS stream. */
SshTlsStatus ssh_tls_get_status(SshStream stream);

typedef enum {
  /* No failure. */
  SSH_TLS_NO_FAILURE                    = 0,  /** Everything is OK. */

  /* Failures detected locally. */
  SSH_TLS_FAIL_UNEXPECTED_MESSAGE       = 10, /** Got unexpected message. */
  SSH_TLS_FAIL_BAD_RECORD_MAC           = 20, /** Recvd pckt w/ invalid MAC. */
  SSH_TLS_FAIL_DECRYPTION_FAILED        = 21, /** Cannot decrypt pckt. */
  SSH_TLS_FAIL_RECORD_OVERFLOW          = 22, /** Too big record received. */
  SSH_TLS_FAIL_DECOMPRESSION_FAILURE    = 30, /** Cannot decompress pckt. */
  SSH_TLS_FAIL_HANDSHAKE_FAILURE        = 40, /** No common ciphersuite. */
  SSH_TLS_FAIL_BAD_CERTIFICATE          = 42, /** Rcvd invalid cert chain. */
  SSH_TLS_FAIL_UNSUPPORTED_CERTIFICATE  = 43, /** Rcvd strange cert type. */
  SSH_TLS_FAIL_CERTIFICATE_REVOKED      = 44, /** Got revoked leaf cert. */
  SSH_TLS_FAIL_CERTIFICATE_EXPIRED      = 45, /** Got expired leaf cert. */
  SSH_TLS_FAIL_CERTIFICATE_UNKNOWN      = 46, /** Couldn't just verify cert. */
  SSH_TLS_FAIL_ILLEGAL_PARAMETER        = 47, /** Other party messing w/ hs. */
  SSH_TLS_FAIL_UNKNOWN_CA               = 48, /** Can't find CA peer cert.*/
  SSH_TLS_FAIL_ACCESS_DENIED            = 49, /** We did deny access. */
  SSH_TLS_FAIL_DECODE_ERROR             = 50, /** Got invalid msg. */
  SSH_TLS_FAIL_DECRYPT_ERROR            = 51, /** Handshake crypto-op failed.*/
  SSH_TLS_FAIL_EXPORT_RESTRICTION       = 60, /** HS params out of exp ctrl.*/
  SSH_TLS_FAIL_PROTOCOL_VERSION         = 70, /** Invalid protocol version.*/
  SSH_TLS_FAIL_INSUFFICIENT_SECURITY    = 71, /** Can't accepts client ciph. */
  SSH_TLS_FAIL_INTERNAL_ERROR           = 80, /** This doesn't happen. */
  SSH_TLS_FAIL_USER_CANCELED            = 90, /** Application cannot actually
                                                  get this value. */

  /* Failures claimed by the remote party. */
  SSH_TLS_FAIL_REMOTE_BUG               = 100, /** She is messing somehow. */

  SSH_TLS_FAIL_REMOTE_CERT_BAD          = 150,
  SSH_TLS_FAIL_REMOTE_CERT_UNSUPPORTED  = 151,
  SSH_TLS_FAIL_REMOTE_CERT_REVOKED      = 152,
  SSH_TLS_FAIL_REMOTE_CERT_EXPIRED      = 153,
  SSH_TLS_FAIL_REMOTE_CERT_CA           = 154,
  SSH_TLS_FAIL_REMOTE_CERT_UNKNOWN      = 155,

  SSH_TLS_FAIL_REMOTE_DENY_ACCESS       = 102, /** She rejects us. */
  SSH_TLS_FAIL_REMOTE_INSUFFICIENT_SECURITY
                                        = 103, /** She won't accept our ciph.*/

  /* Other failure reasons. */
  SSH_TLS_FAIL_PREMATURE_EOF            = 200, /** Medium disconn too early. */
  SSH_TLS_FAIL_KEX_TIMEOUT              = 300  /** Local key exch timeout. */

} SshTlsFailureReason;

/** Return the name of the failure reason 'reason'. */
const char *ssh_tls_failure_str(SshTlsFailureReason reason);

/** Request the reason for a failure. */
SshTlsFailureReason ssh_tls_get_failure_reason(SshStream stream);

/** Return the ciphersuite used with the stream.

    @return
    Can return SSH_TLS_CIPHERSUITE_NOT_AVAILABLE. */
SshTlsCipherSuite ssh_tls_get_ciphersuite(SshStream stream);

typedef enum {
  SSH_TLS_CERT_NONE = 0,
  SSH_TLS_CERT_FORGOTTEN = 1,
  SSH_TLS_CERT_OK = 2,
  SSH_TLS_CERT_KEX_IN_PROGRESS = 3
} SshTlsCertQueryResult;

/** Return the certificate chain presented by the remote party.

    @return
    The return value is as follows:

    SSH_TLS_CERT_NONE: The remote party is anonymous.

    SSH_TLS_CERT_FORGOTTEN: The remote party presented certificates
    that have been accepted, but the chain has now been forgotten in
    order to conserve memory.

    SSH_TLS_CERT_OK: A pointer to the chain has been written to
    '*chain_return'. The returned chain remains valid until the end of
    the notification function if called inside one, and otherwise
    until the TLS protocol instance gains control next time save for
    calling ssh_tls_get_ciphersuite, ssh_tls_set_private_key and
    similar functions that do not involve reading or sending protocol
    data. The exception is that if the application calls
    ssh_tls_grab_certs, then the chain remains valid forever and the
    application must free it manually or by calling
    ssh_tls_free_cert_chain.

    The list is ordered so that the first item in the list is the leaf
    certificate and every other certificate assumedly certifies the
    previous one. The self-signed root certificate can be present but
    not necessarily is.

    SSH_TLS_CERT_KEX_IN_PROGESS: Key exchange is in progress and it is
    no known yet whether the other party is going to present a
    certificate or not. This is returned also when full renegotiation
    is taking place and it is not known whether we will get a
    certificate again or not, and if, what kind of. */

SshTlsCertQueryResult ssh_tls_get_cert_chain(SshStream stream,
                                             SshTlsBerCert *chain_return);

/** Free a certificate chain. */
void ssh_tls_free_cert_chain(SshTlsBerCert chain);

/** Get a handle to a cached security context. */

int ssh_tls_get_cache_id(SshStream stream,
                         unsigned char **session_id_return);

/** Invalidate the security context that was cached with the given
    identifier. This is called by the library when a protocol instance
    is terminated due to an error. */
void ssh_tls_invalidate_cached_session(SshTlsSessionCache cache,
                                       unsigned char *id,
                                       int id_len);

/** Get the certificate chain from the protocol instance: after
    calling this function, the current certificate chain will not be
    freed. Later the application must free it like in the following
    example:

    <CODE>
    ssh_tls_get_cert_chain(s, &chain);
    ssh_tls_grab_certs(s);
    ...
    ssh_tls_free_cert_chain(chain);
    </CODE>

    If, for some reason, some BER data must live longer than the
    others, the application can also free the chain piece by piece.
    The SshTlsBerCert objects are dynamically allocated as well as the
    BER data items `ber_data' themselves:

    <CODE>
    while (chain != NULL) {
    temp = chain->next; ssh_free(chain->ber_data); ssh_free(chain);
    chain = temp;
    }
    </CODE>

   */
void ssh_tls_grab_certs(SshStream stream);

#ifdef SSHDIST_VALIDATOR
/** Return TRUE if the (current) certificate chain was successfully
    verified by the certificate manager. Should be called only from
    inside SSH_TLS_PEER_CERTS notification callback.

    Should be called only from inside SSH_TLS_PEER_CERTS nofification
    callback, otherwise the result can be meaningless or even wrong. */
Boolean ssh_tls_chain_verified_by_cm(SshStream stream);


/** Return a pointer to the SshCMSearchInfoRec structure returned by
    the certificate manager for the most recent certificate chain
    verification attempt.

    Should be called only from inside SSH_TLS_PEER_CERTS nofification
    callback, otherwise the result can be meaningless or even wrong.

    @return
    The returned pointer remains valid until the notification callback
    returns.

    Return FALSE if the certificate manager has
    not been consulted at all; then `*info' has not been changed.

    */
Boolean ssh_tls_get_cm_status(SshStream stream,
                              SshCMSearchInfo *info);
#endif /* SSHDIST_VALIDATOR */


/** TLS statistics. */
typedef struct SshTlsStatisticsRec {
  unsigned char remote_address[128]; /** The remote IP address of the
                                         underlying stream,
                                         if it can be determined. */
  unsigned char remote_port[64];/** The remote port number of the underlying
                                    stream if it can be determined. */

  SshUInt64 packets_sent;       /** The number of packets sent. */
  SshUInt64 packets_received;   /** The number of packets received. */
  SshUInt64 bytes_sent;         /** The number of bytes sent. */
  SshUInt64 bytes_received;     /** The number of bytes received. */
  SshUInt64 num_key_exchanges;
                                /** Number of actual key exchanges;
                                    this is zero if only cached
                                    security contexts have been used. */
  SshUInt64 num_context_changes;
                                /** Number of fast key exchanges
                                    (security context updates,
                                    meaning the number of
                                    resumed sessions including
                                    rekeyings). */
  SshUInt64 app_bytes_given;    /** Number of bytes given to application. */
  SshUInt64 app_bytes_got;      /** Number of bytes rcvd from application. */
} *SshTlsStatistics, SshTlsStatisticsStruct;

/** Get statistics. */
void ssh_tls_get_statistics(SshStream stream,
                            SshTlsStatistics ptr);

/* Control the protocol dynamically. */

/** Accept or reject a new connection request. */
void ssh_tls_decide_new_connection_request(SshStream stream, Boolean accept);

/** Accept or reject certificates.

   Should be called only from inside SSH_TLS_PEER_CERTS nofification
   callback. */
void ssh_tls_decide_certs(SshStream stream, Boolean accept);

/** Set the private key to be used for authentication. The key must
    remain valid until the protocol has been destroyed or a new key is
    set.

    If set to NULL, self authentication is not performed. Otherwise a
    certificate manager must be present.

    If id_data is set, it can be used as distinguished name identity
    for the private key. If it is NULL private key has no identity set.

    Should be called only from inside SSH_TLS_AUTH_REQUEST nofification
    callback. */

void ssh_tls_set_private_key(SshStream stream, SshPrivateKey key,
                             unsigned char *id_data, size_t id_data_size);

/** Freeze the protocol so that the application can use some time for
    considering what to do. When this function is called, the TLS
    protocol stops certain actions such as running the negotiation
    process and transporting application data. The protocol then does
    not proceed until the application has called ssh_tls_continue for
    the same stream as ssh_tls_freeze was called for.

    Should be called only from inside notification callbacks. */
void ssh_tls_freeze(SshStream stream);

/** Revive the protocol.

    May not be called if ssh_tls_freeze() has not been called
    previously. There MUST be an equal number of ssh_tls_freeze() and
    ssh_tls_continue() calls for any given protocol instance. */
void ssh_tls_continue(SshStream stream);

/* Cipher suites. */

typedef enum {
  SSH_TLS_KEX_RSA,
  SSH_TLS_KEX_DH,
  SSH_TLS_KEX_DHE,
  SSH_TLS_KEX_DH_ANON,
  SSH_TLS_KEX_NULL,

  SSH_TLS_UNKNOWN_SUITE
} SshTlsKexMethod;

typedef enum {
  SSH_TLS_CIPH_RC4,
  SSH_TLS_CIPH_RC2,
  SSH_TLS_CIPH_IDEA,
  SSH_TLS_CIPH_DES,
  SSH_TLS_CIPH_3DES,
  SSH_TLS_CIPH_AES128,
  SSH_TLS_CIPH_AES256,
  SSH_TLS_CIPH_NULL
} SshTlsCipher;

typedef enum {
  SSH_TLS_SIGN_DSS,
  SSH_TLS_SIGN_RSA,
  SSH_TLS_SIGN_NONE
} SshTlsSignatureMethod;

typedef enum {
  SSH_TLS_MAC_MD5, SSH_TLS_MAC_SHA,
  SSH_TLS_MAC_NULL
} SshTlsMac;

typedef struct {
  SshTlsKexMethod kex_method;
  SshTlsSignatureMethod signature_method;
  SshTlsCipher cipher;
  SshTlsMac mac;
  Boolean crippled;
  const char *friendly_name;
  SshUInt32 ciphersuite_code;
} *SshTlsCipherSuiteDetails, SshTlsCipherSuiteDetailsStruct;

/** Parse the ciphersuite 'suite' into its distinct components.  Fill
    the structure 'details'.

    @return
    If the given suite is not a valid one the field 'kex_method' will
    be set to the special value SSH_TLS_UNKNOWN_SUITE and the
    remaining fields become undefined. */

void ssh_tls_get_ciphersuite_details(SshTlsCipherSuite suite,
                                     SshTlsCipherSuiteDetails details);


#ifdef SSHDIST_EAP_TLS
/** Extract the master key for the EAP method EAP-TLS.

   @param stream
   The wrapped TLS stream.

   @param key
   The allocated key is returned in this buffer

   @param keylen
   The size of returned key is returned in this variable

   @return
   FALSE: If unable to get stream context properly.

   TRUE:  If key and keylen contain valid values.

*/
Boolean ssh_tls_get_eap_master_key(SshStream stream,
                                   unsigned char **key,
                                   size_t *keylen);

/** Extract the Session-Id for the EAP method EAP-TLS.

   @param stream
   The wrapped TLS stream.

   @param id
   The allocated id is returned in this buffer

   @param idlen
   The size of returned id is returned in this variable

   @return
   FALSE: If unable to get session id.

   TRUE:  If key and keylen contain valid values.

*/
Boolean ssh_tls_get_eap_session_id(SshStream stream,
                                   unsigned char **id,
                                   size_t *idlen);
#endif /* SSHDIST_EAP_TLS */

#endif /* SSHTLS_H_INCLUDED */
