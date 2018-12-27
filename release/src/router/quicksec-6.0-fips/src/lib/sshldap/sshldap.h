/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   LDAPv3 client side API at extend needed when using LDAP to access PKI
   related information.


   * Introduction to Operation *

   The operations with LDAP typically consist of the following steps:

   * <B>Initializing the LDAP library</B>. This operation allocates the
     LDAP client context and defines the configuration parameters. It is
     implemented with the SshLdapClientParams structure, and with the
     ssh_ldap_client_create function.

   * <B>Connections to the LDAP server</B>. This operation is done by
     using the ssh_ldap_client_connect function.

   * <B>Binding the connection</B>. This operation is done by using the
     ssh_ldap_client_bind function.

   * <B>Doing a search in the database</B>.  This operation involves
     searching data with a certain filter. The actual function performing
     the search is ssh_ldap_client_search.  Filters can be created with
     ssh_ldap_string_to_filter or manually by creating the
     SshLdapSearchFilter structure.

   * <B>Unbinding and disconnecting</B>. These operations are performed
     by calls to ssh_ldap_client_disconnect and ssh_ldap_client_destroy
     functions.

   Connecting and binding without TLS being involved is hidden behind a
   convenience API function ssh_ldap_client_connect_and_bind.


   * Initialization of LDAP client *

   Before any other operations can be done, the LDAP client must be
   initialized with the ssh_ldap_client_create function. This functions
   takes structure defining default configuration parameters as an
   argument and copies them to the internal context that is returned.
   This SshLdapClient context is then given to all the other LDAP library
   client functions. The ssh_ldap_client_destroy function may be used to
   release all data structures and resources allocated by the LDAP
   client.

   Each SshLdapClient context may only be connected to one LDAP server at
   a time. If multiple concurrent LDAP connections are needed multiple
   LDAP clients must be initialized. Each of these clients is completely
   separate from each other.


   * General Data Types and Enums *

   Each of the LDAP functions takes SshLdapClient context as a first
   argument. Each LDAP operation (a function that sends an operation to
   LDAP server), except ssh_ldap_client_unbind, returns an
   SshOperationHandle pointer. This pointer may be used to abort the
   operation later by using ssh_operation_abort.

   LDAP server result codes are returned in the SshLdapResult code. Each
   positive code is reserved for LDAP protocol errors, while negative
   error codes are reserved for internal errors.


   * Connecting and Disconnecting *

   Before the LDAP client can send any commands to the LDAP server, it
   needs to connect to it. If the user wants to have control over the
   connection attempts and disconnects, she may call the
   ssh_ldap_client_connect function. The user gives an SshLdapConnectCB
   callback to that function. That callback is then used to inform the
   user when something happens in the connection status of the LDAP
   library.

   The ssh_ldap_client_connect function may also be used to change the
   connected LDAP server. Previous connections have to be torn down by a
   call to ssh_ldap_client_disconnect first.  If multiple concurrent
   connections to LDAP servers are needed, then multiple SshLdapClient
   structures are needed.


   * Binding and Unbinding Connections *

   The first operation after connecting that must be sent to the LDAP
   server is bind. This operation tells the server the username and the
   password of the connecting user.  Normally, both username and password
   are empty, meaning that an anonymous bind is wanted. Most servers only
   allow searches if an anonymous bind was used when connecting.


   * Aborting Operations and Processing Replies and Errors *

   Each LDAP operation function returns an SshOperationHandle that may be
   used to abort that operation later. Also, each operation function can
   be given a callback function that is called when a operation finishes.
   If given, this callback function is called unless the operation is
   aborted with call to ssh_operation_abort.


   * Starting Search *

   The ssh_ldap_client_search function can be used for starting LDAP
   searches.


   * Search Filters *

   SshLdapFilterOperator specifies the filter that is used for searching
   for entries in the directory.

   The SshLdapSearchFilter filter handle given to the
   ssh_ldap_client_search function to specify the conditions that must be
   fulfilled in order for the search to match a given entry.

    * ssh_ldap_string_to_filter
    * ssh_ldap_filter_to_string
    * ssh_ldap_free_filter


   * Processing Search Data *

     * SshLdapResultInfoRec
     * SshLdapSearchResultCB
     * SshLdapAttributeRec
     * SshLdapObjectRec
     * ssh_ldap_free_object
     * ssh_ldap_duplicate_object


   * Other LDAP Operations *

   The LDAP server can also allow operations other than normal searching.
   These operations include modifying entries in the directory, adding
   new entries to the directory, removing entries from the directory,
   comparing an entry with given values and moving entries around in the
   directory tree.

   In most servers these operations are only allowed if a non-anonymous
   bind is used. Enabling non-anonymous binds in a server can cause
   security risks.

     * modifying LDAP entries: ssh_ldap_client_modify
     * adding LDAP entries: ssh_ldap_client_add
     * deleting LDAP entries: ssh_ldap_client_delete
     * moving LDAP entries: ssh_ldap_client_modify_rdn
     * comparing LDAP entries: ssh_ldap_client_compare
     * extending LDAP entries: ssh_ldap_client_extension


   * Convenience API *

   The convenience API hides complex connect-bind-perform callback
   sequences.

      * ssh_ldap_search_url
      * ssh_ldap_client_search_url
      * ssh_ldap_client_connect_and_bind


   * Transport Layer Security (TLS) *

   The ssh_ldap_client_enable_tls function can be used for enabling a
   Transport Layer Security (TLS) connection.


   * LDAP Libary Object Reference *
*/

#ifndef SSHLDAP_H
#define SSHLDAP_H

#include "sshenum.h"
#include "sshtcp.h"
#include "sshoperation.h"

/*--------------------------------------------------------------------*/
/* LDAP client data types and defined values                          */
/*--------------------------------------------------------------------*/

/** LDAP protocol version. */
typedef enum {
  /** Use LDAP version 2. */
  SSH_LDAP_VERSION_2 = 2,

  /** Use LDAP version 3. */
  SSH_LDAP_VERSION_3 = 3
} SshLdapVersion;

/** LDAP client handle. */
typedef struct SshLdapClientRec *SshLdapClient;

/** LDAP Operation Result Codes. See the LDAP specifications for
    further details.

    @see SshLdapClientResultCB
    @see ssh_ldap_client_disconnect
    @see ssh_ldap_error_code_to_string

    */
typedef enum {

  /** The operation ended successfully */
  SSH_LDAP_RESULT_SUCCESS                       = 0,

  /** The operation resulted in an unspecified error. */
  SSH_LDAP_RESULT_OPERATIONS_ERROR              = 1,

  /** Protocol error occurred, server did not understand what we said. */
  SSH_LDAP_RESULT_PROTOCOL_ERROR                = 2,

  /** Search time limit exceeded, the search result will be truncated. */
  SSH_LDAP_RESULT_TIME_LIMIT_EXCEEDED           = 3,

  /** Search size limit exceeded, the search result will be truncated. */
  SSH_LDAP_RESULT_SIZE_LIMIT_EXCEEDED           = 4,

  /** Compare operation returns this error when attribute value
      assertions did not match. */
  SSH_LDAP_RESULT_COMPARE_FALSE                 = 5,

  /** Compare operation returns this error when attribute value
      assertions mathed. */
  SSH_LDAP_RESULT_COMPARE_TRUE                  = 6,

  /** The requested authentication method is not supported by the server. */
  SSH_LDAP_RESULT_AUTH_METHOD_NOT_SUPPORTED     = 7,

  /** Server requires a stronger authentication method to be used. */
  SSH_LDAP_RESULT_STRONG_AUTH_REQUIRED          = 8,

  /** Referral. (Only relevant for LDAPv3.) */
  SSH_LDAP_RESULT_REFERRAL                      = 10,

  /** The admin limit has been exceeded. */
  SSH_LDAP_RESULT_ADMINLIMITEXCEEDED            = 11,

  /** A critical extension is not available. */
  SSH_LDAP_RESULT_UNAVAILABLECRITICALEXTENSION  = 12,

  /** Confidentiality is required. */
  SSH_LDAP_RESULT_CONFIDENTIALITYREQUIRED       = 13,

  /** A SASL bind is in progress. */
  SSH_LDAP_RESULT_SASLBINDINPROGRESS            = 14,

  /** An attribute was not found from the object. */
  SSH_LDAP_RESULT_NO_SUCH_ATTRIBUTE             = 16,

  /** The attribute type was undefined. */
  SSH_LDAP_RESULT_UNDEFINED_ATTRIBUTE_TYPE      = 17,

  /** Inappropriate matching has occurred. */
  SSH_LDAP_RESULT_INAPPROPRIATE_MATCHING        = 18,

  /** A constraint violation has occurred. */
  SSH_LDAP_RESULT_CONSTRAINT_VIOLATION          = 19,

  /** The operation could not be carried out because the attribute
      or the value already exists. */
  SSH_LDAP_RESULT_ATTRIBUTE_OR_VALUE_EXISTS     = 20,

  /** The attribute syntax is not valid. */
  SSH_LDAP_RESULT_INVALID_ATTRIBUTE_SYNTAX      = 21,

  /** The operation could not be carried out because the base object
      could not be found. */
  SSH_LDAP_RESULT_NO_SUCH_OBJECT                = 32,

  /** An LDAP alias problem has occurred. */
  SSH_LDAP_RESULT_ALIAS_PROBLEM                 = 33,

  /** The base distinguished name has an invalid format. */
  SSH_LDAP_RESULT_INVALID_DN_SYNTAX             = 34,

  /** This operation is not allowed on a leaf node. */
  SSH_LDAP_RESULT_IS_LEAF                       = 35,

  /** There was a problem when dereferencing an alias. */
  SSH_LDAP_RESULT_ALIAS_DEREFERENCING_PROBLEM   = 36,

  /** The authentication provided does not provide enough information
      to determine access control. */
  SSH_LDAP_RESULT_INAPPROPRIATE_AUTHENTICATION  = 48,

  /** The credentials are invalid or expired. */
  SSH_LDAP_RESULT_INVALID_CREDENTIALS           = 49,

  /** The credentials provided do not allow access to the requested object. */
  SSH_LDAP_RESULT_INSUFFICIENT_ACCESS_RIGHTS    = 50,

  /** The server is too busy at the moment, try again later. */
  SSH_LDAP_RESULT_BUSY                          = 51,

  /** The server is not available at the moment. */
  SSH_LDAP_RESULT_UNAVAILABLE                   = 52,

  /** Server administration rejected the operation for some reason. */
  SSH_LDAP_RESULT_UNWILLING_TO_PERFORM          = 53,

  /** A loop was detected. */
  SSH_LDAP_RESULT_LOOP_DETECT                   = 54,

  /** A naming violation has occurred. */
  SSH_LDAP_RESULT_NAMING_VIOLATION              = 64,

  /** An object class violation has occurred. */
  SSH_LDAP_RESULT_OBJECT_CLASS_VIOLATION        = 65,

  /** The operation is not allowed on a non-leaf node. */
  SSH_LDAP_RESULT_NOT_ALLOWED_ON_NON_LEAF       = 66,

  /** The operation is not allowed on relative distinguished names. */
  SSH_LDAP_RESULT_NOT_ALLOWED_ON_RDN            = 67,

  /** The operation was not performed because the entry already exists. */
  SSH_LDAP_RESULT_ENTRY_ALREADY_EXISTS          = 68,

  /** A modification operation is not allowed on the subject. */
  SSH_LDAP_RESULT_OBJECT_CLASS_MODS_PROHIBITED  = 69,

  /** Affects multiple DSAs. (Only relevant for LDAPv3.) */
  SSH_LDAP_RESULT_AFFECTSMULTIPLEDSAS           = 71,

  /** Catchall error code, nothing else applies, or server internal error. */
  SSH_LDAP_RESULT_OTHER                         = 80,

  /** Codes reserved for APIs. */

  /** The operation was aborted because of a disconnect or abort request.
      (This code is reserved for APIs.) */
  SSH_LDAP_RESULT_ABORTED                       = 81,

  /** This status code is returned by ssh_ldap_client_disconnect or
  ssh_ldap_client_connect to indicate that a connection attempt is
  still in progress and it cannot be disconnected before the
  connection attempt finishes. (This code is reserved for APIs.) */
  SSH_LDAP_RESULT_IN_PROGRESS                   = 82,

  /** An internal error occurred. (This code is reserved for APIs.) */
  SSH_LDAP_RESULT_INTERNAL                      = 83,

  /** Disconnected. (This code is reserved for APIs.) */
  SSH_LDAP_RESULT_DISCONNECTED                  = 84
} SshLdapResult;

/** LDAP error code to string mapping using sshkeywords.h */
extern const SshKeywordStruct ssh_ldap_error_keywords[];

/** This convenience function converts LDAP error codes to US English
    strings.

    @param code
    The error code.

    @return
    Returns a pointer to a constant string that describes the error code.

    */
const char *ssh_ldap_error_code_to_string(SshLdapResult code);

/** Structure to provide LDAP result to the application. */
typedef struct SshLdapResultInfoRec
{
  /** Distinguished Name matched during query, and its length. */
  unsigned char *matched_dn;
  size_t matched_dn_len;

  /** Optional error message provided by the server. */
  unsigned char *error_message;
  size_t error_message_len;

  /** Array of referrals. Each element in the array whose size is
      'number_of_referrals' is a pointer to a nul-terminated
      C-string. */
  size_t number_of_referrals;
  char **referrals;

  /** LDAP extension mechanism, including Name (OID) of the extension,
      and the extension specific data and its length. */
  char *extension_name;
  unsigned char *extension_data;
  size_t extension_data_len;
} *SshLdapResultInfo, SshLdapResultInfoStruct;

/** LDAP operation result callback.

    This callback is called after each operation is finished,
    e.g. once for each operation that is not aborted by the caller. */
typedef void
(*SshLdapClientResultCB)(SshLdapClient client,
                         SshLdapResult result,
                         const SshLdapResultInfo info,
                         void *callback_context);

/** TLS wrapping result callback.

    This callback is called after tls start request has finished. This
    needs to wrap the plaintext 'ldap_stream' into TLS stream which
    this returns. */
typedef SshStream
(*SshLdapClientWrapCB)(SshLdapClient client,
                       SshLdapResult result,
                       const SshLdapResultInfo info,
                       SshStream ldap_stream,
                       void *callback_context);

/** LDAP attribute list. This containts all values for single
   attribute type. */
typedef struct SshLdapAttributeRec {
  /** Allocated attribute type and its size. */
  unsigned char *attribute_type;
  size_t attribute_type_len;

  /** Number of attribute values. */
  int number_of_values;

  /** Allocated table of allocated attribute values and respective
      sizes. */
  unsigned char **values;
  size_t *value_lens;
} *SshLdapAttribute;

/** LDAP search result object and public operations on the object
    type.  This object contains information about one object in the
    LDAP directory server. The object_name is DN to the object
    found. */
typedef struct SshLdapObjectRec {
  /** Allocated object name and its length. */
  unsigned char *object_name;
  size_t object_name_len;

  /** Number of attributes in the object, and the allocated attributes
      table of size 'number_of_attributes'. */
  int number_of_attributes;
  SshLdapAttribute attributes;
} *SshLdapObject;

/** This function frees a LDAP object */
void ssh_ldap_free_object(SshLdapObject object);

/** This function duplicates a LDAP object.

    If null_terminated is TRUE, the strings at the source object are
    null-terminated and the lengths are discarded. The source object
    is not modified. */
SshLdapObject ssh_ldap_duplicate_object(const SshLdapObject object,
                                        Boolean null_terminated);


/** LDAP search result callback.

    This will be called once for each object found (resulted).  After
    all search result objects have been processed the
    SshLdapClientResultCB will be called to notify search has
    completed and this will not be called again for the same
    operation.

    The copy of object found is given to the this function and it is
    responsible of freeing it after it is not needed any more. */
typedef void (*SshLdapSearchResultCB)(SshLdapClient client,
                                      SshLdapObject object,
                                      void *callback_context);


/** LDAP connect callback.

    This receives the result of LDAP connect operation, which must
    always be done using the API function ssh_ldap_client_connect().
    On successful connection the 'status' contain SSH_TCP_OK.

    */
typedef void (*SshLdapConnectCB)(SshLdapClient client,
                                 SshTcpError status,
                                 void *callback_context);

/** LDAP client parameters.

The LDAP configuration parameter structure given to the
ssh_ldap_client_create function. This structure must be initialized
with the value zero, before filling it in, so that if new fields are
added to the structure, they will get the default values
automatically. The default value is always indicated by either the
number zero or a NULL pointer.

ssh_ldap_client_create will copy everything from this structure to its
internal data structures, so that a caller may immediately free this
structure and all data inside after the ssh_ldap_client_create
function returns.

@see ssh_ldap_client_create
@see ssh_ldap_client_destroy

*/
typedef struct SshLdapClientParamsRec {
  /** SOCKS server URI - the default is not to use SOCKS. */
  unsigned char *socks;

  /** Number of connection attempts: 0 means the default value, which
      is one. */
  int connection_attempts;

  /** The maximum number of simultaneus LDAP operations performed using
      same client handle - the default (that is used if this value is zero)
      is five. */
  int maxoperations;

  /** The number of seconds the LDAP server is allowed to process the
      request - if no value is given, the value zero is used, and the
      server policy decides the actual value. */
  int request_timelimit;

  /** The maximum number of objects in the response - this value is sent
      to the server as a hint, and it is up the server policy to decide if it
      should be enforced or not (the server can also always default to
      a smaller limit); when set to zero the limit is disabled. */
  int response_sizelimit;

  /** The maximum number of bytes in the response, enforced by the
      client - if input exceeds this value, the connection is
      closed (set to zero to disable). */
  int response_bytelimit;

  /** The version number of the LDAP protocol used by this client -
      note that the search and modify operations will fail on client code
      if version is 2 and bind has not been performed; the default
      value is two. */
  SshLdapVersion version;

  /** LDAP version 2 flavored TLS wrapping. */
  SshLdapClientWrapCB stream_wrap;
  void *stream_wrap_context;

  /** TCP connection timeout. Number of seconds to wait for the server
      to respond our TCP handshake. If zero, the underlying OS default
      will be used. */
  SshUInt32 tcp_connect_timeout;

} *SshLdapClientParams, SshLdapClientParamsStruct;


/*--------------------------------------------------------------------*/
/*  LDAP client operations                                            */
/*--------------------------------------------------------------------*/

/** Allocate the LDAP client and fill it with the configuration parameters
    given in the params argument.

    The input parameters, which may be a NULL pointer, is used only
    within this call, and can be freed after the call returns.  The
    'params' may be NULL, in which case default values are used.

    The returned SshLdapClient structure is given to all other LDAP
    client functions and it is only destroyed by the
    ssh_ldap_client_destroy function.

    @param params
    Configuration parameters used for the LDAP connection.

    @return

    The ssh_ldap_client_create function returns a handle to be used
    in all other LDAP library functions, or NULL if memory
    allocation for a new client fails.

    @see ssh_ldap_client_destroy
    @see SshLdapClient
    @see SshLdapClientParams

   */
SshLdapClient ssh_ldap_client_create(const SshLdapClientParams params);

/** Destroy LDAP client. This function tries to abandon currently
    active LDAP operations using the client, and disconnects the client
    from the server. It does not return before all callbacks to those
    operations are called with the SSH_LDAP_RESULT_ABORTED error code.

    Note: One should call ssh_operation_abort() for all pending
    operations before calling this to avoid memory leaks, or risk for
    NULL or free pointer dereference.

    @param client
    A pointer to the LDAP client to destroy.

    @see ssh_ldap_client_create
    @see ssh_ldap_client_disconnect
    @see SshLdapClient

   */
void ssh_ldap_client_destroy(SshLdapClient client);


/*--------------------------------------------------------------------*/
/*  LDAP operations on client, connect, disconnect, bind, unbind.     */
/*--------------------------------------------------------------------*/

/** This function opens connection to a LDAP server.

    If the LDAP connection is closed by the server, after having been
    successfully established, this information will be passed to using
    application next time it performs an operation (result callback
    with disconnected status).

    Note: This function must not be called, if the LDAP client given
    is already connected to any server. For reconnect, existing
    connections must first be disconnected. This can be called, if
    search/modify operations have failed with status
    SSH_LDAP_RESULT_DISCONNECTED.

    @param client
    The LDAP client.

    @param ldap_server_name
    The IP number or DNS name for the LDAP server to connect to.

    @param ldap_server_port
    The port number, or service entry name.

    @param callback
    The connection notification callback, called when connection is
    established or has failed.

    @param callback_context
    The context to the connection notification callback.

    @see ssh_ldap_client_create
    @see ssh_ldap_client_destroy
    @see ssh_ldap_client_bind
    @see ssh_ldap_client_disconnect

*/
SshOperationHandle
ssh_ldap_client_connect(SshLdapClient client,
                        const unsigned char *ldap_server_name,
                        const unsigned char *ldap_server_port,
                        SshLdapConnectCB callback,
                        void *callback_context);

/** This function disconnects from a LDAP server. Disconnection is
    also done automatically if it is not done before destroying the
    client.

    Note: If there are any operations in progress, they are
    immediately aborted and SshLdapClientResultCB is called with
    the error code SSH_LDAP_RESULT_ABORTED.

    Note that this cannot be used to abort ssh_ldap_client_connect.

    @return

    If the connection is still in progress, this returns an
    SSH_LDAP_RESULT_IN_PROGRESS error message, otherwise it
    returns SSH_LDAP_RESULT_SUCCESS.

    @see ssh_ldap_client_create
    @see ssh_ldap_client_destroy
    @see ssh_ldap_client_unbind
    @see ssh_ldap_client_connect

    */
void ssh_ldap_client_disconnect(SshLdapClient client);

/** This function performs a LDAP bind operation (simple mechanism).

    This will bind authentication information to the existing
    connected LDAP client. One can bind the same client multiple
    times.  Binding is not neccessary for the protocol version 3. */
SshOperationHandle
ssh_ldap_client_bind(SshLdapClient client,
                     const unsigned char *bind_name, size_t bind_name_len,
                     const unsigned char *password, size_t password_len,
                     SshLdapClientResultCB callback, void *callback_context);

/** This function performs a LDAP bind operation authenticating with
    SASL. */
SshOperationHandle
ssh_ldap_client_bind_sasl(SshLdapClient client,
                          const char *sasl_mechanism,
                          const unsigned char *bind_name,
                          size_t bind_name_len,
                          const unsigned char *credentials,
                          size_t credentials_len,
                          SshLdapClientResultCB callback,
                          void *callback_context);

/** This function performs a LDAP unbind operation.

    After client is unbound, further operations requiring
    authentication will be denied by the LDAP server.

    This is also done automatically before disconnect, and after this
    only disconnect operation is allowed. */
void ssh_ldap_client_unbind(SshLdapClient client);

/*--------------------------------------------------------------------*/
/*  LDAP read-only operations on client, search and compare.          */
/*--------------------------------------------------------------------*/

/** Scope of the search */
typedef enum {
  SSH_LDAP_SEARCH_SCOPE_BASE_OBJECT                     = 0,
  SSH_LDAP_SEARCH_SCOPE_SINGLE_LEVEL                    = 1,
  SSH_LDAP_SEARCH_SCOPE_WHOLE_SUBTREE                   = 2
} SshLdapSearchScope;

/** Alias dereference options */
typedef enum {
  SSH_LDAP_DEREF_ALIASES_NEVER                          = 0,
  SSH_LDAP_DEREF_ALIASES_IN_SEARCHING                   = 1,
  SSH_LDAP_DEREF_ALIASES_FINDING_BASE_OBJECT            = 2,
  SSH_LDAP_DEREF_ALIASES_ALWAYS                         = 3
} SshLdapDerefAliases;

/** LDAP Attribute value assertion structure */
typedef struct SshLdapAttributeValueAssertionRec {
  unsigned char *attribute_type;
  size_t attribute_type_len;
  unsigned char *attribute_value;
  size_t attribute_value_len;
} *SshLdapAttributeValueAssertion;

/** LDAP Search filter handle.
    Notice on the usage. The preferred way to use filters on the
    application is to use the string->filter conversion routines
    instead of filling the structure directly. */

typedef struct SshLdapSearchFilterRec *SshLdapSearchFilter;

/** Convert LDAP Search filter string (as in RFC1960) to
    SshLdapSearchFilter structure which this function
    allocates. Returns TRUE if successfull, and FALSE in case of
    error. */
Boolean ssh_ldap_string_to_filter(const unsigned char *string,
                                  size_t string_len,
                                  SshLdapSearchFilter *filter);

/** Convert SshLdapSearchFilter to string, which this function
    allocates. TRUE if successfull, and FALSE in case of error.*/
Boolean ssh_ldap_filter_to_string(SshLdapSearchFilter filter,
                                  unsigned char **string,
                                  size_t *string_len);

/** Free SshLdapSearchFilter structure. */
void ssh_ldap_free_filter(SshLdapSearchFilter filter);


/** Perform an LDAP search operation.

    Search can be used to read attributes from single entry, from
    entries immediately below given entry, or from a subtree.

    - 'base_object' is the DN relative to which the search is performed.
    - 'scope' indicates what to return relative to base object.
    - 'deref' indicates if, and when, the server is to expand aliases.
    - 'size_limit' restricts the maximum number of objects returned.
    - 'time_limit' restricts the time used for the search.
    - 'attributes_only' indicates if result should contain values as well.
    - 'filter' that defines conditions the entry must fullfill as a match.
    - 'number_of_attributes' is the size of 'attribute_types'
       and 'attribute_type_lens' arrays.
    - 'attributes' indicate what to return from each matching entry.
       Each attribute may only appear once in the list. Special value '*'
       may be used to fetch all user attributes (unless access control
       denies these to be included).

    If 'size_limit' or 'time_limit' are negative, the value given at
    the client configuration is used. For non negative values these are
    hints for the server. The server policy may decide other values to
    be used.

    The given 'search_callback' will be called once for each matching
    object, and 'callback' once for each search made. The resulting
    object may be a referral, in which case the application should
    perform a new search, with a new client. */

SshOperationHandle
ssh_ldap_client_search(SshLdapClient client,
                       const char *base_object,
                       SshLdapSearchScope scope,
                       SshLdapDerefAliases deref,
                       SshInt32 size_limit,
                       SshInt32 time_limit,
                       Boolean attributes_only,
                       SshLdapSearchFilter filter,
                       int number_of_attributes,
                       unsigned char **attribute_types,
                       size_t *attribute_type_lens,
                       SshLdapSearchResultCB search_callback,
                       void *search_callback_context,
                       SshLdapClientResultCB callback,
                       void *callback_context);


/** This function performs a LDAP compare operation at server.

    Compare an assertion provided with an entry in the directory.

    - 'object_name' is the name of entry at directory to compare against.
    - 'ava' is the attribute-value pair to compare.

    The result 'callback' will receive comparison result as its
    'result' status. */

SshOperationHandle
ssh_ldap_client_compare(SshLdapClient client,
                        const unsigned char *object_name,
                        size_t object_name_len,
                        SshLdapAttributeValueAssertion ava,
                        SshLdapClientResultCB callback,
                        void *callback_context);


/*--------------------------------------------------------------------*/
/*  LDAP read-write operations on client, modifications               */
/*--------------------------------------------------------------------*/

/** Modify operation codes */
typedef enum {
  SSH_LDAP_MODIFY_ADD = 0,
  SSH_LDAP_MODIFY_DELETE = 1,
  SSH_LDAP_MODIFY_REPLACE = 2
} SshLdapModifyOperation;

/** This function performs an LDAP modify operation.

    - 'object_name' describes the DN to be modified (no dereferencing).
    - 'number_of_operations' is size of 'operations' and 'attributes' arrays.
    - 'operations' and 'attributes' describe the changes to be made in
       this order as single atomic operation (e.g individual entries may
       violate schema, but the result must be according to the scheme).

    The result 'callback' will indicate if modification was successful, and
    possible failure reasons. */

SshOperationHandle
ssh_ldap_client_modify(SshLdapClient client,
                       const unsigned char *object_name,
                       size_t object_name_len,
                       int number_of_operations,
                       SshLdapModifyOperation *operations,
                       SshLdapAttribute attributes,
                       SshLdapClientResultCB callback,
                       void *callback_context);

/** This function performs a LDAP add.

   - 'object' is the object to add. It is added to location specified by
     the 'object_name' at the 'object'. The object life-time for the object
     is this call. The server will not dereference aliases while adding.
     The entry with 'object_name' must not exists while this is called.

   The result 'callback' indicates if the object was added. */

SshOperationHandle
ssh_ldap_client_add(SshLdapClient client,
                    const SshLdapObject object,
                    SshLdapClientResultCB callback,
                    void *callback_context);

/** Perform a LDAP delete.

   - 'object_name' is the name of object to delete. Aliases are not
      dereferenced for the object to be found. Also the name must specify
      a leaf entry (e.g. with no subentries).

   The result 'callback' indicates if the object was deleted. */

SshOperationHandle
ssh_ldap_client_delete(SshLdapClient client,
                       const unsigned char *object_name,
                       size_t object_name_len,
                       SshLdapClientResultCB callback,
                       void *callback_context);

/** Perform a LDAP modify RDN.

   This operation is used to change the leftmost (least significant)
   component of the name of an entry in the directory, or to move a
   subtree of entries to a new location in the directory.

   - 'object_name' identifies an existing object (whose leftmost component
      is to be changed)
   - 'new_rdn' identifies new value for the leftmost component
      of 'object_name'
   - 'delete_old_rdn' indicates if to keep old RDN as an attribute of
      the entry.

   The result 'callback' indicates if the object was renamed. */

SshOperationHandle
ssh_ldap_client_modify_rdn(SshLdapClient client,
                           const unsigned char *object_name,
                           size_t object_name_len,
                           const unsigned char *new_rdn,
                           size_t new_rdn_len,
                           Boolean delete_old_rdn,
                           SshLdapClientResultCB callback,
                           void *callback_context);

/** Perform a LDAP extension request.

   This operation sends the extension identifier 'oid' and DER coded
   'ext_data' to the server. The result callback will receive the
   server's respose in the SshLdapResultInfo's extension_name
   (contains oid) and extension_data (contains DER) fields. */

SshOperationHandle
ssh_ldap_client_extension(SshLdapClient client,
                          const char *oid,
                          unsigned char *ext_data, size_t ext_data_len,
                          SshLdapClientResultCB callback,
                          void *callback_context);

/** Perform a LDAP search using a LDAP URL.

   Search object from location given at LDAP URL at 'url'.

   The 'params' value will describe parameters used for the clients
   created to perform the search. This call will automatically create
   a new LDAP client, connect and bind it.  If the 'url' does not
   specify server address this will immediately fail with 'callback'
   being called with SSH_LDAP_RESULT_INTERNAL.

   If the 'url' does not specify bind name and password, an anonymous
   bind (if protocol version 2), or no bind for version 3 protocol,
   will be tried. If this fails the 'callback' will be called with
   status of SSH_LDAP_RESULT_AUTH_METHOD_NOT_SUPPORTED.

   LDAP URL format is as follows:

   <CODE>
   ldap://[user:pass@]
           host[:port]/base[?attrs[?scope?filter]]
   </CODE>

   @see ssh_ldap_client_search_url

*/

SshOperationHandle
ssh_ldap_search_url(SshLdapClientParams params,
                    const unsigned char *url,
                    SshLdapSearchResultCB search_callback,
                    void *search_callback_context,
                    SshLdapClientResultCB callback,
                    void *callback_context);


/** Perform a LDAP search using a LDAP URL.

   Search object from location given at LDAP URL at 'url'.

   The 'client' is created, connected, and bound by the caller. The
   'url' should not specify server address, or binding information.

   A search described at URL will be made. When search results have
   been processed (after 'callback' having been called that is), the
   temporary client created will be destroyed. If one wishes to follow
   referrals, new ssh_ldap_client_search_url() should be called with
   the referred object URL.

   LDAP URL format is as follows:

   <CODE>
   ldap://[user:pass@]
           host[:port]/base[?attrs[?scope?filter]]
   </CODE>

   @see ssh_ldap_search_url

*/

SshOperationHandle
ssh_ldap_client_search_url(SshLdapClient client,
                           const unsigned char *url,
                           SshLdapSearchResultCB search_callback,
                           void *search_callback_context,
                           SshLdapClientResultCB callback,
                           void *callback_context);

/** Connect and bind the client into 'server'. Call result callback
   when bind is done is done. If 'wrap_callback' is not a NULL
   pointer, It will be called right after the connect has been
   established, before bind is performed. */
SshOperationHandle
ssh_ldap_client_connect_and_bind(SshLdapClient client,
                                 const unsigned char *server,
                                 const unsigned char *port,
                                 SshLdapClientWrapCB wrap_callback,
                                 const unsigned char *bind_name,
                                 size_t bind_name_len,
                                 const unsigned char *password,
                                 size_t password_len,
                                 SshLdapClientResultCB callback,
                                 void *callback_context);

/** LDAP version 3 way to enable TLS on a connected client. This should
   be done prior to bind operation if password based authentication is
   used and the server supports TLS. This can be done at any point
   later, when there are no outstanding requests on the client.

   The TLS 'configuration' has to remain valid until the callback gets
   called, and if the callback indicates success, the contents of the
   configuration need to remain valid as long as the client is
   connected. */
SshOperationHandle
ssh_ldap_client_enable_tls(SshLdapClient client,
                           SshLdapClientWrapCB callback,
                           void *callback_context);

#endif /* SSHLDAP_H */
