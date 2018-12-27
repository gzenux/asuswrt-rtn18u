/**
   @copyright
   Copyright (c) 2004 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   IKEv2 utility functions.
*/

#ifndef SSH_IKEV2_UTIL_H
#define SSH_IKEV2_UTIL_H

/** Macro for min. */
#define       SSH_MIN(a,b)    (((a) < (b)) ? (a) : (b))

/** Macro for max. */
#define       SSH_MAX(a,b)    (((a) > (b)) ? (a) : (b))

/* *********************************************************************/

/** Return time when the last input packet for the given IKE SA was
    received from the peer.

    @param sa
    IKE Security Association

*/
SshTime
ssh_ikev2_sa_last_input_packet_time(SshIkev2Sa sa);

/* *********************************************************************/

/** Generate keying material for the IPsec SA.

    @param ed
    The exchange data.

    @param keymat
    The keymat value is filled with the keying material.

    @param keymat_len
    The length of the key material.

    */
SshIkev2Error ssh_ikev2_fill_keymat(SshIkev2ExchangeData ed,
                                    unsigned char *keymat,
                                    size_t keymat_len);

/* *********************************************************************/


/** Allocate a Traffic Selector. The initial traffic selector
    is empty. This will take it from the free list in SAD, or
    return NULL if no entries are available. This will
    automatically take one reference to the traffic selector.
    This function will be provided by the application
    (Policy Manager).

    @param sad_handle
    Security Association Database handle.

    @return
    The function returns NULL if no Traffic Selector entries are available.

    */
SshIkev2PayloadTS
ssh_ikev2_ts_allocate(SshSADHandle sad_handle);

/** Free a traffic selector. This will return the TS back to the
    free list if this was the last reference. This function
    will be provided by the application (Policy Manager).

    @param sad_handle
    Security Association Database handle.

    @param ts
    The traffic selector to be freed.

    */
void
ssh_ikev2_ts_free(SshSADHandle sad_handle,
                  SshIkev2PayloadTS ts);

/** Duplicate a traffic selector. This will take a new entry
    from the free list and copy data from the current traffic
    selector into it.

    @param sad_handle
    Security Association Database handle.

    @param ts
    The traffic selector to be duplicated.

    @return
    This will return NULL if no free traffic selectors are available.

   */
SshIkev2PayloadTS
ssh_ikev2_ts_dup(SshSADHandle sad_handle,
                 SshIkev2PayloadTS ts);

/** Take an extra reference to the traffic selector.

    @param sad_handle
    Security Association Database handle.

    @param ts
    Traffic Selector

*/
void
ssh_ikev2_ts_take_ref(SshSADHandle sad_handle,
                      SshIkev2PayloadTS ts);

/** Add an item to the traffic selector list. This will add a new
    entry to the end of the list.

    @param ts
    The traffic selector to be added.

    @param proto
    The desired protocol.

    @param start_address
    The start address of an address range.

    @param end_address
    The end address of an address range.

    @param start_port
    The start port of a port range.

    @param @end_port
    The end port of a port range.

   */
SshIkev2Error
ssh_ikev2_ts_item_add(SshIkev2PayloadTS ts,
                      SshInetIPProtocolID proto,
                      SshIpAddr start_address,
                      SshIpAddr end_address,
                      SshUInt16 start_port,
                      SshUInt16 end_port);

/** Remove an item from the traffic selector list. This can be used to
    narrow down the traffic selector.

    Note: This will renumber all the indices - meaning that after this
    operation the previous indices have changed.

    @param ts
    The traffic selector to be removed.

    */
SshIkev2Error
ssh_ikev2_ts_item_delete(SshIkev2PayloadTS ts,
                         int item_index_to_delete);

/** Takes a traffic selector and formats it as a string.

    @param str
    The allocated string is returned inside the 'str' argument.
    The 'str' needs to be freed after it is no longer needed.

    @param ts
    The traffic selector to be formatted as a string.

    @return
    Returns the number of characters written.

    */
int ssh_ikev2_ts_to_string(char **str, SshIkev2PayloadTS ts);

/** A function to convert the string back into a traffic selector.
    This function is given a traffic selector and items from the
    string are added to that traffic selector.

    @param str
    The string to be converted into a traffic selector.

    @param ts
    The traffic selector

    @return
    Returns the number of items added, or -1 if there was an error.

    */
int ssh_ikev2_string_to_ts(const char *str, SshIkev2PayloadTS ts);

/** Renderer function to render a traffic selector item for %@
    format string for ssh_e*printf. */
int ssh_ikev2_ts_render_item(unsigned char *buf, int buf_size,
                             int precision, void *datum);

/** Renderer function to render traffic selectors for %@
   format string for ssh_e*printf. */
int ssh_ikev2_ts_render(unsigned char *buf, int buf_size,
                        int precision, void *datum);

/** Test the validity of a subrange.

    @param ts
    traffic selector

    @param sub_ts
    The subrange to be tested.

    @return
    Return TRUE if the 'sub_ts' is valid subrange of 'ts'.

*/
Boolean ssh_ikev2_ts_match(SshIkev2PayloadTS ts,
                           SshIkev2PayloadTS sub_ts);


/** Test equality of traffic selectors.

    @param ts_1
    traffic selector

    @param ts_2
    traffic selector

    @return
    Return TRUE if the selectors are equal.

*/
Boolean ssh_ikev2_ts_equal(SshIkev2PayloadTS ts_1,
                           SshIkev2PayloadTS ts_2);


/** Remove duplicate items from the traffic selector ts.

    @return
    Returns FALSE on error, otherwise returns TRUE.
*/
Boolean ssh_ikev2_ts_remove_duplicate_items(SshSADHandle sad_handle,
                                            SshIkev2PayloadTS ts);

/** Allocate a new traffic selector, and calculate intersection
    of proposed_ts and policy_ts to it. This means that we first copy
    all items from proposed_ts to it, and then remove all items that
    are not in policy_ts, and narrow other subsets to be proper
    subsets of policy_ts. This can also split items in the new_ts if
    required to return maximal selectors.

    The first traffic selector item of the new_ts will always be
    the one that contains the first item from the proposed_ts,
    i.e. the information from the packet.

    If boolean require_match_to_first_ts is set policy_ts must match
    the first selector of the proposed_ts.

    Note: If the implementation only supports one traffic selector,
    then it can take the first item from the new_ts, and send
    SSH_IKEV2_NOTIFY_ADDITIONAL_TS_POSSIBLE. If new_ts is NULL, this
    will not allocate a new traffic selector, but just check if
    proposed_ts and policy_ts have a non-zero intersection.

    @return
    Returns FALSE if no intersection can be found (i.e.
    proposed_ts and policy_ts do not have any common elements),
    otherwise returns TRUE.

 */
Boolean ssh_ikev2_ts_narrow(SshSADHandle sad_handle,
                            Boolean require_match_to_first_ts,
                            SshIkev2PayloadTS *new_ts,
                            SshIkev2PayloadTS proposed_ts,
                            SshIkev2PayloadTS policy_ts);

/** Add a traffic selector to a union.

    Add a traffic selector `add_ts' to the `union_ts', i.e.
    calculate the union of `union_ts' and `add_ts' so that the
    `union_ts' is modified to include `add_ts'.

    The union is calculated so that it should have quite a small
    number of items, i.e. the new item is merged with some
    existing ones.

    Note: This does not try to merge other items inside the
    `union_ts' together, i.e. if there are item1 and item2 there
    and there is a hole between them, and add_ts fills that hole,
    then add_ts is added to the item1, but item2 is not merged to
    item1.

    @param sad_handle
    Security Association Database handle.

    @param union_ts
    The union where the traffic selector is to be added.

    @param add_ts
    The traffic selector to be added to the union.

    */

SshIkev2Error ssh_ikev2_ts_union(SshSADHandle sad_handle,
                                 SshIkev2PayloadTS union_ts,
                                 SshIkev2PayloadTS add_ts);

/** Create a hole to a traffic selector.

    Exclude `higher_ts' from the `lower_ts', i.e. make a hole of size
    of `higher_ts' to the `lower_ts'. After this call the
    intersection of `higher_ts' and `lower_ts' is empty. This will
    modify the `lower_ts'.

    @param sad_handle
    Security Association Database handle.

    @return
    This function will return SSH_IKEV2_ERROR_INVALID_ARGUMENT in
    case the the lower_ts has any IP protocol, and we try to
    remove a range from that which has a specific protocol.

    The resulting lower_ts is calculated as the higher_ts had any
    protocol.

    */

SshIkev2Error ssh_ikev2_ts_exclude(SshSADHandle sad_handle,
                                   SshIkev2PayloadTS lower_ts,
                                   SshIkev2PayloadTS higher_ts);


/** A default to allocate. */
#define SSH_IKEV2_TS_ITEMS_PREALLOC     4
/** A default to allocate. */
#define SSH_IKEV2_TS_ITEMS_ADD          2

/** Render function to render payload structure into a %@ format
    string for ssh_e*printf. */
int ssh_ikev2_payload_ts_render(unsigned char *buf, int buf_size,
                                int precision, void *datum);

/** Retrieve traffic selectors from 'ed'.

    On success this returns TRUE and sets 'ts_i_ret' and 'ts_r_ret' which the
    caller must free with ssh_ikev2_ts_free(). On error this returns FALSE and
    'ts_i_ret' and 'ts_r_ret' are left unset.

    If 'transport_mode_natt' is TRUE, then this will attempt to perform
    transport mode NAT-T traffic selector IP address substitution as specified
    in RFC5996, 2.23.1. This includes checking if either end is behind NAT and
    checking that each traffic selector specify a single IP address in each
    item. */
Boolean
ssh_ikev2_ipsec_get_ts(SshSADHandle sad_handle,
                       SshIkev2ExchangeData ed,
                       Boolean transport_mode_natt,
                       SshIkev2PayloadTS *ts_i_ret,
                       SshIkev2PayloadTS *ts_r_ret);

/* ********************************************************************/

/** Select/deselect transport mode traffic selectors to be used in this
    exchange. */
void
ssh_ikev2_ipsec_set_transport_mode_ts(SshIkev2ExchangeData ed,
                                      Boolean enable_transport_mode);

/** Fetch NAT-T original addresses for exchange. This sets or undefines
    'natt_oa_l' and 'natt_oa_r' depending on which IKE peer was behind NAT.
    If no NAT was detected between the peers, then this undefines both. */
void
ssh_ikev2_ipsec_get_natt_oa(SshIkev2ExchangeData ed,
                            SshIpAddr natt_oa_l,
                            SshIpAddr natt_oa_r);

/* ********************************************************************/

/** Calculate hash value of 'id'. This returns a hash value that can be
    used in hash table insertion and lookup. The returned hash cannot be
    used alone for comparing two SshIkev2PayloadID objects as this does
    not guarantee uniqueness of the hash value. */
SshUInt32
ssh_ikev2_payload_id_hash(SshIkev2PayloadID id);

/* *********************************************************************/

/** Allocate an SA payload. The initial SA payload is empty.
    This will take it from the SAD free list, or return NULL if no
    entries are available. This will automatically take one reference
    to the returned object. This function will be provided by the
    application (Policy Manager).

    @param sad_handle
    Security Association Database handle.

    @return
    Returns NULL if no entries are available.

   */
SshIkev2PayloadSA
ssh_ikev2_sa_allocate(SshSADHandle sad_handle);

/** Free an SA payload. This will return it back to the free
    list. This function will be provided by the application
    (Policy Manager).

    @param sad_handle
    Security Association Database handle.

    @param sa
    Security Association.

   */
void
ssh_ikev2_sa_free(SshSADHandle sad_handle, SshIkev2PayloadSA sa);

/** Duplicate SA payload. This will take a new entry from the
   free list and copy data from the current SA payload into
   it.

   @param sad_handle
   Security Association Database handle.

   @param sa
   Security Association.

   @return
   This will return NULL if no free SA payloads are available.

   */
SshIkev2PayloadSA
ssh_ikev2_sa_dup(SshSADHandle sad_handle,
                 SshIkev2PayloadSA sa);

/** Take extra reference to the SA payloads.

   @param sad_handle
   Security Association Database handle.

   @param sa
   Security Association.

*/
void
ssh_ikev2_sa_take_ref(SshSADHandle sad_handle,
                      SshIkev2PayloadSA sa);

/** Add a transform to the SA payload. This will add a new entry
    to the end of the list.

    Note: The proposal_index value there is not the same as
    sa->proposal_number but an index to the array in the SA payload,
    so it must start from 0, and it must increment by one.

    To get the actual proposal_number increment, add 1 to the
    proposal_index. Also all transforms associated with one proposal
    must be grouped together.

   */
SshIkev2Error
ssh_ikev2_sa_add(SshIkev2PayloadSA sa,
                 SshUInt8 proposal_index,
                 SshIkev2TransformType type,
                 SshIkev2TransformID id,
                 SshUInt32 transform_attribute);

/** Go through proposals in policy_sa starting from proposal number 1.
    For each policy_sa proposal go trough all input_sa proposals
    starting from proposal number 1 and compare transforms of the
    policy and input proposals.

    For each proposal comparison select a transform from input
    proposals for all transform types in the policy proposal. For each
    transform type the most preferred transform from the input
    proposal is chosen. The preference order is the order in which the
    transforms of the given type are listed in the policy proposal.

    @return

    Return TRUE if successful, and FALSE if no proposal can be
    returned. If FALSE is returned, the SshIkev2SaSelectionError
    return value 'failure_mask' provides more information on the exact
    error cause, this may be used for logging. */

typedef SshUInt32 SshIkev2SaSelectionError;
#define SSH_IKEV2_SA_SELECTION_ERROR_OK                 0x0000
#define SSH_IKEV2_SA_SELECTION_ERROR_ENCR_MISMATCH      0x0001
#define SSH_IKEV2_SA_SELECTION_ERROR_PRF_MISMATCH       0x0002
#define SSH_IKEV2_SA_SELECTION_ERROR_INTEG_MISMATCH     0x0004
#define SSH_IKEV2_SA_SELECTION_ERROR_D_H_MISMATCH       0x0008
#define SSH_IKEV2_SA_SELECTION_ERROR_ESN_MISMATCH       0x0010
#define SSH_IKEV2_SA_SELECTION_ERROR_ATTR_MISMATCH      0x0020
#define SSH_IKEV2_SA_SELECTION_ERROR_ESP_NULL_NULL      0x0040
#define SSH_IKEV2_SA_SELECTION_ERROR_UNKNOWN_TRANSFORM  0x0080

Boolean
ssh_ikev2_sa_select(SshIkev2PayloadSA input_sa,
                    SshIkev2PayloadSA policy_sa,
                    int *proposal_index,
                    SshIkev2PayloadTransform
                    selected_transforms[SSH_IKEV2_TRANSFORM_TYPE_MAX],
                    SshIkev2SaSelectionError *failure_mask);

/** Debug print SshIkev2PayloadSA in pretty manner, where each
    payload element has its own line. Use 'debug_level' to set
    the required debugging level, it is internally passed to the
    SSH_DEBUG(). Use 'topic' to give the context to the print, e.g.
    "Responder's tunnel IPSec SA payload is". Use 'line_header' to
    give short header for every line, e.g. "SA_RESPONDER_TUNNEL".

    Returns 0 when succesfull, 1 if input_sa is null.*/
int
ssh_ikev2_payload_sa_debug(int debug_level,
                           const char *topic,
                           const char *line_header,
                           SshIkev2PayloadSA input_sa);

/** Similar to ssh_ikev2_payload_sa_debug() but for SshIkev2PayloadConf.

    Returns 0 when succesful, 1 if input_conf is null, and 2 if internal
    buffer size is too small. */
int
ssh_ikev2_payload_conf_debug(int debug_level,
                        const char *topic,
                        const char *line_header,
                        SshIkev2PayloadConf input_conf);

/** Encode a Security Association. This function allocates memory and
    encodes the SshIkev2Sa 'sa' into it and returns a pointer to the
    allocated memory in 'buf_ret' and it's lenght in 'len_ret'.

    On success this returns SSH_IKEV2_ERROR_OK and the caller is responsible
    for freeing the returned memory. On error the return value indicates
    the reason and no memory is allocated. */
SshIkev2Error
ssh_ikev2_encode_sa(SshIkev2Sa sa, unsigned char **buf_ret, size_t *len_ret);


/** Decode a Security Association. This function decodes the encoded
    SshIkev2Sa given 'buf' that has 'len' bytes into user allocated
    SshIkev2Sa at 'sa'.

    The function expects that IKE SA has a valid SshIkev2Server
    assigned as its server field prior to this function is called. */
SshIkev2Error
ssh_ikev2_decode_sa(SshIkev2Sa sa, unsigned char *buf, size_t len);


/* *********************************************************************/

/** Allocate a configuration payload. The initial conf payload is
    empty. This will take it from the SAD free list, or return
    NULL if no entries are available. This will automatically take
    one reference to the returned object. The conf payload will
    have the type of conf_type.

    This function will be provided by the application (Policy
    Manager).

    @return
    Returns NULL if no entries are available. */
SshIkev2PayloadConf
ssh_ikev2_conf_allocate(SshSADHandle sad_handle,
                        SshIkev2ConfType conf_type);

/** Free a configuration payload. This will return it back to the free
    list. This function will be provided by the application
    (Policy Manager). */
void
ssh_ikev2_conf_free(SshSADHandle sad_handle, SshIkev2PayloadConf conf);

/** Duplicate a configuration payload. This will take a new entry from the
    free list and copy data from the current SA payload into
    it.

    @return
    This will return NULL if no free conf payloads are available.

    */
SshIkev2PayloadConf
ssh_ikev2_conf_dup(SshSADHandle sad_handle,
                   SshIkev2PayloadConf conf);

/** Take extra reference to the configuration payloads. */
void
ssh_ikev2_conf_take_ref(SshSADHandle sad_handle,
                        SshIkev2PayloadConf conf);

/** Add an attribute to the configuration payload. This will add a new
   entry to the end of the list.
*/
SshIkev2Error
ssh_ikev2_conf_add(SshIkev2PayloadConf conf,
                   SshIkev2ConfAttributeType attribute_type,
                   size_t length,
                   const unsigned char *value);

/**
   Free possibly dynamically allocated attributes from the
   configuration payload.
 */
void
ssh_ikev2_conf_free_attributes(SshIkev2PayloadConf conf);


/* *********************************************************************/

/** A default to allocate. */
#define SSH_IKEV2_CONF_ATTRIBUTES_PREALLOC      4
/** A default to allocate. */
#define SSH_IKEV2_CONF_ATTRIBUTES_ADD           2

/** A default to allocate. */
#define SSH_IKEV2_SA_TRANSFORMS_PREALLOC 10
/** A default to allocate. */
#define SSH_IKEV2_SA_TRANSFORMS_ADD      10

/* *********************************************************************/

/** Report an error detected locally by the application level. */
void
ssh_ikev2_debug_error_local(SshIkev2Sa ike_sa, const char *text);

/** Report an error detected by the remote end at application level. */
void
ssh_ikev2_debug_error_remote(SshIkev2Sa ike_sa, const char *text);

/* *********************************************************************/

/** Render functions. */

/** Render function to render IKE SPI and all different
    payload structures into a %@ format string for
    ssh_e*printf. */
int ssh_ikev2_ike_spi_render(unsigned char *buf, int buf_size,
                             int precision, void *datum);

/** Render function to render payload structure into a %@ format
    string for ssh_e*printf. */
int ssh_ikev2_payload_ke_render(unsigned char *buf, int buf_size,
                                int precision, void *datum);

/** Render function to render payload structure into a %@ format
    string for ssh_e*printf. */
int ssh_ikev2_payload_id_render(unsigned char *buf, int buf_size,
                                int precision, void *datum);

#ifdef SSHDIST_IKE_CERT_AUTH

/** Render function to render payload structure into a %@ format
    string for ssh_e*printf. */
int ssh_ikev2_payload_cert_render(unsigned char *buf, int buf_size,
                                  int precision, void *datum);

/** Render function to render payload structure into a %@ format
    string for ssh_e*printf. */
int ssh_ikev2_payload_certreq_render(unsigned char *buf, int buf_size,
                                     int precision, void *datum);

#endif /* SSHDIST_IKE_CERT_AUTH */


/** Render function to render payload structure into a %@ format
    string for ssh_e*printf. */
int ssh_ikev2_payload_auth_render(unsigned char *buf, int buf_size,
                                  int precision, void *datum);

/** Render function to render payload structure into a %@ format
    string for ssh_e*printf. */
int ssh_ikev2_payload_nonce_render(unsigned char *buf, int buf_size,
                                   int precision, void *datum);

/** Render function to render payload structure into a %@ format
    string for ssh_e*printf. */
int ssh_ikev2_payload_notify_render(unsigned char *buf, int buf_size,
                                    int precision, void *datum);

/** Render function to render payload structure into a %@ format
    string for ssh_e*printf. */
int ssh_ikev2_payload_delete_render(unsigned char *buf, int buf_size,
                                    int precision, void *datum);

/** Render function to render payload structure into a %@ format
    string for ssh_e*printf. */
int ssh_ikev2_payload_vid_render(unsigned char *buf, int buf_size,
                                 int precision, void *datum);


#ifdef SSHDIST_IKE_EAP_AUTH

/** Render function to render payload structure into a %@ format
    string for ssh_e*printf. */
int ssh_ikev2_payload_eap_render(unsigned char *buf, int buf_size,
                                 int precision, void *datum);

#endif /* SSHDIST_IKE_EAP_AUTH */

/** Render function to render payload structure into a %@ format
    string for ssh_e*printf. */
int ssh_ikev2_payload_conf_render(unsigned char *buf, int buf_size,
                                  int precision, void *datum);

/** Render function to render payload structure into a %@ format
    string for ssh_e*printf. */
int ssh_ikev2_payload_sa_render(unsigned char *buf, int buf_size,
                                int precision, void *datum);

/** Render function for transform attributes */
int ikev2_render_transform_attribute(unsigned char *buf, int buf_size,
                                     int precision, void *datum);

/** Function to return a string version of an enumerated type. */
const char *ssh_ikev2_auth_method_to_string(SshIkev2AuthMethod auth_method);


#ifdef SSHDIST_IKE_CERT_AUTH

/** Function to return a string version of an enumerated type. */
const char *ssh_ikev2_cert_encoding_to_string(SshIkev2CertEncoding cert_type);

#endif /* SSHDIST_IKE_CERT_AUTH */


/** Function to return a string version of an enumerated type. */
const char *ssh_ikev2_id_to_string(SshIkev2IDType id_type);

/** Function to return a string version of an enumerated type. */
const char *ssh_ikev2_notify_to_string(SshIkev2NotifyMessageType notify);

/** Function to return a string version of an enumerated type. */
const char *ssh_ikev2_error_to_string(SshIkev2Error notify);

/** Function to return a string version of an enumerated type. */
const char *ssh_ikev2_protocol_to_string(SshIkev2ProtocolIdentifiers protocol);

/** Function to return a string version of an enumerated type. */
const char *ssh_ikev2_attr_to_string(SshIkev2ConfAttributeType attr_type);

/** Function to return a string version of an enumerated type. */
const char *ssh_ikev2_transform_to_string(SshIkev2TransformType type,
                                          SshIkev2TransformID value);

/** Function to return a string version of an enumerated type. */
const char *ssh_ikev2_transform_type_to_string(SshIkev2TransformType type);

/** Function to return a string version of packet notify payload */
const char *
ssh_ikev2_notify_payload_to_string(SshIkev2NotifyMessageType type);

/** Function to return a string version of a packet payload */
const char *
ssh_ikev2_packet_payload_to_string(SshIkev2PayloadType type);


/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_attr_type_to_string_table[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_auth_method_to_string_table[];


#ifdef SSHDIST_IKE_CERT_AUTH

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_cert_encoding_to_string_table[];

#endif /* SSHDIST_IKE_CERT_AUTH */

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_id_to_string_table[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_notify_to_string_table[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_error_to_string_table[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_protocol_to_string_table[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_encr_to_string_table[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_prf_to_string_table[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_integ_to_string_table[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_dh_to_string_table[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_esn_to_string_table[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_encr_algorithms[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_prf_algorithms[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_mac_algorithms[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_mac_key_lengths[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_notify_payload_to_string_table[];

/** A keyword table used to perform a string conversion. */
extern const SshKeywordStruct ssh_ikev2_packets_payload_to_string_table[];

#endif /* SSH_IKEV2_UTIL_H */
