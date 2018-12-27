/**
   @copyright
   Copyright (c) 2002 - 2015, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header for Policy Manager utility functions.
*/

#ifndef UTIL_INTERNAL_H
#define UTIL_INTERNAL_H

#include "sshincludes.h"

/* ************************* Types and definitions ***************************/

/** Magic values used in debug builds to check that the context
   structures are of correct type. */
#define SSH_PM_MAGIC_PM 0xfee1706d

/** Macros to check validity of context structures. */
#define SSH_PM_ASSERT_PM(pm) SSH_ASSERT((pm) && (pm)->magic == SSH_PM_MAGIC_PM)

/** The length of the MD5 digest in bytes. */
#define SSH_PM_MD5_DIGEST_LEN 16

#define SSH_XXX_NOT_IMPLEMENTED_YET(what)       \
SSH_DEBUG(SSH_D_ERROR, ("*** %s NOT IMPLEMENTED YET ***", (what)))

#define SSH_XXX_NOT_IMPLEMENTED_YET_FATAL(what) \
ssh_fatal("*** %s:%d: %s NOT IMPLEMENTED YET ***",  __FILE__, __LINE__, (what))

/** Predicate to check whether the character `ch' is a hexadecimal
   character. */
#define SSH_PM_IS_HEX(ch)               \
(('0' <= (ch) && (ch) <= '9')           \
 || ('a' <= (ch) && (ch) <= 'f')        \
 || ('A' <= (ch) && (ch) <= 'F'))

/** Convert hexadecimal digit `ch' to its integer value. */
#define SSH_PM_HEX_TO_INT(ch)   \
('0' <= (ch) && (ch) <= '9'     \
 ? (ch) - '0'                   \
 : ('a' <= (ch) && (ch) <= 'f'  \
    ? (ch) - 'a' + 10           \
    : (ch) - 'A' + 10))

/** Check whether the character `ch' is a blank character: that is a space
    or a tab). */
#define SSH_PM_IS_BLANK(ch) \
((' ' == (ch)) || ('\t' == (ch)))


/* *********************** Interface information  **************************/

/** Lookup the interface 'ifname' from the policy manager 'pm'.

    @param pm
    The Policy Manager.

    @param ifname
    The interface to be looked up.

    @param ifnum_return
    If the argument 'ifnum_return' has a non-null value, the
    interface's number is returned in it.

    @return
    The function returns SshInterceptorInterface describing the
    interface, or NULL if the interface 'ifname' is unknown.

    */
SshInterceptorInterface *ssh_pm_find_interface(SshPm pm, const char *ifname,
                                               SshUInt32 *ifnum_return);


/** Lookup the interface by the interface number 'ifnum'.

    @param pm
    Policy Manager.

    @param ifnum
    Interface number.

    @return
    The function returns SshInterceptorInterface describing the
    interface, or NULL if the interface 'ifnum' is unknown.

    */
SshInterceptorInterface *ssh_pm_find_interface_by_ifnum(SshPm pm,
                                                        SshUInt32 ifnum);


/** Lookup the VRI name from interface.

    @param routing_instance_id
    VRI ID.

    @param context
    Policy Manager

    @return
    The function returns routing instance name corresponding to the id,
    or NULL if the id is unknown.

    */
const char *
ssh_pm_find_interface_vri_name(int routing_instance_id, void * context);

/** Lookup the VRI id from interface.

    @param routing_instance_name
    VRI name.

    @param context
    Policy Manager

    @return
    The function returns routing instance id corresponding to the name,
    or -1 if the id is unknown.

    */
int
ssh_pm_find_interface_vri_id(const char * routing_instance_name,
                             void * context);

/** Lookup the VRI id from interface.

    @param ifnum
    The interface number.

    @param context
    Policy Manager

    @return
    The function returns routing instance id corresponding to the interface,
    or -1 if the id is unknown.

    */
int
ssh_pm_find_interface_vri_id_by_ifnum(SshUInt32 ifnum, void * context);

/** Lookup the first interface with the IP address 'addr' from the
    Policy Manager 'pm'.

    @param pm
    Policy Manager.

    @param addr
    IP address of the searched for interface.

    @param routing_instance_id
    Routing instance ID of the seached interface.

    @param ifnum_return
    If the argument 'ifnum_return' has a non-null value, the
    interface's number is returned in it.

    @return
    The function returns SshInterceptorInterface describing the
    interface, or NULL if the IP address 'addr' is unknown.

    */
SshInterceptorInterface *
ssh_pm_find_interface_by_address(SshPm pm,
                                 SshIpAddr addr,
                                 int routing_instance_id,
                                 SshUInt32 *ifnum_return);

/** Lookup the interface which either has IP address 'addr' or
    an address prefix of an interface matches the prefix of
    'addr'.

    If an exact match based on IP is found, it is always returned,
    otherwise the interface with the longest matching prefix is
    returned.

    @param pm
    Policy Manager.

    @param addr
    The IP address of the searched for interface.

    @param ifnum_return
    If the argument 'ifnum_return' has a non-null value, the
    interface's number is returned in it.

    @return
    The function returns SshInterceptorInterface describing the
    interface, or NULL if the IP address 'addr' is unknown.

    */
SshInterceptorInterface *
ssh_pm_find_interface_by_address_prefix(SshPm pm,
                                        SshIpAddr addr,
                                        SshVriId routing_instance_id,
                                        SshUInt32 *ifnum_return);

/** Look up a usable IP address for the interface 'ifnum'.

    @param pm
    Policy Manager.

    @param ifnum
    The interface for which the IP address is searched for.

    @param ipv6
    Specifies whether an IPv6 or an IPv4 address is required.

    @param dst
    Specifies the destination address to contact with the returned
    address.  If the argument 'dst' has the value NULL, the
    interface's first address of the given IP version will be
    returned.

    @return
    The function returns the address, or NULL if no address of
    specified type was found from the interface 'ifnum'.

    */
SshIpAddr ssh_pm_find_interface_address(SshPm pm, SshUInt32 ifnum,
                                        Boolean ipv6, const SshIpAddr dst);

/** Log the interface information. This may be called after an
    interface change event. */
void ssh_pm_log_interceptor_interface(SshInterceptorInterface *ifp);


/** A callback function for ssh_register_timeout() that continues the
    thread that registered the timeout. The next state must have been
    set by the caller.

    @param context
    The context for the timeout, must be the FSM thread.

    */
void ssh_pm_timeout_cb(void *context);

/** Fetches the payload of an IPv6 packet 'packet'.
    The function skips all extension headers and returns the IP
    protocol ID of the payload in 'ipprotop'.

    @param packet
    The packet whose payload is to be fetched.

    @param packet_len
    The length of the packet, expressed in bytes.

    @param offsetp
    The offset of the payload is returned in 'offsetp'.

    @param ipprotop
    The function returns the IP protocol ID of the payload in
    'ipprotop'.

    @param prev_nh_ofs_return
    If this argument is not NULL, the variable pointed by it it is
    set to the offset of the 'Next Header' field of the preceeding
    header (extension or the IPv6 header).

    @param final_dst_return
    If this argument is not NULL and the packet contains an IPv6
    routing header, the final destination is returned in the
    'final_dst_return'.  If the packet does not have an IPv6 routing
    header, or if the final destination is already at the IP header,
    the value pointed by 'final_dst_return' is not modified.

    @return
    The function returns TRUE if the payload could be fetched.
    Otherwise it returns FALSE (the packet is somehow malformed).

    */
Boolean ssh_pm_fetch_ip6_payload(const unsigned char *packet,
                                 size_t packet_len, size_t *offsetp,
                                 SshInetIPProtocolID *ipprotop,
                                 size_t *prev_nh_ofs_return,
                                 SshIpAddr final_dst_return);

/** Convert binary data 'data', 'datalen' into a hexadecimal armored
    C-string to the buffer 'buf' having 'buflen' bytes of space.
    The binary string is truncated to the 'buflen' bytes.

    @param buf
    Buffer for storing the converted data.

    @param buflen
    Length of 'buf', expressed in bytes.

    @param data
    Binary data to be converted.

    @param datalen
    Length of 'data'.

    @return
    The function returns `buf'.

    */
char *ssh_pm_util_data_to_hex(char *buf, size_t buflen,
                              const unsigned char *data, size_t datalen);

#endif /* not UTIL_INTERNAL_H */
