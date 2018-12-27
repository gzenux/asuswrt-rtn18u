/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Management utils for the IP interface table.
*/

#ifndef SSH_IP_INTERFACES_H

#define SSH_IP_INTERFACES_H 1

/* The SshIpInterfaces structure is used to encapsulate the main
   interface table manipulation. All modifications to the table
   should go through the API defined in this file, to keep any
   encapsulated data structures used to speed up lookups consistent.

   If any of the mutator functions return failure, it is because
   they were unable to allocate memory for updating any lookup
   data structures. */

typedef struct SshIpInterfacesRec
{
  /* Number of interfaces */
  SshUInt32 nifs;
  /* Number of allocated entries in 'ifs' */
  SshUInt32 ifs_size;
  /* Table of interface entries */
  SshInterceptorInterface *ifs;

#ifndef SSH_IPSEC_SMALL
  /* Map from ifnum to interface */
  SshInterceptorInterface **map_from_ifnum;

  /* Map from IP address to interface */
  struct SshInterfaceAddressRec **map_from_ip;

  /* Map from broadcast address to interface */
  struct SshInterfaceAddressRec **map_from_broadcast;
#endif /* SSH_IPSEC_SMALL */
} *SshIpInterfaces, SshIpInterfacesStruct;


/*********************** Interface Table Initialization *********************/

/* There are two alternative ways for interface table initialization:

   1. The hard way:
      ssh_ip_init_interfaces(interfaces);
      for (i = 0; i < nifs; i++)
        ssh_ip_init_interfaces_add(interface, &ifs[i]);
      ssh_ip_init_interfaces_done(interface);

      It is safe to call ssh_ip_uninit_interfaces() in any error case.

   2. The easy way:
      ssh_ip_init_interfaces_from_table(interfaces, ifs, nifs);

      If this call fails, then the interface table is left in an
      uninitialized state.
*/

/* The ssh_ip_init_interfaces() function initializes an uninitialized
   SshIpInterfaces structure. It returns FALSE if it fails. If it fails
   it is still safe to call ssh_ip_uninit_interfaces() for 'interfaces'. */
Boolean
ssh_ip_init_interfaces(SshIpInterfaces interfaces);

/* The ssh_ip_init_interfaces_add() function adds an interface to the
   interface list. This function is used for performing a batch of
   interface additions to the interface table. The caller must call
   ssh_ip_init_interfaces_done() to finalize the job before any lookup
   functions are called for the interface table. This returns FALSE if
   it fails. */
Boolean
ssh_ip_init_interfaces_add(SshIpInterfaces interfaces,
                           const SshInterceptorInterface *iface);

/* The ssh_ip_init_interfaces_done() function finalizes interface table
   initialization. It returns FALSE if it fails and in this case the
   caller must call ssh_ip_uninit_interfaces(). */
Boolean
ssh_ip_init_interfaces_done(SshIpInterfaces interfaces);

/* ssh_ip_uninit_interfaces() frees the resources allocated
   for 'interfaces' in a previous initialization. */
void
ssh_ip_uninit_interfaces(SshIpInterfaces interfaces);

/* The ssh_ip_init_interfaces_from_table() initializes an uninitialized
   SshIpInterfaces structure, adds the 'nifs' interfaces in the array
   'table' and finalizes interface table initialization. On error it
   uninitializes the interface table and returns FALSE. This conviniency
   function can be used as a substitution for the above functions. */
Boolean
ssh_ip_init_interfaces_from_table(SshIpInterfaces interfaces,
                                  SshInterceptorInterface *table,
                                  SshUInt32 nifs);


/*************** Adding Interfaces and Addresses to Interface Table *********/

/* ssh_ip_add_interface() adds an interface to the table
   'interfaces'. It returns FALSE if it fails. If it fails,
   the table is still in a consistent state, but without
   'iface' added to it. */
SshInterceptorInterface *
ssh_ip_add_interface(SshIpInterfaces interfaces,
                     const SshInterceptorInterface *iface);

/* ssh_ip_add_interface_address() adds address 'address' to the table
   'iface'. It returns FALSE if it fails. If it fails, the table is
   left in an consistent state. */
Boolean
ssh_ip_add_interface_address(SshIpInterfaces interfaces,
                             SshInterceptorInterface *iface,
                             const SshInterfaceAddress address);

/** Compare the interface information in 'ifp1' and 'ifp2'. Returns TRUE
    if the interfaces are equivalent and FALSE otherwise. */
Boolean ssh_ip_interface_compare(SshInterceptorInterface *ifp1,
                                 SshInterceptorInterface *ifp2);


/*********************** Interface Table Lookup *****************************/

/* ssh_ip_get_interface_by_subnet() returns an interface which
   has a subnet which contains the address 'ip'. It returns NULL
   if no such interface exists. */
SshInterceptorInterface *
ssh_ip_get_interface_by_subnet(SshIpInterfaces interfaces,
                               const SshIpAddr ip,
                               SshVriId routing_instance_id);

/* ssh_ip_get_interface_by_broadcast() returns an interface which
   has a broadcast address of 'ip'. It returns NULL if no such
   interface exists. */
SshInterceptorInterface *
ssh_ip_get_interface_by_broadcast(SshIpInterfaces interfaces,
                                  const SshIpAddr ip,
                                  SshVriId routing_instance_id);

/* ssh_ip_get_interface_by_ifnum() returns the interface which
   has interface number 'ifnum'. It returns NULL if no such interface
   exists. */
SshInterceptorInterface *
ssh_ip_get_interface_by_ifnum(SshIpInterfaces interfaces, SshUInt32 ifnum);

/* ssh_ip_get_interface_flags_by_ifnum() returns the interface flags which
   has interface number 'ifnum'. It returns 0 if no such interface
   exists or if the flags really are 0. */
SshUInt32
ssh_ip_get_interface_flags_by_ifnum(SshIpInterfaces interfaces,
                                    SshUInt32 ifnum);

/* ssh_ip_get_interface_by_ip() returns an interface which has
   IP address 'ip'. */
SshInterceptorInterface *
ssh_ip_get_interface_by_ip(SshIpInterfaces interfaces, const SshIpAddr ip,
                           int routing_instance_id);

/* ssh_ip_enumerate_start returns the interface number of the first
   interface, or SSH_INVALID_INDEX if no such interface exists. */
SshUInt32
ssh_ip_enumerate_start(SshIpInterfaces interfaces);

/* ssh_ip_enumerate_next returns the interface number of the interface
   that follows the interface identified by number 'ifnum', or
   SSH_INVALID_IFNUM if no such interface exists. */
SshUInt32
ssh_ip_enumerate_next(SshIpInterfaces interfaces, SshUInt32 ifnum);

const char *
ssh_ip_get_interface_vri_name(SshIpInterfaces interfaces,
                              int routing_instance_id);

int
ssh_ip_get_interface_vri_id(SshIpInterfaces interfaces,
                            const char *routing_instance_name);

#endif /* SSH_IP_INTERFACES_H */
