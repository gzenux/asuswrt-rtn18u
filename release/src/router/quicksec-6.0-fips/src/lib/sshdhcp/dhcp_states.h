/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   dhcp_states.h
*/

#ifndef DHCP_STATES_H
#define DHCP_STATES_H

#include "sshudp.h"
#include "dhcp_packet.h"

/* DHCP States for DHCP Client. */

/* UDP Listener callback. Called when packet is received from the UDP
   connection. This always calls dhcp-receive state to parse the incoming
   packet. */
void ssh_dhcp_udp_callback(SshUdpListener listener, void *context);

/* UDP Listener callback when DHCPv6 is in use. Called when packet is
   received from the UDP connection. This always calls dhcpv6_receive state
   to parse the incoming packet. */
void ssh_dhcpv6_udp_callback(SshUdpListener listener, void *context);

/* DHCP States */

/* Client to Server: request IP address from server. This is the first
   state (if previous DHCP configuration does not exist) and will be
   broadcasted to the network to receive offers from server(s). */
SSH_FSM_STEP(ssh_dhcp_st_discover);

/* Server to Client: Server offered IP address to client. Note that there
   can be several DHCP offers from several DHCP servers. This code takes
   the first offer without considering other offers at all. All other offers
   from this point on will be ignored by default. */
SSH_FSM_STEP(ssh_dhcp_st_offer);

/* Client to Server: Client verifies/requests IP address. Sends request
   to the server. This can be first state as well if the information is
   already provided by application. On the other hand, this is called also
   when we've received offer from server. In this case, this is used to
   tell the server that we've accepted the offer. */
SSH_FSM_STEP(ssh_dhcp_st_request);

/* Server to Client: The IP address has been commited. This will again
   run through all the settings server sent, just in case, and will save
   them. This also registers the re-new and re-bind timeouts. */
SSH_FSM_STEP(ssh_dhcp_st_ack);

/* Server to Client: The client won't get the IP address. For some reason
   server did not like our request and refuses to give us the IP. In this
   case we will trigger retransmission and try again. If we fail all over
   again and will reach the maximum retransmission limit we'll stop the
   DHCP session for good. */
SSH_FSM_STEP(ssh_dhcp_st_nak);

/* Client to Server: The IP address is in use already. This is also sent
   if we fail in DHCPACK packet parsing. We'll refuse to use that IP and
   restart DHCP from the begin. */
SSH_FSM_STEP(ssh_dhcp_st_decline);

/* Client to Server: Client don't need the IP anymore. We are doing a
   graceful ending of the DHCP session and will notify the server that we
   won't need the IP anymore. */
SSH_FSM_STEP(ssh_dhcp_st_release);

/* Received an packet from network. Parse it and call correct state. */
SSH_FSM_STEP(ssh_dhcp_st_receive);


/* DHCPv6 specific states */
/* Client to Server: request IP address from server. This is the first
   state for DHCPv6 */
SSH_FSM_STEP(ssh_dhcpv6_st_solicit);

/* Received an packet from network. Parse it and call correct state. */
SSH_FSM_STEP(ssh_dhcpv6_st_receive);

/* Server to Client: Server replied to the message sent by client.
   If the server offered IP address to client it should be noted that there
   can be several DHCP offers from several DHCP servers. This code takes
   the first offer without considering other offers at all. All other offers
   from this point on will be ignored by default. */
SSH_FSM_STEP(ssh_dhcpv6_st_reply);

/* Client to Server: Client requests renewal of IP address. Sends request
   to the server. This is the first state in renewal operation as the
   information is already provided by application. */
SSH_FSM_STEP(ssh_dhcpv6_st_renew);

/* Client to Server: Client don't need the IP anymore. We are doing a
   graceful ending of the DHCP session and will notify the server that we
   won't need the IP anymore. */
SSH_FSM_STEP(ssh_dhcpv6_st_release);

/* Client to Server: The IP address is in use already. This is also sent
   if we fail in REPLY packet parsing. We'll refuse to use that IP and
   restart DHCP from the begin. */
SSH_FSM_STEP(ssh_dhcpv6_st_decline);


/* Common states for the library */
/* After ack the DHCP client, or the relay agent has a responsibility to check
   that the received address is not already in use, calling the user
   callback to enable checking. */
SSH_FSM_STEP(ssh_dhcp_st_finish_pending);

/* The final state that is always called when ending DHCP session. This is
   called regardless was the session successfully completed. This will also
   call the user callback. */
SSH_FSM_STEP(ssh_dhcp_st_finish);

/* Cancels all timeouts. */
void ssh_dhcp_cancel_timeouts(SshDHCP dhcp);

#endif
