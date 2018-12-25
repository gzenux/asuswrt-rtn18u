/**
 * A client-side 802.1x implementation
 *
 * This code is released under both the GPL version 2 and BSD licenses.
 * Either license may be used.  The respective licenses are found below.
 *
 * Copyright (C) 2002 Bryan D. Payne & Nick L. Petroni Jr.
 * All Rights Reserved
 *
 * --- GPL Version 2 License ---
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA  02111-1307, USA.
 *
 * --- BSD License ---
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *  - Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *  - Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *  - All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *       This product includes software developed by the University of
 *       Maryland at College Park and its contributors.
 *  - Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

/*******************************************************************
 * The driver function for a Linux application layer EAPOL
 * implementation
 * File: cardif_linux.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: os_cardif.c,v 1.1.1.1 2007/08/06 10:04:42 root Exp $
 * $Date: 2007/08/06 10:04:42 $
 * $Log: os_cardif.c,v $
 * Revision 1.1.1.1  2007/08/06 10:04:42  root
 * Initial import source to CVS
 *
 * Revision 1.2  2005/02/01 03:33:26  jimmylin
 * Remove space before and after "->" for convenience of source trace
 *
 * Revision 1.1.1.1  2004/08/12 10:33:24  ysc
 *
 *
 * Revision 1.1  2004/07/24 00:52:57  kennylin
 *
 * Client mode TLS
 *
 * Revision 1.1  2004/07/24 00:40:55  kennylin
 *
 * Client mode TLS
 *
 * Revision 1.24  2004/04/18 03:28:26  chessing
 *
 * Fixed a little bit of verbage in cardif_linux.c that could be confusing.
 *
 * Revision 1.23  2004/04/01 06:12:55  npetroni
 * fixed off-by-one error
 *
 * Revision 1.22  2004/03/29 21:36:38  chessing
 *
 * Fixed a problem that would cause XSupplicant to segfault if there was no default network profile defined, an interface was down, and XSupplicant was terminated.  (All at the same time.)
 *
 * Revision 1.21  2004/03/27 01:40:45  chessing
 *
 * Lots of small updates to free memory that wasn't getting freed, add some additional debug output, and fix a couple of memory leaks.
 *
 * Revision 1.20  2004/03/26 21:34:52  chessing
 * Fixed problem with interface being down on startup causing xsupplicant to not read the proper configuration information when the interface is brought up.  Added/fixed code to rebuild userdata piece of structure when the essid changes.  Added code to avoid setting a key on an interface if the interface doesn't already have encryption enabled.  Added a little bit of debugging code to help find a solution to an IPC socket problem.
 *
 * Revision 1.19  2004/03/25 06:06:57  chessing
 *
 * Some debug code cleanups.  Fixed a bug with non-existant, or down interfaces defined in the allow_interfaces would loop forever.  Added calls to reset wireless keys to all 0s when we end up in disconnected, or held state.
 *
 * Revision 1.18  2004/03/24 18:35:47  chessing
 *
 * Added a modified version of a patch from David Relson to fix a problem with some of the debug info in config_grammer.y.  Added some additional checks to eapol_key_type1 that will keep us from segfaulting under some *REALLY* strange conditions.  Changed the set key code in cardif_linux to double check that we aren't a wireless interface before returning an error.  This resolved a problem when XSupplicant was started when an interface was done.  Upon bringing up the interface, XSupplicant would sometimes think it wasn't wireless, and not bother trying to set keys.
 *
 * Revision 1.17  2004/03/23 23:34:20  galimorerpg
 * Removed another un-needed Makefile and added the cardif_get_int patch from Pavel Roskin
 *
 * Revision 1.16  2004/03/22 00:41:00  chessing
 *
 * Added logfile option to the global config options in the config file.  The logfile is where output will go when we are running in daemon mode.  If no logfile is defined, output will go to the console that started xsupplicant.   Added forking to the code, so that when started, the process can daemonize, and run in the background.  If there is a desire to force running in the foreground (such as for debugging), the -f option was added.
 *
 * Revision 1.15  2004/03/06 03:53:54  chessing
 *
 * We now send logoffs when the process is terminated.  Added a new option to the config file "wireless_control" which will allow a user to disable non-EAPoL key changes.  Added an update to destination BSSID checking that will reset the wireless key to all 0s when the BSSID changes.  (This is what "wireless_control" disables when it is set to no.)  Roaming should now work, but because we are resetting keys to 128 bit, there may be issues with APs that use 64 bit keys.  I will test this weekend.
 *
 * Revision 1.14  2004/02/06 06:13:31  chessing
 *
 * Cleaned up some unneeded stuff in the configure.in file as per e-mail from Rakesh Patel.  Added all 12 patches from Jouni Malinen (Including wpa_supplicant patch, until we can add true wpa support in xsupplicant.)
 *
 * Revision 1.13  2004/01/20 03:44:32  chessing
 *
 * A couple of small updates.  TTLS now uses the correct phase 2 type as defined by the config file.  Setting dest_mac now works, and has the desired results.  One small fix to EAP-SIM.
 *
 * Revision 1.12  2004/01/17 21:16:15  chessing
 *
 * Various segfault fixes.  PEAP now works correctly again.  Some new error checking in the tls handlers.  Fixes for the way we determine if we have changed ESSIDs.  We now quit when we don't have a config, or when the config is bad. Added code to check and see if a frame is in the queue, and don't sleep if there is.  "Fixed" ID issue by inheriting the ID from the parent where needed.  However, assigning an ID inside of a handler will override the parent ID.  This could cause problems with some EAP types.  We should add a "username" field to PEAP to allow configuration of the inner EAP identity.
 *
 * Revision 1.11  2004/01/15 23:45:11  chessing
 *
 * Fixed a segfault when looking for wireless interfaces when all we had was a wired interface.  Fixed external command execution so that junk doesn't end up in the processed string anymore.  Changed the state machine to call txRspAuth even if there isn't a frame to process.  This will enable EAP methods to request information from a GUI interface (such as passwords, or supply challenge information that might be needed to generate passwords).  EAP methods now must decide what to do when they are handed NULL for the pointer to the in frame.  If they don't need any more data, they should quietly exit.
 *
 * Revision 1.10  2004/01/15 01:12:45  chessing
 *
 * Fixed a keying problem (keying material wasn't being generated correctly).  Added support for global counter variables from the config file. (Such as auth_period)  Added support for executing command defined in the config file based on different events.  (Things such as what to do on reauth.)  Added the ability to roam to a different SSID.  We now check to make sure our BSSID hasn't changed, and we follow it, if it has.  Fixed a sefault when the program was terminated in certain states.  Added attempt at better garbage collection on program termination. Various small code cleanups.
 *
 * Revision 1.9  2004/01/14 22:07:25  chessing
 *
 * Fixes that were needed in order to allow us to authenticate correctly.  We should now be able to authenticate using only information provided by the config file!
 *
 * Revision 1.8  2004/01/06 23:35:07  chessing
 *
 * Fixed a couple known bugs in SIM.  Config file support should now be in place!!! But, because of the changes, PEAP is probably broken.  We will need to reconsider how the phase 2 piece of PEAP works.
 *
 * Revision 1.7  2003/12/28 07:13:21  chessing
 *
 * Fixed a problem where we would segfault on an EAP type we didn't understand.  Added EAP-OTP.  EAP-OTP has been tested using the opie package, and Radiator 3.8.  EAP-OTP currently prompts for a passphrase, which it shouldn't do, so it should be considered *VERY* much in test mode until we finish the GUI.
 *
 * Revision 1.6  2003/12/19 06:29:57  chessing
 *
 * New code to determine if an interface is wireless or not.  Lots of IPC updates.
 *
 * Revision 1.5  2003/12/04 04:36:25  chessing
 *
 * Added support for multiple interfaces (-D now works), also added DEBUG_EXCESSIVE to help clean up some of the debug output (-d 6).
 *
 * Revision 1.4  2003/11/29 03:50:03  chessing
 *
 * Added NAK code, EAP Type checking, split out daemon config from user config, added Display of EAP-Notification text, revamped phase 2 selection method for TTLS.
 *
 * Revision 1.3  2003/11/24 04:56:04  chessing
 *
 * EAP-SIM draft 11 now works.  Statemachine updated to work based on the up/down state of an interface, rather than just assuming it is up.
 *
 * Revision 1.2  2003/11/24 02:14:08  chessing
 *
 * Added EAP-SIM (draft 11 still needs work), various small changes to eap calls, new hex dump code including ASCII dump (used mostly for dumping frames)
 *
 * Revision 1.1.1.1  2003/11/19 04:13:28  chessing
 * New source tree
 *
 *
 *
 *******************************************************************/

#include <sys/types.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <linux/wireless.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <net/if_arp.h>

#include "cardif/cardif.h"
#include "config.h"
#include "profile.h"
#include "xsup_debug.h"
#include "xsup_err.h"

#ifndef ETH_P_EAPOL
#define ETH_P_EAPOL 0x888e
#endif

#if defined(RTL_WPA_CLIENT)
extern struct interface_data *int_list;
#endif

/***********************************************
 *
 * Do whatever is needed to get the interface in to a state that we can send
 * and recieve frames on the network.  Any information that we need to later
 * use should be stored in the interface_data structure.
 *
 ***********************************************/
int cardif_init(struct interface_data *thisint)
{
  struct ifreq ifr;
  int sockopts, sockerr, retval;
  //  char newdest[6];

  debug_printf(DEBUG_INT, "Initializing socket for interface %s..\n",
	       thisint->intName);

  // Establish a socket handle.
  thisint->sockInt = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_EAPOL));
  if (thisint->sockInt < 0)
    {
      debug_printf(DEBUG_NORMAL,
		   "Couldn't initialize raw socket for interface %s!\n",
		   thisint->intName);
      return XENOSOCK;
    }

  // Tell the ifreq struct which interface we want to use.
  strncpy((char *)&ifr.ifr_name, thisint->intName, sizeof(ifr.ifr_name));

  retval = ioctl(thisint->sockInt, SIOCGIFINDEX, &ifr);
  if (retval < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error getting interface index value for interface %s\n",
		   thisint->intName);
      return XESOCKOP;
    }

  // Build our link layer socket struct, so we can bind it to a specific
  // interface.
  thisint->sll.sll_family = PF_PACKET;
  thisint->sll.sll_ifindex = ifr.ifr_ifindex;
  thisint->sll.sll_protocol = htons(ETH_P_EAPOL);

#ifndef RTL_WPA_CLIENT
  // Bind to the interface.
  retval = bind(thisint->sockInt, (const struct sockaddr *)&thisint->sll,
		sizeof(struct sockaddr_ll));
  if (retval < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error binding raw socket to interface %s!\n",
		   thisint->intName);
      return XESOCKOP;
    }
#endif /* RTL_WPA_CLIENT */

  // Get our MAC address.  (Needed for sending frames out correctly.)
  retval = ioctl(thisint->sockInt, SIOCGIFHWADDR, &ifr);
  if (retval < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error getting hardware (MAC) address for interface %s!\n",
		   thisint->intName);
      return XENOTINT;
    }

  // Store a copy of our source MAC for later use.
  memcpy((char *)&thisint->source_mac[0], (char *)&ifr.ifr_hwaddr.sa_data[0], 6);

  // Set our socket to non-blocking.
  sockopts = fcntl(thisint->sockInt, F_GETFL, 0);
  if (sockopts < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error getting socket options for interface %s!\n",
		   thisint->intName);
      return XENOTINT;
    }

  sockerr = fcntl(thisint->sockInt, F_SETFL, sockopts | O_NONBLOCK);
  if (sockerr < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error setting socket options for interface %s!\n",
		   thisint->intName);
      return XENOTINT;
    }



  return XENONE;
}

#if defined(RTL_WPA_CLIENT)
static int update_hwaddr(struct interface_data *thisint)
{
  struct ifreq ifr;
  int sockopts, sockerr, retval;

  //Check and update dest mac for wlan client roaming
  if(memcmp(thisint->dest_mac,RTLClient.global->supp_pae->auth_addr,ETHER_ADDRLEN))
  {
  	debug_printf(DEBUG_EVERYTHING, "%s(%d): wlan client roaming, update dest wlan mac here.\n",__FUNCTION__,__LINE__);
	memcpy(thisint->dest_mac,RTLClient.global->supp_pae->auth_addr,ETHER_ADDRLEN);
  }

  //Check source mac whether need to update especially for wlan mac clone enabled
  debug_printf(DEBUG_EVERYTHING, "%s(%d): thisint->sockInt(%d),thisint->intName(%s)\n",__FUNCTION__,__LINE__,thisint->sockInt,thisint->intName);//Added for test
  if (thisint->sockInt < 0)
    {
      debug_printf(DEBUG_NORMAL,
		   "No raw socket for interface %s!\n",
		   thisint->intName);
      return XENOSOCK;
    }

  // Tell the ifreq struct which interface we want to use.
  strncpy((char *)&ifr.ifr_name, thisint->intName, sizeof(ifr.ifr_name));

  // Get our MAC address.  (Needed for sending frames out correctly.)
  retval = ioctl(thisint->sockInt, SIOCGIFHWADDR, &ifr);
  if (retval < 0)
    {
      debug_printf(DEBUG_NORMAL, "Error getting hardware (MAC) address for interface %s!\n",
		   thisint->intName);
      return XENOTINT;
    }

  if(memcmp((char *)&thisint->source_mac[0], (char *)&ifr.ifr_hwaddr.sa_data[0], 6) == 0)
  {
  	debug_printf(DEBUG_EVERYTHING, "%s(%d): needn't update source_mac\n",__FUNCTION__,__LINE__);//Added for test
  	return XNONEWWLANMAC;
  }
  else
  {
	  // update our source MAC for later use.
	  memcpy((char *)&thisint->source_mac[0], (char *)&ifr.ifr_hwaddr.sa_data[0], 6);
	  debug_printf(DEBUG_NORMAL, "%s(%d): source_mac[%02x:%02x:%02x:%02x:%02x:%02x]\n",__FUNCTION__,__LINE__,
	  	thisint->source_mac[0],thisint->source_mac[1],thisint->source_mac[2],thisint->source_mac[3],thisint->source_mac[4],thisint->source_mac[5]);
  }

  return XENONE;
}
#endif


/**************************************************************
 *
 * Check if encryption is available.  If it is, we will return
 * TRUE, if it isn't, we will return FALSE.  On error, we return
 * -1.
 *
 **************************************************************/
int cardif_enc_enabled(struct interface_data *thisint)
{
  int rc = 0;
  int skfd;
  struct iwreq wrq;

  bzero((struct iwreq *)&wrq, sizeof(struct iwreq));

  skfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (skfd < 0)
    return -1;

  strncpy(wrq.ifr_name, thisint->intName, IFNAMSIZ);

  if ((rc = ioctl(skfd, SIOCGIWENCODE, &wrq)) < 0)
    {
      // We got an error while trying to get encryption information
      // from the card.
      rc = -1;
    } else {

      // We got some data, so see if we have encryption or not.
      if ((wrq.u.data.flags & IW_ENCODE_DISABLED) == IW_ENCODE_DISABLED)
	{
	  // Encryption is disabled.
	  rc = FALSE;
	} else {
	  // Encryption is enabled.
	  rc = TRUE;
	}
    }

  close(skfd);
  return rc;
}

/**************************************************************
 *
 * If we have detected, or forced this interface to reset keys, then
 * we need to reset them.  Otherwise, we will just ignore the fact that
 * we changed APs, and return.
 *
 **************************************************************/
void cardif_reset_keys(struct interface_data *thisint)
{
  char zerokey[13];
  char keylen = 13;

  if (thisint->userdata == NULL)
    {
      debug_printf(DEBUG_INT, "Userdata is NULL!\n");
      return;
    }

  if (thisint->userdata->wireless_ctrl == CTL_NO)
    {
      debug_printf(DEBUG_INT, "Config file has instructed us not to reset the key!  Roaming may not work!!!\n");
      return;
    }

  if (cardif_enc_enabled(thisint) != TRUE)
    {
      debug_printf(DEBUG_INT, "Encryption appears to be disabled.  We will not reset keys on interface %s!\n", thisint->intName);
      return;
    }

  bzero(&zerokey, 13);

  // We set the key index to 0x80, to force key 0 to be set to all 0s,
  // and to have key 0 be set as the default transmit key.
  set_wireless_key(thisint, (char *)&zerokey, keylen, 0x80);
}

/**************************************************************
 *
 * If we determine that this interface is a wireless interface, then
 * we should call this, to have the destination address changed to the
 * AP that we are talking to.  Otherwise, we will always send frames to
 * the multicast address, instead of the AP.  (And, most APs won't answer
 * to the multicast address.)
 *
 **************************************************************/
int cardif_check_dest(struct interface_data *thisint)
{
  char newdest[6], *newssid;
  char baddest[6];
  int changed = FALSE;

  bzero((char *)&newdest, 6);

  // If we are on wireless, figure out the target MAC address.
  if ((thisint->isWireless == TRUE) &&
      (GetBSSID(thisint, (char *)&newdest) == XENONE))
    {
      if (memcmp(thisint->dest_mac, newdest, 6) != 0)
	{
	  debug_printf(DEBUG_INT, "The card reported that the destination MAC address is now ");
	  debug_hex_printf(DEBUG_INT, (char *)&newdest, 6);

	  memcpy((char *)&thisint->dest_mac[0], (char *)&newdest, 6);

	  changed = TRUE;

	  // Since we changed destination addresses, we need to see if
	  // we should reset keys.
	  cardif_reset_keys(thisint);
	}

      memset((char *)&baddest, 0x00, 6);
      if (memcmp(thisint->dest_mac, baddest, 6) == 0)
	{
	  debug_printf(DEBUG_INT, "We don't appear to be associated!  Resetting keys!\n");
	  cardif_reset_keys(thisint);
	}

      memset((char *)&baddest, 0x44, 6);
      if (memcmp(thisint->dest_mac, baddest, 6) == 0)
	{
	  debug_printf(DEBUG_INT, "All 4s for dest mac! Resetting keys!\n");
	  cardif_reset_keys(thisint);
	}

      memset((char *)&baddest, 0xff, 6);
      if (memcmp(thisint->dest_mac, baddest, 6) == 0)
	{
	  debug_printf(DEBUG_INT, "All Fs for dest mac!  Resetting keys!\n");
	  cardif_reset_keys(thisint);
	}

      // If we were able to get a BSSID, we should also try to get an SSID.
      newssid = malloc(100);
      if (newssid == NULL)
	{
	  debug_printf(DEBUG_NORMAL, "Couldn't malloc newssid in cardif_linux.\n");
	  return XEMALLOC;
	}

      bzero(newssid, 100);
      GetSSID(thisint, newssid);
      if ((thisint->cur_essid == NULL) ||
	  (strncmp(newssid, thisint->cur_essid, 100) != 0))
	{
	  if (thisint->cur_essid != NULL) free(thisint->cur_essid);
	  thisint->cur_essid = newssid;
	  debug_printf(DEBUG_INT, "Working with ESSID : %s\n",
		       thisint->cur_essid);
	} else {
	  if (newssid != NULL)
	    {
	      free(newssid);
	      newssid = NULL;
	    }
	}
    } else {
      //      debug_printf(DEBUG_INT, "Interface doesn't appear to be a wireless interface!\n");
    }

  return changed;
}

/******************************************
 *
 * Clean up anything that was created during the initialization and operation
 * of the interface.  This will be called before the program terminates.
 *
 ******************************************/
int cardif_deinit(struct interface_data *thisint)
{
  debug_printf(DEBUG_EVERYTHING, "Cleaning up interface %s...\n",thisint->intName);
  close(thisint->sockInt);
  return XENONE;
}

/******************************************
 *
 * Set a wireless key.  Also, based on the index, we may change the transmit
 * key.
 *
 ******************************************/
int set_wireless_key(struct interface_data *thisint, u_char *key, int keylen,
		     int index)
{
  int rc = 0;
#ifndef RTL_WPA_CLIENT
  int skfd;
  struct iwreq wrq;

  if (thisint->isWireless == FALSE)
    {
      if ((cardif_int_is_wireless(thisint->intName) != TRUE) ||
	  (thisint->userdata->type == WIRED) ||
	  (thisint->userdata->wireless_ctrl == CTL_NO))
	{
	  debug_printf(DEBUG_NORMAL, "Interface isn't wireless, but an attempt to set a key was made!\n");
	  return XENOWIRELESS;
	} else {
	  thisint->isWireless = TRUE;
	}
    }

  skfd = socket(AF_INET, SOCK_DGRAM, 0);
  if (skfd < 0)
    return -1;

  strncpy(wrq.ifr_name, thisint->intName, IFNAMSIZ);

  wrq.u.data.flags = ((index & 0x7f) + 1) & IW_ENCODE_INDEX;
  wrq.u.data.flags |= IW_ENCODE_OPEN;

  wrq.u.data.length = keylen;
  wrq.u.data.pointer = (caddr_t)key;

  if ((rc = ioctl(skfd, SIOCSIWENCODE, &wrq)) < 0)
    {
      debug_printf(DEBUG_NORMAL, "Failed to set WEP key [%d], error %d : %s\n",
		   (index & 0x7f) + 1, errno, strerror(errno));

      rc = XENOKEYSUPPORT;
    } else {
      debug_printf(DEBUG_INT, "Successfully set WEP key [%d]\n",
		   (index & 0x7f)+1);

      if (index & 0x80)
	{
	  // This is a unicast key, use it for transmissions.
	  strncpy(wrq.ifr_name, thisint->intName, IFNAMSIZ);

	  wrq.u.data.flags = ((index & 0x7f) + 1) & IW_ENCODE_INDEX;
	  wrq.u.data.flags |= IW_ENCODE_OPEN;

	  wrq.u.data.length = 0;
	  wrq.u.data.pointer = (caddr_t)NULL;

	  if (ioctl(skfd, SIOCSIWENCODE, &wrq) < 0)
	    {
	      debug_printf(DEBUG_NORMAL, "Failed to set the WEP transmit key ID [%d]\n", (index & 0x7f)+1);
	      rc = XENOKEYSUPPORT;
	    } else {
	      debug_printf(DEBUG_INT, "Successfully set the WEP transmit key [%d]\n", (index & 0x7f)+1);
	    }
	}
    }

  close(skfd);
#endif
  return rc;
}

/******************************************
 *
 * Ask the wireless card for the ESSID that we are currently connected to.  If
 * this is not a wireless card, or the information is not available, we should
 * return an error.
 *
 ******************************************/
int GetSSID(struct interface_data *thisint, char *ssid_name)
{
#ifndef RTL_WPA_CLIENT
  struct iwreq iwr;

  if (thisint->isWireless == FALSE)
    {
      // We want to verify that the interface is in fact, not wireless, and
      // not that we are in a situation where the interface has just been
      // down.
      if (thisint->wasDown == FALSE)
	{
	  return XENOWIRELESS;
	}
    }

  // If we get here, and isWireless == FALSE, then we need to double
  // check that our interface is really not wireless.
  if (thisint->isWireless == FALSE)
    {
      thisint->isWireless = cardif_int_is_wireless(thisint->intName);
      if (thisint->isWireless == FALSE)
	{
	  thisint->wasDown = FALSE;
	}
    }

  // Specify the interface name we are asking about.
  strncpy(iwr.ifr_name, thisint->intName, sizeof(iwr.ifr_name));

  iwr.u.essid.pointer = (caddr_t) ssid_name;
  iwr.u.essid.length = 100;
  iwr.u.essid.flags = 0;

  if (ioctl(thisint->sockInt, SIOCGIWESSID, &iwr) < 0) return XENOWIRELESS;

#else
  memcpy(ssid_name, RTLClient.auth->RSNVariable.ssid, strlen(RTLClient.auth->RSNVariable.ssid));
  debug_printf(DEBUG_EVERYTHING, "[1] GetSSID = %s\n", ssid_name);
#endif

  thisint->wasDown = FALSE;

  return XENONE;
}

/******************************************
 *
 * Check the SSID against what we currently have, and determine if we need
 * to reset our configuration.
 *
 ******************************************/
int cardif_check_ssid(struct interface_data *thisint)
{
  char new_essid[100];

  bzero((char *)&new_essid, 100);

  if (GetSSID(thisint, (char *)&new_essid) != XENONE)
    {
      // This interface probably isn't wireless!

      // On the off chance that it is, we will trash the essid we have
      // listed as the current one, so that if we suddenly do get an
      // essid, we will load the proper config.
      if (thisint->cur_essid != NULL)
	{
	  free(thisint->cur_essid);
	  thisint->cur_essid = NULL;
	}

      return XENONE;
    }

  if (thisint->cur_essid != NULL)
    {
      if (strcmp(thisint->cur_essid, (char *)&new_essid) != 0)
	{
	  // We have changed essids.
	  debug_printf(DEBUG_INT, "ESSID Changed to : %s\n", (char *)&new_essid);

	  // Kill off the essid we currently have.
	  free(thisint->cur_essid);
	  thisint->cur_essid = (char *)malloc(strlen(new_essid)+1);
	  if (thisint->cur_essid == NULL) return XEMALLOC;

	  strncpy(thisint->cur_essid, new_essid, strlen(new_essid));

	  // Since we changed essids, we no longer have completed a
	  // "first auth"
	  thisint->firstauth = FALSE;

	  return XNEWESSID;
	}
    }
  return XENONE;
}

/******************************************
 *
 * Get the Broadcast SSID (MAC address) of the Access Point we are connected
 * to.  If this is not a wireless card, or the information is not available,
 * we should return an error.
 *
 ******************************************/
int GetBSSID(struct interface_data *thisint, char *bssid_dest)
{
#ifdef RTL_WPA_CLIENT
  memcpy(bssid_dest, RTLClient.global->supp_pae->auth_addr, 6);
  debug_printf(DEBUG_EVERYTHING, "[1] GetBSSID = %02X:%02X:%02X:%02X:%02X:%02X\n",
  			(unsigned char)bssid_dest[0],
  			(unsigned char)bssid_dest[1],
  			(unsigned char)bssid_dest[2],
  			(unsigned char)bssid_dest[3],
  			(unsigned char)bssid_dest[4],
  			(unsigned char)bssid_dest[5]);
#else
  struct iwreq iwr;

  // Specify the interface name we are asking about.
  strncpy(iwr.ifr_name, thisint->intName, sizeof(iwr.ifr_name));

  if (ioctl(thisint->sockInt, SIOCGIWAP, &iwr) < 0) return XENOWIRELESS;

  memcpy(bssid_dest, iwr.u.ap_addr.sa_data, 6);
#endif /* RTL_WPA_CLIENT */
  return XENONE;
}

/******************************************
 *
 * Set the flag in the state machine that indicates if this interface is up
 * or down.  If there isn't an interface, we should return an error.
 *
 ******************************************/
int get_if_state(struct interface_data *thisint)
{
  int retVal;
  struct ifreq ifr;

  strncpy(ifr.ifr_name, thisint->intName, sizeof(ifr.ifr_name));
  retVal = ioctl(thisint->sockInt, SIOCGIFFLAGS, &ifr);
  if (retVal < 0)
    {
      debug_printf(DEBUG_NORMAL, "Interface %s not found!\n", thisint->intName);
      return FALSE;
    }

  if ((ifr.ifr_flags & IFF_UP) == IFF_UP)
    {
      return TRUE;
    } else {
      thisint->wasDown = TRUE;
      return FALSE;
    }
  return XENONE;
}

/******************************************
 *
 * Send a frame out of the network card interface.  If there isn't an
 * interface, we should return an error.  We should return a different error
 * if we have a problem sending the frame.
 *
 ******************************************/
int sendframe(struct interface_data *thisint, char *sendframe, int sendsize)
{
  char nomac[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
  int retval;
#ifdef RTL_ETH_CLIENT
 	unsigned char dot1x_group_mac[6] = {0x01,0x80,0xC2,0x00,0x00,0x03};
#endif
  debug_printf(DEBUG_STATE, "%s:\n", __FUNCTION__);

  if (thisint == NULL) return XEMALLOC;

  if (sendframe == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Cannot send NULL frame!\n");
      return XENOFRAMES;
    }

#if defined(RTL_WPA_CLIENT)
  //Specially added for wlan client mode mac clone.
  if(update_hwaddr(thisint)==XENONE)
  {
  	//Update wlan mac address already
  	debug_printf(DEBUG_EVERYTHING, "%s(%d): To reinit state machine!\n",__FUNCTION__,__LINE__);//Added for test
  	eapol_cleanup(int_list);
	eapol_init(int_list);
	lib1x_reset_supp(RTLClient.global);
	return XEWRONGWLANMAC;
  }
#endif

  // The frame we are handed in shouldn't have a src/dest, so put it in.
#ifdef RTL_ETH_CLIENT
 	if(RTLClient.auth->currentRole == role_eth){
		memcpy(&sendframe[0], dot1x_group_mac, 6); 
 	}
	else
#endif
  memcpy(&sendframe[0], &thisint->dest_mac[0], 6);  
  memcpy(&sendframe[6], &thisint->source_mac[0], 6);
  debug_printf(DEBUG_EVERYTHING, "%s(%d): [%02x:%02x:%02x:%02x:%02x:%02x] ==> [%02x:%02x:%02x:%02x:%02x:%02x]\n",__FUNCTION__,__LINE__,
  	(unsigned char)sendframe[6],(unsigned char)sendframe[7],(unsigned char)sendframe[8],(unsigned char)sendframe[9],(unsigned char)sendframe[10],(unsigned char)sendframe[11],
  	(unsigned char)sendframe[0],(unsigned char)sendframe[1],(unsigned char)sendframe[2],(unsigned char)sendframe[3],(unsigned char)sendframe[4],(unsigned char)sendframe[5]);


  if (thisint->userdata != NULL)
    {
      if (memcmp(nomac, (char *)&thisint->userdata->dest_mac[0], 6) != 0)
	{
	  debug_printf(DEBUG_INT, "Static MAC address defined!  Using it!\n");
	  memcpy(&sendframe[0], &thisint->userdata->dest_mac[0], 6);
	}
    }

  debug_printf(DEBUG_EVERYTHING, "Frame to be sent : \n");
  //debug_hex_dump(DEBUG_EVERYTHING, sendframe, sendsize);

  retval = sendto(thisint->sockInt, sendframe, sendsize, 0,
		  (struct sockaddr *)&thisint->sll, sizeof(thisint->sll));
  if (retval <= 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't send frame! (%s)\n", strerror(errno));
    }

  return retval;
}

/******************************************
 *
 * Get a frame from the network.  Since we are in promisc. mode, we will get
 * frames that aren't intended for us.  So, check the frame, determine if it
 * is something we care about, and act accordingly.
 *
 ******************************************/
int getframe(struct interface_data *thisint, char *resultframe, int *resultsize)
{
  int newsize=0;
  char dot1x_default_dest[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x03};

  errno = 0;
  *resultsize = 1550;

  newsize = recvfrom(thisint->sockInt, resultframe, *resultsize, 0, 0, 0);
  if (newsize <= 0)
    {
      debug_printf(DEBUG_EXCESSIVE, "Couldn't get frame.  (Maybe there weren't any!)\n");
      switch (errno)
	{
	case EBADF:
	  debug_printf(DEBUG_EXCESSIVE, "Invalid descriptor!\n");
	  break;
	case ECONNREFUSED:
	  debug_printf(DEBUG_EXCESSIVE, "Connection refused!\n");
	  break;
	case ENOTCONN:
	  debug_printf(DEBUG_EXCESSIVE, "Not connected!\n");
	  break;
	case ENOTSOCK:
	  debug_printf(DEBUG_EXCESSIVE, "Not a socket!\n");
	  break;
	case EAGAIN:
	  debug_printf(DEBUG_EXCESSIVE, "Socket would block!\n");
	  break;
	case EINTR:
	  debug_printf(DEBUG_EXCESSIVE, "Recieve Interrupted!\n");
	  break;
	case EFAULT:
	  debug_printf(DEBUG_EXCESSIVE, "Invalid recieve buffer!\n");
	  break;
	case EINVAL:
	  debug_printf(DEBUG_EXCESSIVE, "Invalid argument!\n");
	  break;
	case ENOMEM:
	  debug_printf(DEBUG_EXCESSIVE, "Couldn't allocate memory!\n");
	  break;
	default:
	  debug_printf(DEBUG_EVERYTHING, "Unknown error (%d)\n",newsize);
	  break;
	}
      return XENOFRAMES;
    } else {
      debug_printf(DEBUG_EVERYTHING, "Got Frame : \n");
      debug_hex_dump(DEBUG_EVERYTHING, resultframe, newsize);
    }

  // Make sure that the frame we got is for us..
  if ((memcmp(&thisint->source_mac[0], &resultframe[0], 6) == 0) ||
      ((memcmp(&resultframe[0], &dot1x_default_dest[0], 6) == 0) &&
       (memcmp(&resultframe[6], &thisint->source_mac[0], 6) != 0)))
    {
        debug_printf(DEBUG_NORMAL, "%s(%d): source_mac[%02x:%02x:%02x:%02x:%02x:%02x]\n",__FUNCTION__,__LINE__,
  	thisint->source_mac[0],thisint->source_mac[1],thisint->source_mac[2],thisint->source_mac[3],thisint->source_mac[4],thisint->source_mac[5]);

      *resultsize = newsize;
      return newsize;
    }

  // Otherwise it isn't for us.
  debug_printf(DEBUG_INT, "Got a frame, not for us.\n");
  return XENOFRAMES;
}

/******************************************
 *
 * Return true if there is a frame in the queue to be processed.
 *
 ******************************************/
int frameavail(struct interface_data *thisint)
{
  int newsize=0;
  char resultframe[1520];

  newsize = recvfrom(thisint->sockInt, &resultframe, 1520, MSG_PEEK, 0, 0);
  if (newsize > 0) return TRUE;

  return FALSE;
}

/******************************************
 *
 * Validate an interface, based on if it has a MAC address.
 *
 ******************************************/
int cardif_validate(char *interface)
{
  int sd, res;
  struct ifreq ifr;

  strncpy(ifr.ifr_name, interface, sizeof(interface)+1);

  sd = socket(PF_PACKET, SOCK_RAW, 0);
  if (sd < 0)
    return FALSE;
  res = ioctl(sd, SIOCGIFHWADDR, &ifr);
  close(sd);
  if (res < 0)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't get information for interface %s!\n",interface);
    } else {
      switch (ifr.ifr_hwaddr.sa_family)
	{
	case ARPHRD_ETHER:
	case ARPHRD_IEEE80211:
	  return TRUE;
	}
    }
  return FALSE;
}

/******************************************
 *
 * Get the name of an interface, based on an index value.
 *
 ******************************************/
#define PROC_DEV_FILE  "/proc/net/dev"

int cardif_get_int(int index, char *retInterface)
{
  FILE *fp;
  int hits;
  char line[1000], *lineptr;

  hits = 0;

  fp = fopen(PROC_DEV_FILE, "r");
  if (fp == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't access /proc/net/dev!\n");
      exit(250);
    }

  bzero(line, 1000);

  while ((hits <= index) && (fgets(line, 999, fp) != NULL))
    {
      lineptr = strchr(line, ':');

      if (lineptr == NULL) continue;

      *lineptr = '\0';
      lineptr = &line[0];

      while (*lineptr == ' ') lineptr++;  // Strip out blanks.

      strcpy(retInterface, lineptr);
      hits++;
    }

  if (hits <= index)
    {
      debug_printf(DEBUG_INT, "No more interfaces to look at!\n");
      return XNOMOREINTS;
    }

  debug_printf(DEBUG_INT, "Found interface : %s\n",retInterface);

  fclose(fp);

  return XENONE;   // No errors.
}


/*******************************************************
 *
 * Check to see if an interface is wireless.  On linux, we look in
 * /proc/net/wireless to see if the interface is registered with the
 * wireless extensions.
 *
 *******************************************************/
#define PROC_WIRELESS_FILE  "/proc/net/wireless"

int cardif_int_is_wireless(char *interface)
{
  FILE *fp;
  char line[1000], *lineptr=NULL;
  int done;

#ifdef RTL_WPA_CLIENT
  return TRUE;
#endif

  done = FALSE;

  fp = fopen(PROC_WIRELESS_FILE, "r");
  if (fp == NULL)
    {
      debug_printf(DEBUG_NORMAL, "Couldn't access /proc/net/wireless!  (You probably don't have wireless extensions enabled!)\n");
      return -1;
    }

  bzero(line, 1000);

  while ((!done) && (fgets(line, 999, fp) != NULL))
    {
      lineptr = strchr(line, ':');

      if (lineptr != NULL)
	{

	  *lineptr = '\0';
	  lineptr = &line[0];

	  while (*lineptr == ' ') lineptr++;  // Strip out blanks.
	  if (lineptr != NULL)
	    {
	      if (strcmp(lineptr, interface) == 0) done=TRUE;
	    }
	}
    }
  fclose(fp);

  if ((lineptr != NULL) && (strcmp(lineptr, interface) == 0))
    {
      debug_printf(DEBUG_INT, "Interface %s is wireless!\n",interface);
      return TRUE;
    } else {
      debug_printf(DEBUG_INT, "Interface %s is NOT wireless!\n",interface);
      return FALSE;
    }
  return XENONE;   // No errors.
}





