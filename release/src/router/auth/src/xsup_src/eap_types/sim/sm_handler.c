/**
 * A client-side 802.1x implementation supporting EAP/SIM
 *
 * This code is released under both the GPL version 2 and BSD licenses.
 * Either license may be used.  The respective licenses are found below.
 *
 * Copyright (C) 2003 Chris Hessing
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
* EAPOL Function implementations for supplicant
 * 
 * File: sm_handler.c
 *
 * Authors: Chris.Hessing@utah.edu
 *
 * $Id: sm_handler.c,v 1.1.1.1 2007/08/06 10:04:43 root Exp $
 * $Date: 2007/08/06 10:04:43 $
 * $Log: sm_handler.c,v $
 * Revision 1.1.1.1  2007/08/06 10:04:43  root
 * Initial import source to CVS
 *
 * Revision 1.1.1.1  2004/08/12 10:33:31  ysc
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
 * Revision 1.8  2004/05/23 03:48:01  chessing
 *
 * Small fix to EAP-SIM code to make it work correctly.
 *
 * Revision 1.7  2004/04/13 22:13:30  chessing
 *
 * Additional error checking in all eap methods.
 *
 * Revision 1.6  2004/02/07 07:19:37  chessing
 *
 * Fixed EAP-SIM so that it works with FreeRADIUS correctly.  Fixed a bunch of memory leaks in the EAP-SIM, and related code.
 *
 * Revision 1.5  2004/01/20 00:07:07  chessing
 *
 * EAP-SIM fixes.
 *
 * Revision 1.4  2004/01/13 01:55:56  chessing
 *
 * Major changes to EAP related code.  We no longer pass in an interface_data struct to EAP handlers.  Instead, we hand in a generic_eap_data struct which containsnon-interface specific information.  This will allow EAP types to be reused as phase 2 type easier.  However, this new code may create issues with EAP types that make use of the identity in the eap type.  Somehow, the identity value needs to propigate down to the EAP method.  It currently does not.  This should be any easy fix, but more testing will be needed.
 *
 * Revision 1.3  2003/12/14 06:11:03  chessing
 *
 * Fixed some stuff with SIM in relation to the new config structures.  Cleaned out CR/LF from LEAP source files.  Added user certificate support to TTLS and PEAP. Some additions to the IPC code. (Not tested yet.)
 *
 * Revision 1.2  2003/11/29 04:46:02  chessing
 *
 * EAP-SIM changes : EAP-SIM will now try to use the IMSI as the username, when the preferred EAP type is SIM, and the username value is NULL.  Also, if simautogen is TRUE, then we will also build and attach a realm as specified in the RFC.
 *
 * Revision 1.1  2003/11/24 02:14:08  chessing
 *
 * Added EAP-SIM (draft 11 still needs work), various small changes to eap calls, new hex dump code including ASCII dump (used mostly for dumping frames)
 *
 *
 *******************************************************************/

/*******************************************************************
 *
 * The development of the EAP/SIM support was funded by Internet
 * Foundation Austria (http://www.nic.at/ipa)
 *
 *******************************************************************/


/* Interface to Smart Cards using PCSC with 802.1x.  */


/* Taken from code by Michael Haberler    mah@eunet.at */
/* which was based on work by marek@bmlv.gv.at */

#ifdef EAP_SIM_ENABLE

#include <stdio.h>
#include <winscard.h>
#include <ctype.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

#include "../mschapv2/mschapv2.h"  // Needed for ctonibble function.
#include "profile.h"
#include "config.h"
#include "eap.h"
#include "xsup_debug.h"
#include "xsup_err.h"
#include "sm_handler.h"

int need_init = 1;   // By default, we need an init to start with.

#ifndef SCDEBUG
#define SCDEBUG  1
#endif

#define MAXBUFF  (512)

#define SELECT_MF       "A0A40000023F00"
#define SELECT_DF_GSM   "A0A40000027F20"
#define SELECT_EF_IMSI  "A0A40000026F07"
#define RUN_GSM         "A088000010"
#define GET_IMSI        "A0B0000009"

char *o_readername;
SCARDCONTEXT g_sc_context;
SCARDHANDLE g_card_hdl = 0;
SCARD_IO_REQUEST scir;

unsigned long o_stdprotocol;
DWORD readerstrlen;

int debug;


void print_sc_error(long err)
{
  switch (err)
    {
    case SCARD_S_SUCCESS:
      printf("Successful card call!\n");
      break;
    case SCARD_E_CANCELLED:
      printf("Error : Card Request Cancelled!\n");
      break;
    case SCARD_E_CANT_DISPOSE:
      printf("Error : Can't dispose (!?)\n");
      break;
    case SCARD_E_INSUFFICIENT_BUFFER:
      printf("Error : Insufficient Buffer\n");
      break;
    case SCARD_E_INVALID_ATR:
      printf("Error : Invalid ATR\n");
      break;
    case SCARD_E_INVALID_HANDLE:
      printf("Error : Invalid handle\n");
      break;
    case SCARD_E_INVALID_PARAMETER:
      printf("Error : Invalid parameter\n");
      break;
    case SCARD_E_INVALID_TARGET:
      printf("Error : Invalid target\n");
      break;
    case SCARD_E_INVALID_VALUE:
      printf("Error : Invalid Value\n");
      break;
    case SCARD_E_NO_MEMORY:
      printf("Error : No memory\n");
      break;
    case SCARD_F_COMM_ERROR:
      printf("Error : Communication error \n");
      break;
    case SCARD_F_INTERNAL_ERROR:
      printf("Error : Internal error\n");
      break;
    case SCARD_F_WAITED_TOO_LONG:
      printf("Error : Waited too long\n");
      break;
    case SCARD_E_UNKNOWN_READER:
      printf("Error : Unknown reader\n");
      break;
    case SCARD_E_TIMEOUT:
      printf("Error : Timeout\n");
      break;
    case SCARD_E_SHARING_VIOLATION:
      printf("Error : Sharing Violation\n");
      break;
    case SCARD_E_NO_SMARTCARD:
      printf("Error : No smartcard!\n");
      break;
    case SCARD_E_UNKNOWN_CARD:
      printf("Error : Unknown card!\n");
      break;
    case SCARD_E_PROTO_MISMATCH:
      printf("Error : Protocol mismatch!\n");
      break;
    case SCARD_E_NOT_READY:
      printf("Error : Not ready!\n");
      break;
    case SCARD_E_SYSTEM_CANCELLED:
      printf("Error : System Cancelled\n");
      break;
    case SCARD_E_NOT_TRANSACTED:
      printf("Error : Not Transacted\n");
      break;
    case SCARD_E_READER_UNAVAILABLE:
      printf("Error : Reader unavailable\n");
      break;
    case SCARD_F_UNKNOWN_ERROR:
    default:
      printf("Unknown error!\n");
      break;
    }
}

void strtohex(char *instr, char *outstr, int *blen)
{
  int i;
  char val1,val2;

  if ((!instr) || (!outstr) || (!blen))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed to strtohex()!\n");
      return;
    }

  for (i=0;i<(strlen(instr)/2);i++)
    {
      val1=ctonibble(instr[i*2]);
      val2=ctonibble(instr[(i*2)+1]);
      outstr[i]=((val1<<4)+val2);
    }
  *blen = (strlen(instr)/2);
}

  

int card_io(char *cmd, LPBYTE outbuff, LPDWORD olen)
{
  static char g_getresponse[5]= {0xa0,0xc0,0x00,0x00 };
  int cmdlen, ret;
  char *bcmd;

  if (!cmd)
    {
      debug_printf(DEBUG_NORMAL, "Invalid command passed to card_io()!\n");
      return XESIMBADCMD;
    }

  cmdlen = strlen(cmd)/2;
  bcmd = (char *)malloc(cmdlen);  // Get a little more than we need.
  if (bcmd == NULL) return -1;

  strtohex(cmd, bcmd, &cmdlen);

  ret=SCardTransmit(g_card_hdl,
		    o_stdprotocol==SCARD_PROTOCOL_T1 ? 
		    SCARD_PCI_T1 : SCARD_PCI_T0,
		    bcmd, cmdlen, &scir,
		    (BYTE *) outbuff,olen);

  free(bcmd);
  bcmd = NULL;

  if (ret != 0)
    {
      print_sc_error(ret);
      return ret;
    }
  
  if (*olen==2) {
    switch ((unsigned char)outbuff[0]) {
    case 0x61:
    case 0x9f:
      if (outbuff[1]==0) 
        {
          break;
        }
      g_getresponse[4]=outbuff[1];

      *olen=MAXBUFF;
      ret=SCardTransmit(g_card_hdl,
			o_stdprotocol==SCARD_PROTOCOL_T1 ? SCARD_PCI_T1 : SCARD_PCI_T0,
			g_getresponse,sizeof(g_getresponse),&scir,
			(BYTE *)outbuff,olen);

  if (ret != 0)
    {
      print_sc_error(ret);
      return ret;
    }


    }
  }
  return 0;
}

unsigned char
hinibble(unsigned char c)
{
  unsigned char k;

  k = (c >> 4) & 0x0f;
  if (k == 0x0f)
    return 0;
  else
    return (k + '0');
}

unsigned char
lonibble(unsigned char c)
{
  unsigned char k;

  k = c & 0x0f;
  if (k == 0x0f)
    return 0;
  else
    return (k + '0');
}

int do_gsm(unsigned char *challenge, unsigned char *response, 
	   unsigned char *ckey)
{
  unsigned char buf[MAXBUFF], buff2[MAXBUFF], buff3[MAXBUFF];
  int i;
  DWORD len;

  if ((!challenge) || (!response) || (!ckey))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed to do_gsm()!\n");
      return XEMALLOC;
    }

  strcpy(buff2, RUN_GSM);
  bzero(&buff3, MAXBUFF);

  for (i = 0; i < 16; i++)
    {
      sprintf(buff3,"%02X",challenge[i]);
      strcat(buff2, buff3);
    }

  //  printf("(in do_gsm) Sending in : %s\n",buff2);
  len = MAXBUFF;
  card_io(buff2, buf, &len);

  /*printf("Response : ");
  
  for (i=0; i<4; i++)
    printf("%02X ",buf[i]);
  */
  memcpy(response, &buf[0], 4);
  /*
  printf("\nCipher Key : ");

  for (i=4; i<12; i++)
    printf("%02X ",buf[i]);
  */
  memcpy(ckey, &buf[4], 8);

  //  printf("\n");
  return 0;
}


int sc_need_init()
{
  return need_init;
}

int init_get_imsi(struct generic_eap_data *thisint, char *rimsi)
{
  LPSTR mszReaders;
  long ret;
  DWORD size, dwState, dwProtocol, dwAtrLen;
  DWORD len;
  unsigned char *buf; 
  unsigned char buff2[MAXBUFF], buff3[MAXBUFF];
  unsigned char imsi[20];
  int i;
  char *s, *dbuf, *pin;
  BYTE pbAtr[MAX_ATR_SIZE];
  struct config_eap_sim *mydata;

  if ((!thisint) || (!thisint->eap_conf_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid data passed to init_get_imsi()!\n");
      return XEMALLOC;
    }

  mydata = (struct config_eap_sim *)thisint->eap_conf_data;

  if (need_init == 0) return 0;

  buf = (unsigned char *)malloc(MAXBUFF);
  if (buf == NULL) return XEMALLOC;

  g_sc_context = 0;
  g_card_hdl = 0;
  o_stdprotocol = 0;

  pin = mydata->password;

  // First, get a context for us to work with the card.
  ret = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &g_sc_context);
  if (ret != SCARD_S_SUCCESS)
    {
      printf("Error!  Couldn't establish Smart Card Context!  (Is pcscd loaded?)\n");
      free(buf);
      buf = NULL;
      return -1;
    }

  // Find out the size of the buffer that we need in order to get our
  // reader information back.
  ret = SCardListReaders(g_sc_context, NULL, NULL, &readerstrlen);
  if (ret != SCARD_S_SUCCESS)
    {
      print_sc_error(ret);
      free(buf);
      buf = NULL;
      return -1;
    }

  o_readername = (char *)malloc(readerstrlen);
  if (o_readername == NULL)
    {
      printf("Couldn't allocate memory for reader info string!\n");
    }

  ret = SCardListReaders(g_sc_context, NULL, o_readername, &readerstrlen);
  if (ret != SCARD_S_SUCCESS)
    {
      printf("Couldn't list smart card readers!\n");
      print_sc_error(ret);
      free(buf);
      buf = NULL;
      return -1;
    }

  // We may have found more than one reader, but we are only going to use 
  // the first one we found.  This could be changed in the future if a
  // situation presents itself that needs more than one reader.  In that
  // case, the string that is returned contains the names of all of the readers
  // with the last name being terminated with a double NULL. \0\0.
  debug_printf(DEBUG_AUTHTYPES, "Found reader : %s\n",o_readername);

  while (1)
    {
      ret = SCardConnect(g_sc_context, o_readername,
			 SCARD_SHARE_SHARED,
			 SCARD_PROTOCOL_T0, 
			 &g_card_hdl, &o_stdprotocol);
      
      if (ret == SCARD_S_SUCCESS) break;

      if (ret == SCARD_E_NO_SMARTCARD)
	{
	  printf("Please insert a smart card!\n");
	  sleep(2);
	  continue;
	} else {
	  printf("An unchecked error happened!\n");
	  print_sc_error(ret);
	  break;
	}
    }

  dwState = 0;
  dwProtocol = 0;
  dwAtrLen = MAX_ATR_SIZE;
  size = 50;
  mszReaders= (LPSTR) malloc(size);
  bzero(mszReaders, 50);
  bzero(&pbAtr, MAX_ATR_SIZE);
  ret = SCardStatus(g_card_hdl, mszReaders, &size, &dwState, &dwProtocol, pbAtr, &dwAtrLen);
  if (ret != SCARD_S_SUCCESS)
    {
      print_sc_error(ret);
      free(mszReaders);
      free(buf);
      buf = NULL;
      exit(1);                /* Need to fix this! */
    }

  switch (dwState)
    {
    case SCARD_ABSENT:
      debug_printf(DEBUG_NORMAL, "There is no card in the reader.\n");
      break;
    case SCARD_PRESENT:
      debug_printf(DEBUG_NORMAL, "The card needs to be moved to a position that the reader can use!\n");
      break;
    case SCARD_SWALLOWED:
      debug_printf(DEBUG_NORMAL, "Card is ready, but not powered.\n");
      break;
    case SCARD_POWERED:
      debug_printf(DEBUG_NORMAL, "Card is powered, but we aren't sure of the mode of the card!\n");
      break;
    }

  /* select the Master File */                
  len=MAXBUFF;
  card_io(SELECT_MF, buf, &len);

  /* select DF_GSM */
  len=MAXBUFF;
  card_io(SELECT_DF_GSM, buf, &len); 

  if (!(buf[13] & 0x80))
    {
      if (pin == NULL) return -1;   /* We don't have a pin, but we need one. */

      strcpy(buff2, "A020000108");
      for (i = 0;i<strlen(pin); i++)
	{
	  sprintf(buff3, "%02X",pin[i]);
	  strcat(buff2, buff3);
	}
      for (i = strlen(pin); i < 8; i++)
	{
	  strcat(buff2, "FF");             /* Pad it to 8 bytes */
	}
      len=MAXBUFF;
      card_io(buff2, buf, &len);

      if (len == 2 && buf[0] == 0x98)
	{
	  if (buf[1] == 0x04)
	    {
	      printf("Incorrect PIN, at least one attempt left\n");
	      exit (1);               /* Need to fix this! */
	    }
	  else if (buf[1] == 0x40)
	    {
	      printf("Incorrect PIN, no attempts left\n");
	      exit (1);               /* Need to fix this! */
	    }
	}
    }
  len=MAXBUFF;
  dbuf = (char *)malloc(MAXBUFF);
  card_io(SELECT_EF_IMSI,dbuf,&len);

  len=MAXBUFF;
  bzero(dbuf,MAXBUFF);
  card_io(GET_IMSI,dbuf,&len);
  
  s = imsi;
  *s++ = hinibble(dbuf[1]);
  
  for (i = 2; i<9; i++)
    {
      *s++ = lonibble(dbuf[i]);
      *s++ = hinibble(dbuf[i]);
    }
  *s = '\0';

  if (rimsi != NULL)
    {
      memcpy(rimsi, imsi, 18);
    }
  
  free(buf);
  buf = NULL;
  free(dbuf);
  dbuf = NULL;

  free(mszReaders);
  mszReaders = NULL;

  return XENONE;
}

int eapsim_get_username(struct interface_data *thisint)
{
  char imsi[18];   // An IMSI should always be 18 digits.
  char realm[25];
  char *username;
  struct config_eap_sim *userdata;
  struct generic_eap_data mydata;

  if ((!thisint) || (!thisint->userdata) || (!thisint->userdata->methods) ||
      (!thisint->userdata->methods->method_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface structure passed to eapsim_get_username()!\n");
      return XEMALLOC;
    }

  userdata = (struct config_eap_sim *)thisint->userdata->methods->method_data;

  mydata.eap_conf_data = userdata;

  bzero(&imsi, 18);
  init_get_imsi(&mydata, (char *)&imsi);

  debug_printf(DEBUG_AUTHTYPES, "SIM IMSI : %s\n",imsi);

  if (thisint->userdata->identity != NULL)
    {
      free(thisint->userdata->identity);
    }

  thisint->userdata->identity = (char *)malloc(50);  // 50 should be plenty!
  if (thisint->userdata->identity == NULL) return XEMALLOC;

  username = thisint->userdata->identity;
  userdata->username = username;
  bzero(username, 50);

  username[0] = '1';  // An IMSI should always start with a 1.
  strncpy(&username[1], (char *)&imsi, 18);

  if (userdata->auto_realm == TRUE)
    {
      bzero(&realm, 25);
      sprintf((char *)&realm, "@mnc%c%c%c.mcc%c%c%c.owlan.org",
	      username[4], username[5], username[6], username[1], username[2],
	      username[3]);

      debug_printf(DEBUG_AUTHTYPES, "Realm Portion : %s\n",realm);
      strcat(username, realm);
    }

  // Close the smartcard, so that we know what state we are in.
  close_smartcard();

  debug_printf(DEBUG_AUTHTYPES, "Username is now : %s\n", username);

  return XENONE;
}

int init_smartcard(struct generic_eap_data *thisint)
{

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface structure passed to init_smartcard()!\n");
      return XEMALLOC;
    }

  init_get_imsi(thisint, NULL);

  return XENONE;
}


int close_smartcard()
{
  long ret;

  if (g_card_hdl) 
    {
      ret = SCardDisconnect(g_card_hdl, SCARD_UNPOWER_CARD);
      if (ret != SCARD_S_SUCCESS) 
	debug_printf(DEBUG_NORMAL, "Couldn't disconnect from Smart Card!\n");
      g_card_hdl = 0;
    }

  if (g_sc_context)
    {
      ret = SCardReleaseContext(g_sc_context);
      if (ret != SCARD_S_SUCCESS) 
	debug_printf(DEBUG_NORMAL, "Couldn't release smart card context!\n");
      g_sc_context = 0;
    }

  return XENONE;
}


#endif
