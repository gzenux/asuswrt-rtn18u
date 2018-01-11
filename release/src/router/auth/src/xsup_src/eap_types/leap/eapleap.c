/**
 * A client-side 802.1x implementation supporting EAP/LEAP
 *
 * This code is released under both the GPL version 2 and BSD licenses.
 * Either license may be used.  The respective licenses are found below.
 *
 * Copyright (C) 2003 Marios Karagiannopoulos
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

/*****************************************************************************
 * EAPOL Function implementations for supplicant
 *
 * File: eapleap.c
 *
 * Authors: Marios Karagiannopoulos (marios@master.math.upatras.gr)
 *
 ****************************************************************************/

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include "xsup_debug.h"
#include "xsup_err.h"
#include "frame_structs.h"

#include "config.h"
#include "profile.h"
#include "eap.h"
#include "eapleap.h"
#include "leapmd4.h"
#include "eap_types/mschapv2/mschapv2.h"
#include "interactive.h"

#define LEAP_LENGTH    0x08
struct leap_requests *leaprequest;
struct leap_responses *leapresponse;
struct leap_challenges *leapchallenges;

static void ntPwdHash(unsigned char *MD4Hash, char *password) {
    char unicodePass[513];
    char passLen;
    int i;

    if ((!MD4Hash) || (!password))
      {
	debug_printf(DEBUG_NORMAL, "Invalid data passed in to ntPwdHash!\n");
	return;
      }

    /* Microsoft passwords are unicode.  Convert plain text password
       to unicode by inserting a zero every other byte */
    passLen = strlen(password);
    for (i = 0; i < passLen; i++) {
        unicodePass[2 * i] = password[i];
        unicodePass[2 * i + 1] = 0;
    }
    /* Encrypt plain text password to a 16-byte MD4 hash */
    md4_calc(MD4Hash, unicodePass, passLen * 2);
}

void leap_mschap(char * password, char * response) {
    unsigned char MD4Hash[16], MD4HashHash[16];

    if ((!password) || (!response))
      {
	debug_printf(DEBUG_NORMAL, "Invalid data passed in to leap_mschap()!\n");
	return;
      }

    ntPwdHash(MD4Hash, password);
    md4_calc(MD4HashHash, MD4Hash, 16);
    ChallengeResponse(leapchallenges->apc, MD4HashHash, response);
}


/*****************************************************
 *
 * Setup to handle LEAP EAP requests
 *
 * This function is called each time we receive a packet of the EAP type LEAP.
 * At a minimum, it should check to make sure it's stub in the structure
 * exists, and if not, set up any variables it may need.  Since LEAP doesn't
 * have any state that needs to survive successive calls, we don't need to
 * do anything here.
 *
 *****************************************************/
int eapleap_setup(struct generic_eap_data *thisint)
{
  struct leap_data *mydata;

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface structure passed to eapleap_setup()!\n");
      return XEMALLOC;
    }

  mydata = (struct leap_data *)malloc(sizeof(struct leap_data));
  if (mydata == NULL) 
    {
      debug_printf(DEBUG_NORMAL, "Cannot allocate memory in eapleap_setup()!\n");
      return XEMALLOC;
    }

  mydata->keyingMaterial = NULL;
  mydata->eapsuccess = FALSE;

  thisint->eap_data = mydata;
 
  debug_printf(DEBUG_EVERYTHING, "Initalized EAP-LEAP!\n");

  return XENONE;
}

/*************************************************************
  leap_decode_packet - decode an LEAP challenge, and answer it

  	Cisco LEAP authenticates users to the wireless access point via a
password.  This password is authenticated against a back-end radius server
via a Challenge-Response protocol.  The protocol is such:
	1.) The Wireless client sends an authentication request;
	2.) The AP Acknowledges request with an 8 byte challenge;
	3.) The Wireless client computes the response by:
		a.) MD4 Hashing the password producing a 16 byte hash;
		b.) Padding the hash with 5 nulls producing 21 bytes;
		c.) Splitting the resulting 21 bytes into 7 byte chunks;
		d.) Iterating through the 7 byte chunks, des encrypting
			the challenge as plain-text with the 7-byte chunk
			as the key.
		e.) Concatenating the resulting cipher text producing 24
			bytes
	4.) The client then sends the resulting 24 bytes as the challenge
		response;
	5.) The back-end systems iterate through the same processes and
		check for a match; then
	6.) If the two match, authentication has been accomplished.

************************************************************/

int eapleap_process(struct generic_eap_data *thisint, u_char *dataoffs,
		   int insize, u_char *outframe, int *outsize)

{
  struct eap_header *eapheader;
  char *answer = NULL;
  char *data, *username;
  unsigned char chall_response[24];
  int total_length;
  unsigned char MD4Hash[16], MD4HashHash[16];
  char MasterKey[16], mppeSend[16], mppeRecv[16];
  struct config_eap_leap *userdata;
  struct leap_data *mydata;
  unsigned char challenge_response_expected[24];
  unsigned char *challenge_response_got;

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface struct passed in to eapleap_process()!\n");
      return XEMALLOC;
    }

  if (!thisint->eap_conf_data)
    {
      debug_printf(DEBUG_NORMAL, "No valid configuration information for LEAP!\n");
      return XEMALLOC;
    }

  if (!outframe)
    {
      debug_printf(DEBUG_NORMAL, "Invalid out frame buffer in eapleap_process()!\n");
      return XEMALLOC;
    }

  userdata = (struct config_eap_leap *)thisint->eap_conf_data;

  if (!thisint->eap_data)
    {
      debug_printf(DEBUG_NORMAL, "No valid state information in eapleap_proces()!\n");
      return XEMALLOC;
    }

  mydata = (struct leap_data *)thisint->eap_data;

  if ((thisint->tempPwd == NULL) && (userdata->password == NULL))
    {
      thisint->need_password = 1;
      thisint->eaptype = strdup("LEAP");
      thisint->eapchallenge = NULL;
      *outsize = 0;

      return XENONE;
    }

  // Make sure we have something to process...
  if (dataoffs == NULL) return XENONE;

  if (userdata->username == NULL)
    {
      username = thisint->identity;
    } else {
      username = userdata->username;
    }

  debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Processing.\n");
  // Actually process, and respond to challenges.

  // LEAP shouldn't be used as an inner type, so we should be able to get
  // away with this.
  data = dataoffs-5;
  eapheader = (struct eap_header *)data;

  switch (eapheader->eap_code) {

  case EAP_REQUEST:
      // ***********************************************************************************************
    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Got EAP-REQUEST\n");

    leapchallenges = (struct leap_challenges *)malloc(sizeof(struct leap_challenges));
    leaprequest = (struct leap_requests *)malloc(sizeof(struct leap_requests));

    // extract the payload received
    memcpy((struct leap_requests *)leaprequest, (struct leap_requests *)dataoffs, 16);

    // store Peer Challenge
    memcpy((uint8_t *)leapchallenges->pc, (char *)leaprequest->randval, 8);

    if (leaprequest->count != LEAP_LENGTH)  {
      debug_printf(DEBUG_NORMAL, "(EAP-LEAP) Incorrect length value for LEAP random value.\n");
      return XELEAP;
    }
    memset(chall_response, 0x0, 24);

    // Get our username and password out of our configuration structure in memory
    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) ID : %d\n",eapheader->eap_identifier);
    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Username = %s   --   Password = %s\n", username,userdata->password);
    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Incoming Peer Challenge Random Value (Length = %d) : ",leaprequest->count);
    debug_hex_printf(DEBUG_AUTHTYPES,(uint8_t *)leaprequest->randval, leaprequest->count);

    NtChallengeResponse((char *)leapchallenges->pc, userdata->password, (char *)&chall_response);

    debug_printf(DEBUG_AUTHTYPES, "MSCHAP Response Calculated : ");
    debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *)&chall_response, 24);

     // store Peer Response
    memcpy((uint8_t *)leapchallenges->pr, (char *)chall_response, 24);

    total_length = 24+2+strlen(username)+1;
    answer = (char *)malloc(total_length);
    if (answer == NULL) {
        debug_printf(DEBUG_NORMAL, "(EAP-LEAP) Couldn't allocate memory for building hash source!\n");
        return XEMALLOC;
    }
    // Construct the LEAP response sub fields packet
    // let's start with the version number (LEAP subfield)

    // byte 0: Version
    // byte 1: Unused - Reserved
    // byte 2: Count
    // byte 3..26: MS-CHAP Challenge Response
    // byte 27..m: username

    answer[0] = 0x01;
    answer[1] = 0x00; // Reserved - Unused
    answer[2] = 24; // Count

    // Include MSCHAP Challenge response in the built packet
    memcpy(&answer[3],&chall_response,24);
    // Include username in the built packet
    memcpy(&answer[24+3],username,strlen(username)+1);
    // be sure that the username (last field) will be NUL terminated!
    answer[strlen(answer)] = '\0';

    // Set up our response frame.
    memcpy(outframe, answer, total_length);
    *outsize = total_length;

    if (answer != NULL)
      free(answer);
    answer=NULL;
    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Response Packet Built\n");

  break;

  case EAP_SUCCESS:
    // ***********************************************************************************************
    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Got EAP-SUCCESS\n");
    memset(chall_response, 0x0, 8);
    NtChallengeResponse((char *)leaprequest->randval, userdata->password, (char *)&chall_response);

    GenerateNTResponse((char *)leapchallenges->pr, (char *)leapchallenges->pc, username, userdata->password, chall_response);

    // store Access Point Challenge
    memcpy((uint8_t *)leapchallenges->apc, (char *)chall_response, 8);

    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) GenerateNTResponse Calculated : ");
    debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *)&chall_response, 8);

    total_length = 8+2+strlen(username)+1;
    answer = (char *)malloc(total_length);
    if (answer == NULL) {
        debug_printf(DEBUG_NORMAL, "(EAP-LEAP) Couldn't allocate memory for building hash source!\n");
        return XEMALLOC;
    }

    // Construct the LEAP request sub fields packet
    // let's start with the version number (LEAP subfield)

    // byte 0: Version
    // byte 1: Unused - Reserved
    // byte 2: Count
    // byte 3..10: MS-CHAP Nt Challenge Response
    // byte 11..m: username

    answer[0] = 0x01;
    answer[1] = 0x00; // Reserved - Unused
    answer[2] = 8; // Count

    // Include MSCHAP Challenge response in the built packet
    memcpy(&answer[3],&chall_response,8);
    // Include username in the built packet
    memcpy(&answer[8+3],username,strlen(username)+1);
    // be sure that the username (last field) will be NUL terminated!
    answer[strlen(answer)] = '\0';

    // Set up our response frame.
    memcpy(outframe, answer, total_length);
    *outsize = total_length;

    // Store the new random value to the leapdata for further validation of the AP response !
    memcpy((char *)leaprequest->randval, (char *)&chall_response,8);

    if (answer != NULL)
      free(answer);
    answer=NULL;

    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Request Packet for Mutual Authentication Built\n");

  break;

  case EAP_RESPONSE:
    // ***********************************************************************************************
    // Verify an AP-Challenge Response from an EAP LEAP response frame.
    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Got EAP-RESPONSE\n");
    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Verification phase....\n");

    leapresponse = (struct leap_responses *)dataoffs;

    challenge_response_got =  (char *)malloc(leapresponse->count+1);
    if (!challenge_response_got) {
      debug_printf(DEBUG_NORMAL, "(EAP-LEAP) challenge_response_got is NULL after malloc!\n");
    }
    memcpy(challenge_response_got, &leapresponse->randval, leapresponse->count);

    // store Access Point Response
    memcpy((uint8_t *)leapchallenges->apr, (char *)leapresponse->randval, 24);

    // this is the real 24 bytes Challenge we got !
/*
    debug_printf(DEBUG_NORMAL, "(EAP-LEAP) AP ChallengeResponse just got: ");
    print_hex((uint8_t *)challenge_response_got, 24);
*/

    // Let's construct the expected one
    memset(challenge_response_expected, 0x0, 24);

    // Calculate the 24 bytes MS-CHAP Challenge Response
    leap_mschap(userdata->password, challenge_response_expected);

/*
    debug_printf(DEBUG_NORMAL, "(EAP-LEAP) Expected AP ChallengeResponse : ");
    print_hex((uint8_t *)challenge_response_expected,24);
*/
    if (memcmp(challenge_response_got, challenge_response_expected, 24) == 0) {
      debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) AP ChallengeResponse got is valid.\n");
      *outsize = 0;
      
      // Authentication was successful.
      //      #warning "FIX!"
      //      thisint->statemachine->eapSuccess = TRUE;
      mydata->eapsuccess = TRUE;
    }
    else {
      debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) AP ChallengeResponse got is NOT valid.\n");
      *outsize = -1;
      return XELEAP;
    }

    // We were successful, so generate keying material.

    ntPwdHash(MD4Hash, userdata->password);
    md4_calc(MD4HashHash, MD4Hash, 16);
    debug_printf(DEBUG_AUTHTYPES, "leap_session_key : ");
    debug_hex_printf(DEBUG_AUTHTYPES, MD4HashHash, 16);

    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) leapchallenges->pc : ");
    debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *)leapchallenges->pc, 8);

    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) leapchallenges->pr : ");
    debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *)leapchallenges->pr, 24);

    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) leapchallenges->apc : ");
    debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *)leapchallenges->apc, 8);

    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) leapchallenges->apr : ");
    debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *)leapchallenges->apr, 24);

    GetMasterLEAPKey((char *)MD4HashHash, leapchallenges->apc, leapchallenges->apr, leapchallenges->pc, leapchallenges->pr, (char *)&MasterKey);
    debug_printf(DEBUG_AUTHTYPES, "MasterLEAPKey : ");
    debug_hex_printf(DEBUG_AUTHTYPES, (unsigned char *)&MasterKey, 16);
    // Now, get the send key.
    GetAsymetricStartKey((u_char *)&MasterKey, (u_char *)&mppeSend, 16, TRUE, FALSE);

    // And the recv key.
    GetAsymetricStartKey((u_char *)&MasterKey, (u_char *)&mppeRecv, 16, FALSE, FALSE);

    // Finally, populate our thisint->keyingMaterial.
    if (mydata->keyingMaterial != NULL) {
      free(mydata->keyingMaterial);
      mydata->keyingMaterial = NULL;
    }
    mydata->keyingMaterial = (char *)malloc(64);  // 32 bytes each.
    if (mydata->keyingMaterial == NULL)
      return XEMALLOC;

    bzero(mydata->keyingMaterial, 64);
    memcpy(&mydata->keyingMaterial[32], &mppeRecv, 16);
    memcpy(mydata->keyingMaterial, &mppeSend, 16);

    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Long Key : ");
    debug_hex_printf(DEBUG_AUTHTYPES, mydata->keyingMaterial, 64);

    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) MPPE-Recv : ");
    debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *)mppeRecv,16);

    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) MPPE-Send : ");
    debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *)mppeSend,16);
    
    //    debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) thisint->keyingMaterial : ");
    //    debug_hex_printf(DEBUG_AUTHTYPES, (uint8_t *)thisint->keyingMaterial,64);

  break;
  }    

  return XENONE;
}

/*******************************************************
 *
 * Assign our keying material.  (Return -1 if we can't generate keys.)
 *
 *******************************************************/
int eapleap_get_keys(struct interface_data *thisint)
{
  struct leap_data *mydata;
  // If we return keys, we return 0.  If we don't, return -1;

  if ((!thisint) || (!thisint->userdata))
    {
      debug_printf(DEBUG_NORMAL, "Invalid user data in eapleap_get_keys()!\n");
      return -1;
    }

  if (thisint->userdata->activemethod == NULL)
    {
      printf("ACK! activemethod was toasted!\n");
      return -1;
    }
  mydata = (struct leap_data *)thisint->userdata->activemethod->eap_data;

  // Right now, we don't return anything from LEAP.
  thisint->keyingMaterial = mydata->keyingMaterial;

  return 0;
}

/*******************************************************
 *
 * Return if we have successfully authenticated.
 *
 *******************************************************/
int eapleap_done(struct generic_eap_data *thisint)
{
  struct leap_data *mydata;

  if (!thisint)
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface structure passed in to eapleap_done()!\n");
      return XEMALLOC;
    }

  mydata = (struct leap_data *)thisint->eap_data;

  if (!mydata)
    {
      debug_printf(DEBUG_NORMAL, "Invalid eap data in eapleap_done()!\n");
      return XEMALLOC;
    }

  return mydata->eapsuccess;
}

/*******************************************************
 *
 * Clean up after ourselves.  This will get called when we get a packet that
 * needs to be processed requests a different EAP type.  It will also be
 * called on termination of the program.
 *
 *******************************************************/
int eapleap_cleanup(struct generic_eap_data *thisint)
{
  struct leap_data *mydata;

  if ((!thisint) || (!thisint->eap_data))
    {
      debug_printf(DEBUG_NORMAL, "Invalid interface structure passed in to eapleap_cleanup()!\n");
      return XEMALLOC;
    }

  mydata = (struct leap_data *)thisint->eap_data;

  if (mydata->keyingMaterial != NULL)
    {
      free(mydata->keyingMaterial);
    }

  free(mydata);

  debug_printf(DEBUG_AUTHTYPES, "(EAP-LEAP) Cleaning up.\n");
  return XENONE;
}

/********************************************************
 *
 * We failed authentication for some reason, so clear out our password so
 * that we are prompted again at a later time.
 *
 ********************************************************/
int eapleap_failed(struct generic_eap_data *thisint)
{
  struct config_eap_leap *userdata;

  if ((!thisint) || (!thisint->eap_conf_data))
    {
      debug_printf(DEBUG_AUTHTYPES, "Invalid LEAP configuration data! Nothing to clean up!\n");
      return XEMALLOC;
    }

  userdata = (struct config_eap_leap *)thisint->eap_conf_data;

#ifndef NO_PWD_RESET
  /*
  if (userdata->password != NULL)
    {
      free(userdata->password);
      userdata->password = NULL;
    }
  */
#endif

  return XENONE;
}
