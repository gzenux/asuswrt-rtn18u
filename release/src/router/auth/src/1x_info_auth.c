
#include "stdafx.h"
#include "1x_info.h"
#include "1x_common.h"
#include "1x_ioctl.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


int multicast;
int unicast[4];
u_short ucount;
int auth[4];
u_short acount;
int unicastasgroup;
int replayindex;

/*
void test(struct InfoElement *IE, int length)
{
	u_char oui00[4] = { 0x00, 0x50, 0xf2, 0x00 };
	u_char oui01[4] = { 0x00, 0x50, 0xf2, 0x01 };
	u_char oui02[4] = { 0x00, 0x50, 0xf2, 0x02 };
	u_char oui03[4] = { 0x00, 0x50, 0xf2, 0x03 };
	u_char oui04[4] = { 0x00, 0x50, 0xf2, 0x04 };
	u_char oui05[4] = { 0x00, 0x50, 0xf2, 0x05 };
	int i = 0, j, m, n;
	struct _ieauth *ieauth;
	char *caps;

	multicast = CIPHER_TKIP;
	unicast[0] = CIPHER_TKIP;
	ucount = 1;
	auth[0] = IEEE802_1X;
	acount = 1;
	unicastasgroup = 0;
	replayindex = 2;

	// information element header makes sense
	if ( (IE->length+2 == length) && (IE->length >= 6)
  && (IE->Elementid == ELEMENTID)
	  && !memcmp(IE->oui, oui01, 4) && (IE->version == 1)) {
	    // update each variable if IE is long enough to contain the
    // variable
		if (IE->length >= 10) {
			if (!memcmp(IE->multicast, oui01, 4))
				multicast = CIPHER_WEP40;
			else if (!memcmp(IE->multicast, oui02, 4))
				multicast = CIPHER_TKIP;
			else if (!memcmp(IE->multicast, oui03, 4))
				multicast = CIPHER_AESCCMP;
			else if (!memcmp(IE->multicast, oui04, 4))
				multicast = CIPHER_AESWRAP;
			else if (!memcmp(IE->multicast, oui05, 4))
				multicast = CIPHER_WEP104;
			else
				// any vendor checks here
				multicast = -1;
		}
		if (IE->length >= 12) {
			j = 0;
			for(i = 0; (i < IE->ucount)
 && (j < sizeof(unicast)/sizeof(int)); i++) {
				if(IE->length >= 12+i*4+4) {
					if (!memcmp(IE->unicast[i].oui, oui00, 4))
						unicast[j++] = NONE;
					else if (!memcmp(IE->unicast[i].oui, oui02, 4))
						unicast[j++] = CIPHER_TKIP;
					else if (!memcmp(IE->unicast[i].oui, oui03, 4))
						unicast[j++] = CIPHER_AESCCMP;
					else if (!memcmp(IE->unicast[i].oui, oui04, 4))
						unicast[j++] = CIPHER_AESWRAP;
					else
						// any vendor checks here
						;
				}
				else
					break;
			}
			ucount = j;
		}
		m = i;
		if (IE->length >= 14+m*4) {
			// overlay ieauth structure into correct place
			ieauth = (struct _ieauth *)IE->unicast[m].oui;
			j = 0;
			for(i = 0; (i < ieauth->acount)
 && (j < sizeof(auth)/sizeof(int)); i++) {
				if(IE->length >= 14+4+(m+i)*4) {
					if (!memcmp(ieauth->auth[i].oui, oui00, 4))
						auth[j++] = IEEE802_1X;
					else
						// any vendor checks here
						;
				}
				else
					break;
			}
			if(j > 0)
				acount = j;
		}
		n = i;
		if(IE->length+2 >= 14+4+(m+n)*4) {
			caps = (char *)ieauth->auth[n].oui;
			unicastasgroup = (*caps)&GROUPFLAG;
			replayindex = 2<<((*caps>>REPLAYBITSSHIFT)&REPLAYBITS);
		}
	}
}

char *cip[] = { "", " WEP40", " TKIP", " AES-CCMP", "AES-WRAP", "WEP104" };
char *cip1[] = { " NONE", " WEP40", " TKIP", " AES-CCMP", "AES-WRAP", "CIPHER_WEP104" };
char *aip[] = { "", " 802.1X" };

// Various IEs to try above with
u_char test1[] = {	0xdd, 0x06, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00 };
u_char test2[] = {	0xdd, 0x0a, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
	0x00, 0x50, 0xf2, 0x01};
u_char test3[] = {	0xdd, 0x10, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
	0x00, 0x50, 0xf2, 0x01,
	0x01, 0x00, 0x00, 0x50, 0xf2, 0x00};
u_char test4[] = {	0xdd, 0x10, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
	0x00, 0x50, 0xf2, 0x01,
	0x01, 0x00, 0x00, 0x50, 0xf2, 0x02 };
u_char test5[] = {	0xdd, 0x18, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
	0x00, 0x50, 0xf2, 0x01,
	0x01, 0x00, 0x00, 0x50, 0xf2, 0x02,
	0x01, 0x00, 0x00, 0x50, 0xf2, 0x00,
	0x06, 0x00 };
u_char test6[] = {	0xdd, 0x1c, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
	0x00, 0x50, 0xf2, 0x02,
	0x02, 0x00, 0x00, 0x50, 0xf2, 0x02, 0x00, 0x50, 0xf2, 0x03,
	0x01, 0x00, 0x00, 0x50, 0xf2, 0x00,
	0x02, 0x00 };
// too small - ignored
u_char test7[] = {	0xdd, 0x04, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00 };
// unicast count too high, 2nd unicast ignored and default auth
u_char test8[] = {	0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
	0x00, 0x50, 0xf2, 0x01,
	0x02, 0x00, 0x00, 0x50, 0xf2, 0x02,
	0x01, 0x00, 0x00, 0x50, 0xf2, 0x00};
// unicast count past end of IE
u_char test9[] = {	0xdd, 0x16, 0x00, 0x50, 0xf2, 0x01, 0x01, 0x00,
	0x00, 0x50, 0xf2, 0x01,
	0x10, 0x00, 0x00, 0x50, 0xf2, 0x02,
	0x01, 0x00, 0x00, 0x50, 0xf2, 0x00};

u_char *testinfo[] = { test1, test2, test3, test4, test5, test6, test7, test8, test9, NULL };

int testsize[] = { sizeof(test1), sizeof(test2), sizeof(test3),
sizeof(test4), sizeof(test5), sizeof(test6), sizeof(test7),

sizeof(test8), sizeof(test9), 0 };



int _tmain()
{
	int i;
	for(i = 0; testinfo[i] != NULL; i++) {
		test(( struct InfoElement *)testinfo[i], testsize[i]);
		printf("IE %d Multicast%s Unicast%s%s%s%s Auth%s%s%s%s %sReplayIndex %d\n",
			i, cip1[(multicast+1)], cip1[(ucount>0?unicast[0]:-1)+1],
			cip[(ucount>1?unicast[1]:-1)+1], cip[(ucount>2?unicast[2]:-1)+1], cip[(ucount>3?unicast[3]:-1)+1],
			aip[(acount>0?auth[0]:-1)+1], aip[(acount>1?auth[1]:-1)+1], aip[(acount>2?auth[2]:-1)+1], aip[(acount>3?auth[3]:-1)+1],
			unicastasgroup?"Group ":"", replayindex);
	}
	return 0;
}

*/
char * lib1x_authRSN_err(int err)
{

        switch(err)
        {
		case ERROR_BUFFER_TOO_SMALL:
                return RSN_STRERROR_BUFFER_TOO_SMALL;
        case ERROR_INVALID_PARA:
                return RSN_STRERROR_INVALID_PARAMETER;
		case ERROR_INVALID_RSNIE:
			return RSN_STRERROR_INVALID_RSNIE;
		case ERROR_INVALID_MULTICASTCIPHER:
			return RSN_STRERROR_INVALID_MULTICASTCIPHER;
		case ERROR_INVALID_UNICASTCIPHER:
			return RSN_STRERROR_INVALID_UNICASTCIPHER;
		case ERROR_INVALID_AUTHKEYMANAGE:
			return RSN_STRERROR_INVALID_AUTHKEYMANAGE;
		case ERROR_UNSUPPORTED_RSNEVERSION:
			return RSN_STRERROR_UNSUPPORTED_RSNEVERSION;
		case ERROR_INVALID_CAPABILITIES:
			return RSN_STRERROR_INVALID_CAPABILITIES;
#ifdef CONFIG_IEEE80211W			
		case ERROR_MGMT_FRAME_PROTECTION_VIOLATION:
			return RSN_STRERROR_MGMT_FRAME_PROTECTION_VIOLATION;
#endif			
        }
        return "Uknown Failure";
}

int lib1x_authRSN_constructIE(Dot1x_Authenticator * auth,
				u_char * pucOut,
				int * usOutLen,
				BOOLEAN bAttachIEHeader)
{
        int retVal = 0;

        DOT11_RSN_IE_HEADER dot11RSNIEHeader = { 0 };
        DOT11_RSN_IE_SUITE dot11RSNGroupSuite;
#if defined(CONFIG_IEEE80211W) || defined(HS2_SUPPORT)
		DOT11_RSN_IE_SUITE dot11RSNMgmtSuite;
#endif
#ifdef HS2_SUPPORT
		DOT11_OSEN_IE_HEADER dot11OSENHeader = {0};
#endif
        DOT11_RSN_IE_COUNT_SUITE  * pDot11RSNPairwiseSuite = NULL;
        DOT11_RSN_IE_COUNT_SUITE  * pDot11RSNAuthSuite = NULL;
        DOT11_RSN_CAPABILITY dot11RSNCapability = { 0 };
		u_short usSuitCount;
        u_long  ulIELength = 0;
        u_long  ulIndex = 0;
        u_long  ulPairwiseLength = 0, uCipherAlgo = 0;
		BOOLEAN bCipherAlgoEnabled = FALSE;
        u_long  ulAuthLength = 0, uAuthAlgo = 0;
		BOOLEAN bAuthAlgoEnabled = FALSE;
        u_long  ulRSNCapabilityLength = 0;
        u_char* pucBlob;

#ifdef RTL_WPA2
	*usOutLen = 0;
	if ( auth->RSNVariable.WPAEnabled ) {
#endif
        //
        // Construct Information Header
	//
        dot11RSNIEHeader.ElementID = RSN_ELEMENT_ID;
	dot11RSNIEHeader.OUI[0] = 0x00;
	dot11RSNIEHeader.OUI[1] = 0x50;
	dot11RSNIEHeader.OUI[2] = 0xf2;
	dot11RSNIEHeader.OUI[3] = 0x01;
	lib1x_Little_S2N(RSN_VER1, (u_char*)&dot11RSNIEHeader.Version);
        ulIELength += sizeof(DOT11_RSN_IE_HEADER);

	// Construct Cipher Suite:
	//      - Multicast Suite:
	//
	memset(&dot11RSNGroupSuite, 0, sizeof dot11RSNGroupSuite);
	dot11RSNGroupSuite.OUI[0] = 0x00;
	dot11RSNGroupSuite.OUI[1] = 0x50;
	dot11RSNGroupSuite.OUI[2] = 0xF2;

	dot11RSNGroupSuite.Type = auth->RSNVariable.MulticastCipher;
	ulIELength += sizeof(DOT11_RSN_IE_SUITE);

    	//      - UnicastSuite

        pDot11RSNPairwiseSuite = (DOT11_RSN_IE_COUNT_SUITE*)malloc(sizeof(DOT11_RSN_IE_COUNT_SUITE));
        memset(pDot11RSNPairwiseSuite, 0, sizeof(DOT11_RSN_IE_COUNT_SUITE));

	usSuitCount = 0;
        for (ulIndex = 0; ulIndex < auth->RSNVariable.UniCastCipherSuit.NumOfAlgo; ulIndex++)
        {
                uCipherAlgo = auth->RSNVariable.UniCastCipherSuit.AlgoTable[ulIndex].AlgoId;
                bCipherAlgoEnabled = auth->RSNVariable.UniCastCipherSuit.AlgoTable[ulIndex].Enabled;


                if (!bCipherAlgoEnabled) {
                    continue;
                }
                pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].OUI[0] = 0x00;
		pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].OUI[1] = 0x50;
		pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].OUI[2] = 0xF2;

                switch (uCipherAlgo) {
			case DOT11_ENC_NONE:
				pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_ENC_NONE;
				usSuitCount++;
                                break;
                        case DOT11_ENC_WEP40:
                                pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_ENC_WEP40;
                                usSuitCount++;
                                break;

                        case DOT11_ENC_TKIP:
                                pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_ENC_TKIP;
				usSuitCount++;
                                break;

                        case DOT11_ENC_WRAP:
                                pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_ENC_WRAP;
				usSuitCount++;
                                break;

                        case DOT11_ENC_CCMP:
                                pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_ENC_CCMP;
				usSuitCount++;
                                break;

                        case DOT11_ENC_WEP104:
                                pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_ENC_WEP104;
				usSuitCount++;
                                break;
                        default:
                                break;
                        }//switch
        }
	lib1x_Little_S2N(usSuitCount, (u_char*)&pDot11RSNPairwiseSuite->SuiteCount);
        ulPairwiseLength = sizeof(pDot11RSNPairwiseSuite->SuiteCount) + usSuitCount*sizeof(DOT11_RSN_IE_SUITE);
        ulIELength += ulPairwiseLength;

	//
	// Construction of Auth Algo List
	//

        pDot11RSNAuthSuite = (DOT11_RSN_IE_COUNT_SUITE*)malloc(sizeof(DOT11_RSN_IE_COUNT_SUITE));
        memset(pDot11RSNAuthSuite, 0, sizeof(DOT11_RSN_IE_COUNT_SUITE));

		usSuitCount = 0;
        for (ulIndex = 0; ulIndex < auth->RSNVariable.AuthenticationSuit.NumOfAlgo; ulIndex++)
        {
                uAuthAlgo = auth->RSNVariable.AuthenticationSuit.AlgoTable[ulIndex].AlgoId;
                bAuthAlgoEnabled = auth->RSNVariable.AuthenticationSuit.AlgoTable[ulIndex].Enabled;

                if (!bAuthAlgoEnabled) {
                    continue;
                }

                pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].OUI[0] = 0x00;
				pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].OUI[1] = 0x50;
				pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].OUI[2] = 0xF2;

                switch (uAuthAlgo) {
                case DOT11_AuthKeyType_RSN:
                    pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_AuthKeyType_RSN;
				    usSuitCount++;
                    break;
                case DOT11_AuthKeyType_RSNPSK:
                    pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_AuthKeyType_RSNPSK;
				    usSuitCount++;
                    break;
#ifndef CONFIG_IEEE80211R
				case DOT11_AuthKeyType_NonRSN802dot1x:
				    pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_AuthKeyType_NonRSN802dot1x;
				    usSuitCount++;
#endif
		        default:
                    break;
                }

        }
		lib1x_Little_S2N(usSuitCount, (u_char*)&pDot11RSNAuthSuite->SuiteCount);
        ulAuthLength = sizeof(pDot11RSNAuthSuite->SuiteCount) + usSuitCount*sizeof(DOT11_RSN_IE_SUITE);
        ulIELength += ulAuthLength;


	//---------------------------------------------------------------------------------------------
	// Do not encapsulate capability field to solve TI WPA issue
	//---------------------------------------------------------------------------------------------
	/*
        dot11RSNCapability.field.PreAuthentication = 0;//auth->RSNVariable.isSupportPreAuthentication
        dot11RSNCapability.field.PairwiseAsDefaultKey = auth->RSNVariable.isSupportPairwiseAsDefaultKey;
        switch(auth->RSNVariable.NumOfRxTSC)
        {
        case 1:
	        dot11RSNCapability.field.NumOfReplayCounter = 0;
        	break;
	case 2:
		dot11RSNCapability.field.NumOfReplayCounter = 1;
		break;
	case 4:
		dot11RSNCapability.field.NumOfReplayCounter = 2;
		break;
	case 16:
		dot11RSNCapability.field.NumOfReplayCounter = 3;
        	break;
        default:
		dot11RSNCapability.field.NumOfReplayCounter = 0;
        }

        ulRSNCapabilityLength = sizeof(DOT11_RSN_CAPABILITY);
        ulIELength += ulRSNCapabilityLength;
	*/

        pucBlob = pucOut;
        //memcpy(pucBlob, &dot11RSNIEHeader, sizeof(DOT11_RSN_IE_HEADER));
        pucBlob += sizeof(DOT11_RSN_IE_HEADER);
        memcpy(pucBlob, &dot11RSNGroupSuite, sizeof(DOT11_RSN_IE_SUITE));
        pucBlob += sizeof(DOT11_RSN_IE_SUITE);
        memcpy(pucBlob, pDot11RSNPairwiseSuite, ulPairwiseLength);
        pucBlob += ulPairwiseLength;
        memcpy(pucBlob, pDot11RSNAuthSuite, ulAuthLength);
        pucBlob += ulAuthLength;
        memcpy(pucBlob, &dot11RSNCapability, ulRSNCapabilityLength);

        *usOutLen = (int)ulIELength;
        pucBlob = pucOut;
        dot11RSNIEHeader.Length = (u_char)ulIELength - 2; //This -2 is to minus elementID and Length in OUI header
        memcpy(pucBlob, &dot11RSNIEHeader, sizeof(DOT11_RSN_IE_HEADER));

		free(pDot11RSNPairwiseSuite);
		free(pDot11RSNAuthSuite);
#ifdef RTL_WPA2
		//wpa2_hexdump("lib1x_authRSN_constructIE: WPA RSN IE", pucBlob, ulIELength);
    }
#endif

#ifdef RTL_WPA2
	if ( auth->RSNVariable.WPA2Enabled ) {

        DOT11_WPA2_IE_HEADER dot11WPA2IEHeader = { 0 };
		ulIELength = 0;
		ulIndex = 0;
		ulPairwiseLength = 0;
		uCipherAlgo = 0;
		bCipherAlgoEnabled = FALSE;
		ulAuthLength = 0;
		uAuthAlgo = 0;
		bAuthAlgoEnabled = FALSE;
		ulRSNCapabilityLength = 0;


		/*Construct Information Header*/ 

        #ifdef HS2_SUPPORT

        HS2DEBUG("OSEN=[%d]\n",auth->RSNVariable.bOSEN);
		HS2DEBUG("11W=[%d]\n",auth->RSNVariable.ieee80211w);

        if(auth->RSNVariable.bOSEN == 1)
		{
			//HS2DEBUG("OSEN IE Information\n");
			dot11OSENHeader.ElementID = RSN_ELEMENT_ID;
			dot11OSENHeader.OUI[0] = 0x50;
			dot11OSENHeader.OUI[1] = 0x6F;
			dot11OSENHeader.OUI[2] = 0x9A;
			dot11OSENHeader.Type = 0x12;
			ulIELength += sizeof(DOT11_OSEN_IE_HEADER);

			/*Construct Cipher Suite:*/ 

			/*- Multicast Suite:*/      
			memset(&dot11RSNGroupSuite, 0, sizeof dot11RSNGroupSuite);
			dot11RSNGroupSuite.OUI[0] = 0x00;
			dot11RSNGroupSuite.OUI[1] = 0x0F;
			dot11RSNGroupSuite.OUI[2] = 0xAC;
			dot11RSNGroupSuite.Type = DOT11_ENC_NOGA;
			ulIELength += sizeof(DOT11_RSN_IE_SUITE);

			/*- UnicastSuite*/      
			pDot11RSNPairwiseSuite = (DOT11_RSN_IE_COUNT_SUITE*)malloc(sizeof(DOT11_RSN_IE_COUNT_SUITE));
			memset(pDot11RSNPairwiseSuite, 0, sizeof(DOT11_RSN_IE_COUNT_SUITE));
			usSuitCount = 0;
			pDot11RSNPairwiseSuite->dot11RSNIESuite[0].OUI[0] = 0x00;
			pDot11RSNPairwiseSuite->dot11RSNIESuite[0].OUI[1] = 0x0F;
			pDot11RSNPairwiseSuite->dot11RSNIESuite[0].OUI[2] = 0xAC;
			pDot11RSNPairwiseSuite->dot11RSNIESuite[0].Type = DOT11_ENC_CCMP;
			usSuitCount++;
			lib1x_Little_S2N(usSuitCount, (u_char*)&pDot11RSNPairwiseSuite->SuiteCount);
			ulPairwiseLength = sizeof(pDot11RSNPairwiseSuite->SuiteCount) + usSuitCount*sizeof(DOT11_RSN_IE_SUITE);
			ulIELength += ulPairwiseLength;


			/*Construction of Auth Algo List*/ 

			pDot11RSNAuthSuite = (DOT11_RSN_IE_COUNT_SUITE*)malloc(sizeof(DOT11_RSN_IE_COUNT_SUITE));
			memset(pDot11RSNAuthSuite, 0, sizeof(DOT11_RSN_IE_COUNT_SUITE));
			usSuitCount = 0;
		
			pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].OUI[0] = 0x50;
			pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].OUI[1] = 0x6F;
			pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].OUI[2] = 0x9A;
			pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].Type = 0x01;
			
			usSuitCount++;	
			lib1x_Little_S2N(usSuitCount, (u_char*)&pDot11RSNAuthSuite->SuiteCount);
			ulAuthLength = sizeof(pDot11RSNAuthSuite->SuiteCount) + usSuitCount*sizeof(DOT11_RSN_IE_SUITE);
			ulIELength += ulAuthLength;
			
			/*RSN Capability*/ 
			memset(&dot11RSNCapability, 0, sizeof(dot11RSNCapability));

			
			pucBlob = pucOut + *usOutLen;
			//memcpy(pucBlob, &dot11WPA2IEHeader, sizeof(DOT11_RSN_IE_HEADER));
			pucBlob += sizeof(DOT11_OSEN_IE_HEADER);
			memcpy(pucBlob, &dot11RSNGroupSuite, sizeof(DOT11_RSN_IE_SUITE));
			pucBlob += sizeof(DOT11_RSN_IE_SUITE);
			memcpy(pucBlob, pDot11RSNPairwiseSuite, ulPairwiseLength);
			pucBlob += ulPairwiseLength;
			memcpy(pucBlob, pDot11RSNAuthSuite, ulAuthLength);
			pucBlob += ulAuthLength;
			memcpy(pucBlob, &dot11RSNCapability, ulRSNCapabilityLength);
			ulRSNCapabilityLength = sizeof(DOT11_RSN_CAPABILITY);
			ulIELength += ulRSNCapabilityLength;
						
			pucBlob += ulRSNCapabilityLength + 2; // add PMDID Count (2bytes)
			
			memset(&dot11RSNMgmtSuite, 0, sizeof(dot11RSNMgmtSuite));					
			memcpy(pucBlob, &dot11RSNMgmtSuite, sizeof(DOT11_RSN_IE_SUITE));	
			ulIELength += sizeof(dot11RSNMgmtSuite)+2;
			
			pucBlob = pucOut + *usOutLen;
			dot11OSENHeader.Length = (u_char)ulIELength - 2; //This -2 is to minus elementID and Length in OUI header
			memcpy(pucBlob, &dot11OSENHeader, sizeof(DOT11_OSEN_IE_HEADER));
			*usOutLen = *usOutLen + (int)ulIELength;
		}
		else
        #endif // end of HS2_SUPPORT
    	{


    		//HS2DEBUG("WPA2 IE Information\n");
    		dot11WPA2IEHeader.ElementID = WPA2_ELEMENT_ID;
    		lib1x_Little_S2N(RSN_VER1, (u_char*)&dot11WPA2IEHeader.Version);
    		ulIELength += sizeof(DOT11_WPA2_IE_HEADER);

    		/*Construct Cipher Suite:*/ 

    		/*- Multicast Suite:*/      

    		memset(&dot11RSNGroupSuite, 0, sizeof dot11RSNGroupSuite);
    		dot11RSNGroupSuite.OUI[0] = 0x00;
    		dot11RSNGroupSuite.OUI[1] = 0x0F;
    		dot11RSNGroupSuite.OUI[2] = 0xAC;

    		dot11RSNGroupSuite.Type = auth->RSNVariable.MulticastCipher;
    		ulIELength += sizeof(DOT11_RSN_IE_SUITE);

    		/*- UnicastSuite*/      

    		pDot11RSNPairwiseSuite = (DOT11_RSN_IE_COUNT_SUITE*)malloc(sizeof(DOT11_RSN_IE_COUNT_SUITE));
    		memset(pDot11RSNPairwiseSuite, 0, sizeof(DOT11_RSN_IE_COUNT_SUITE));
    		usSuitCount = 0;
            
            for (ulIndex = 0; ulIndex < auth->RSNVariable.WPA2UniCastCipherSuit.NumOfAlgo; ulIndex++)
    		{
    		
                uCipherAlgo = auth->RSNVariable.WPA2UniCastCipherSuit.AlgoTable[ulIndex].AlgoId;
                bCipherAlgoEnabled = auth->RSNVariable.WPA2UniCastCipherSuit.AlgoTable[ulIndex].Enabled;


    			if (!bCipherAlgoEnabled) {
    			    continue;
    			}
                
    			pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].OUI[0] = 0x00;
    			pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].OUI[1] = 0x0F;
    			pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].OUI[2] = 0xAC;

    			switch (uCipherAlgo) {
    				case DOT11_ENC_NONE:
    					pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_ENC_NONE;
    					usSuitCount++;
    					break;
    				case DOT11_ENC_WEP40:
    					pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_ENC_WEP40;
    					usSuitCount++;
    					break;

    				case DOT11_ENC_TKIP:
    					pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_ENC_TKIP;
    					usSuitCount++;
    					break;

    				case DOT11_ENC_WRAP:
    					pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_ENC_WRAP;
    					usSuitCount++;
    					break;

    				case DOT11_ENC_CCMP:
    					pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_ENC_CCMP;
    					usSuitCount++;
    					break;

    				case DOT11_ENC_WEP104:
    					pDot11RSNPairwiseSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_ENC_WEP104;
    					usSuitCount++;
    					break;
    				default:
    					break;
    		    }//end of switch
    		}
            
    		lib1x_Little_S2N(usSuitCount, (u_char*)&pDot11RSNPairwiseSuite->SuiteCount);
    		ulPairwiseLength = sizeof(pDot11RSNPairwiseSuite->SuiteCount) + usSuitCount*sizeof(DOT11_RSN_IE_SUITE);
    		ulIELength += ulPairwiseLength;
   			//printf("ulIELength=%d\n",ulIELength);

            

    		/* Construction of Auth Algo List*/

    		pDot11RSNAuthSuite = (DOT11_RSN_IE_COUNT_SUITE*)malloc(sizeof(DOT11_RSN_IE_COUNT_SUITE));
    		memset(pDot11RSNAuthSuite, 0, sizeof(DOT11_RSN_IE_COUNT_SUITE));

    		usSuitCount = 0;
    		for (ulIndex = 0; ulIndex < auth->RSNVariable.AuthenticationSuit.NumOfAlgo; ulIndex++)
    		{
    			uAuthAlgo = auth->RSNVariable.AuthenticationSuit.AlgoTable[ulIndex].AlgoId;
    			bAuthAlgoEnabled = auth->RSNVariable.AuthenticationSuit.AlgoTable[ulIndex].Enabled;

    			if (!bAuthAlgoEnabled) {
    			    continue;
    			}

    			pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].OUI[0] = 0x00;
    			pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].OUI[1] = 0x0F;
    			pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].OUI[2] = 0xAC;

    			switch (uAuthAlgo) {
        			case DOT11_AuthKeyType_RSN:
        			    pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_AuthKeyType_RSN;
        			    usSuitCount++;
        			    break;

        			case DOT11_AuthKeyType_RSNPSK:
        			    pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_AuthKeyType_RSNPSK;
        			    usSuitCount++;
        			    break;
#ifndef CONFIG_IEEE80211R		
					case DOT11_AuthKeyType_NonRSN802dot1x:				
						pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_AuthKeyType_NonRSN802dot1x;	
						usSuitCount++;				
					break;
#else
					case DOT11_AuthKeyType_FT:
						pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_AuthKeyType_FT;	
						usSuitCount++;								
						break;
#endif
                    #ifdef CONFIG_IEEE80211W					
        			case DOT11_AuthKeyType_802_1X_SHA256:
        				pDot11RSNAuthSuite->dot11RSNIESuite[usSuitCount].Type = DOT11_AuthKeyType_802_1X_SHA256;
        			    usSuitCount++;
        				break;
                    #endif					
        			default:
        			    break;
    			}

    		}

            
    		lib1x_Little_S2N(usSuitCount, (u_char*)&pDot11RSNAuthSuite->SuiteCount);
    		ulAuthLength = sizeof(pDot11RSNAuthSuite->SuiteCount) + usSuitCount*sizeof(DOT11_RSN_IE_SUITE);
    		ulIELength += ulAuthLength;
    		//printf("ulIELength=%d\n",ulIELength);

    		//---------------------------------------------------------------------------------------------
    		// Do not encapsulate capability field to solve TI WPA issue
    		//---------------------------------------------------------------------------------------------

#ifdef RTL_WPA2
    		dot11RSNCapability.field.PreAuthentication = auth->RSNVariable.isSupportPreAuthentication;

            #ifdef CONFIG_IEEE80211W
			/*Protected Managemenet Protection Capability (PMF)*/
			if (auth->RSNVariable.ieee80211w == NO_MGMT_FRAME_PROTECTION) {			
				dot11RSNCapability.field.MFPC = 0;
				dot11RSNCapability.field.MFPR = 0;
			}
			else if (auth->RSNVariable.ieee80211w == MGMT_FRAME_PROTECTION_OPTIONAL)
				dot11RSNCapability.field.MFPC= 1; // MFPC 
			else if (auth->RSNVariable.ieee80211w == MGMT_FRAME_PROTECTION_REQUIRED) {
				dot11RSNCapability.field.MFPR= 1; // MFPR
				dot11RSNCapability.field.MFPC= 1; // MFPC 
			}
            #endif
            
#else
    		dot11RSNCapability.field.PairwiseAsDefaultKey = auth->RSNVariable.isSupportPairwiseAsDefaultKey;
    		switch(auth->RSNVariable.NumOfRxTSC)
    		{
    		case 1:
    			dot11RSNCapability.field.NumOfReplayCounter = 0;
    			break;
    		case 2:
    			dot11RSNCapability.field.NumOfReplayCounter = 1;
    			break;
    		case 4:
    			dot11RSNCapability.field.NumOfReplayCounter = 2;
    			break;
    		case 16:
    			dot11RSNCapability.field.NumOfReplayCounter = 3;
    			break;
    		default:
    			dot11RSNCapability.field.NumOfReplayCounter = 0;
    		}
#endif
    		ulRSNCapabilityLength = sizeof(DOT11_RSN_CAPABILITY);
    		ulIELength += ulRSNCapabilityLength;

            #ifdef CONFIG_IEEE80211W

    		/*Construct Cipher Suite: - IGTK Suite:*/ 

    		if (auth->RSNVariable.ieee80211w != NO_MGMT_FRAME_PROTECTION)
    		{
    			memset(&dot11RSNMgmtSuite, 0, sizeof(dot11RSNMgmtSuite));
    			dot11RSNMgmtSuite.OUI[0] = 0x00;
    			dot11RSNMgmtSuite.OUI[1] = 0x0F;
    			dot11RSNMgmtSuite.OUI[2] = 0xAC;

    			dot11RSNMgmtSuite.Type = DOT11_ENC_BIP;
    			ulIELength += sizeof(dot11RSNMgmtSuite)+2;
    		}
            #endif // CONFIG_IEEE80211W

    		pucBlob = pucOut + *usOutLen;
    		//memcpy(pucBlob, &dot11WPA2IEHeader, sizeof(DOT11_RSN_IE_HEADER));
    		pucBlob += sizeof(DOT11_WPA2_IE_HEADER);
    		memcpy(pucBlob, &dot11RSNGroupSuite, sizeof(DOT11_RSN_IE_SUITE));
    		pucBlob += sizeof(DOT11_RSN_IE_SUITE);
    		memcpy(pucBlob, pDot11RSNPairwiseSuite, ulPairwiseLength);
    		pucBlob += ulPairwiseLength;
    		memcpy(pucBlob, pDot11RSNAuthSuite, ulAuthLength);
    		pucBlob += ulAuthLength;
    		memcpy(pucBlob, &dot11RSNCapability, ulRSNCapabilityLength);
            
            #ifdef CONFIG_IEEE80211W		
    		if (auth->RSNVariable.ieee80211w != NO_MGMT_FRAME_PROTECTION) { 		
    			pucBlob += ulRSNCapabilityLength + 2; // add PMDID Count (2bytes)
    			memcpy(pucBlob, &dot11RSNMgmtSuite, sizeof(DOT11_RSN_IE_SUITE));
    		}
            #endif //end of  CONFIG_IEEE80211W
            
    		pucBlob = pucOut + *usOutLen;
    		dot11WPA2IEHeader.Length = (u_char)ulIELength - 2; //This -2 is to minus elementID and Length in OUI header
    		memcpy(pucBlob, &dot11WPA2IEHeader, sizeof(DOT11_WPA2_IE_HEADER));
    		*usOutLen = *usOutLen + (int)ulIELength;
   		}
		

		free(pDot11RSNPairwiseSuite);
		free(pDot11RSNAuthSuite);
        #if 0 /*for debug*/ 
    	wpa2_hexdump("lib1x_authRSN_constructIE: WPA2 RSN IE", pucBlob, ulIELength);
        #endif

    	}
    
#endif /*end  of  RTL_WPA2 */

        return retVal;
}

//--------------------------------------------------------------------------
// Save Association Request info
//--------------------------------------------------------------------------
int lib1x_authRSN_parseIE(Dot1x_Authenticator * auth,
				Global_Params * global,
				u_char * pucIE, u_long ulIELength)
{

        int retVal = 0;
	u_short	usVersion;
	u_short	usSuitCount;

        DOT11_RSN_IE_HEADER * pDot11RSNIEHeader = NULL;
	DOT11_RSN_IE_SUITE  * pDot11RSNIESuite = NULL;
	DOT11_RSN_IE_COUNT_SUITE * pDot11RSNIECountSuite = NULL;
	DOT11_RSN_CAPABILITY * pDot11RSNCapability = NULL;

	//AUTHDEBUG("lib1x_authRSN_parseIE\n");
    if(ulIELength < sizeof(DOT11_RSN_IE_HEADER)) {
		retVal = ERROR_INVALID_RSNIE;
		goto lib1x_authRSN_parseIE_error;
	}

	pDot11RSNIEHeader = (DOT11_RSN_IE_HEADER *)pucIE;
	lib1x_Little_N2S((u_char*)&pDot11RSNIEHeader->Version, usVersion);

	if (usVersion != RSN_VER1)
	{
		retVal = ERROR_UNSUPPORTED_RSNEVERSION;
		goto lib1x_authRSN_parseIE_error;
	}
	if (pDot11RSNIEHeader->ElementID != RSN_ELEMENT_ID ||
		pDot11RSNIEHeader->Length != ulIELength -2 ||
		pDot11RSNIEHeader->OUI[0] != 0x00 || pDot11RSNIEHeader->OUI[1] != 0x50 ||
		pDot11RSNIEHeader->OUI[2] != 0xf2 || pDot11RSNIEHeader->OUI[3] != 0x01 )
	{
		retVal = ERROR_INVALID_RSNIE;
		goto lib1x_authRSN_parseIE_error;
	}
	global->RSNVariable.RSNEnabled= TRUE;
#ifdef RTL_WPA2
	global->RSNVariable.WPAEnabled= TRUE;
#endif
	ulIELength -= sizeof(DOT11_RSN_IE_HEADER);
	pucIE += sizeof(DOT11_RSN_IE_HEADER);


	//----------------------------------------------------------------------------------
 	// Multicast Cipher Suite processing
	//----------------------------------------------------------------------------------

	if(ulIELength < sizeof(DOT11_RSN_IE_SUITE)) {
		retVal = 0;
		goto lib1x_authRSN_parseIE_success;
	}

	pDot11RSNIESuite = (DOT11_RSN_IE_SUITE *)pucIE;
	if (pDot11RSNIESuite->OUI[0] != 0x00 ||
		pDot11RSNIESuite->OUI[1] != 0x50 ||
		pDot11RSNIESuite->OUI[2] != 0xF2)
	{
		retVal = ERROR_INVALID_RSNIE;
		goto lib1x_authRSN_parseIE_error;
	}
#ifdef CONFIG_IEEE80211W	
	if(pDot11RSNIESuite->Type > DOT11_ENC_BIP)
#else
	if(pDot11RSNIESuite->Type > DOT11_ENC_WEP104)
#endif	
	{
		retVal = ERROR_INVALID_MULTICASTCIPHER;
		goto lib1x_authRSN_parseIE_error;
	}

	global->RSNVariable.MulticastCipher = pDot11RSNIESuite->Type;
#ifdef CONFIG_IEEE80211W		
	if (auth->RSNVariable.ieee80211w == MGMT_FRAME_PROTECTION_REQUIRED)
	{
		if (global->RSNVariable.MulticastCipher != DOT11_ENC_CCMP) {
			printf("Invalid WPA group cipher %d\n", global->RSNVariable.MulticastCipher);
			return ERROR_MGMT_FRAME_PROTECTION_VIOLATION;
		}
	}
#endif	
	ulIELength -= sizeof(DOT11_RSN_IE_SUITE);
	pucIE += sizeof(DOT11_RSN_IE_SUITE);

	//----------------------------------------------------------------------------------
        // Pairwise Cipher Suite processing
	//----------------------------------------------------------------------------------

	if(ulIELength < sizeof(u_short) + sizeof(DOT11_RSN_IE_SUITE)) {
		retVal = 0;
		goto lib1x_authRSN_parseIE_success;
	}

	pDot11RSNIECountSuite = (PDOT11_RSN_IE_COUNT_SUITE)pucIE;
	pDot11RSNIESuite = pDot11RSNIECountSuite->dot11RSNIESuite;
	lib1x_Little_N2S((u_char*)&pDot11RSNIECountSuite->SuiteCount, usSuitCount);


	if (    usSuitCount != 1 ||
		pDot11RSNIESuite->OUI[0] != 0x00 ||
		pDot11RSNIESuite->OUI[1] != 0x50 ||
		pDot11RSNIESuite->OUI[2] != 0xF2)
	{
		AUTHDEBUG(" RSN IE Suite[0x%x]\n", pDot11RSNIESuite->Type);
		retVal = ERROR_INVALID_RSNIE;
		goto lib1x_authRSN_parseIE_error;
	}
	if(pDot11RSNIESuite->Type > DOT11_ENC_WEP104)
	{
		retVal = ERROR_INVALID_UNICASTCIPHER;
		goto lib1x_authRSN_parseIE_error;
	}
                        //pDot11RSNConfig->ulNumOfPairwiseSuite = 1;

    global->RSNVariable.UnicastCipher = pDot11RSNIESuite->Type;
#ifdef CONFIG_IEEE80211W						
	if (auth->RSNVariable.ieee80211w == MGMT_FRAME_PROTECTION_REQUIRED)
	{
		if (global->RSNVariable.UnicastCipher == DOT11_ENC_TKIP) {
			printf("Management frame protection cannot use TKIP\n");
			return ERROR_MGMT_FRAME_PROTECTION_VIOLATION;
		}
	}
#endif	
	//pDot11SSNConfig->ulPairwiseSuite[0] = pDot11SSNIESuite->Type;
	ulIELength -= sizeof(pDot11RSNIECountSuite->SuiteCount) + sizeof(DOT11_RSN_IE_SUITE);
	pucIE += sizeof(pDot11RSNIECountSuite->SuiteCount) + sizeof(DOT11_RSN_IE_SUITE);

	//----------------------------------------------------------------------------------
        // Authentication suite
	//----------------------------------------------------------------------------------
	if(ulIELength < sizeof(u_short) + sizeof(DOT11_RSN_IE_SUITE)) {
		retVal = 0;
		goto lib1x_authRSN_parseIE_success;
	}

	pDot11RSNIECountSuite = (PDOT11_RSN_IE_COUNT_SUITE)pucIE;
	pDot11RSNIESuite = pDot11RSNIECountSuite->dot11RSNIESuite;
	lib1x_Little_N2S((u_char*)&pDot11RSNIECountSuite->SuiteCount, usSuitCount);


	if (usSuitCount != 1 ||
		pDot11RSNIESuite->OUI[0] != 0x00 ||
		pDot11RSNIESuite->OUI[1] != 0x50 ||
		pDot11RSNIESuite->OUI[2] != 0xF2 )
	{
		retVal = ERROR_INVALID_RSNIE;
		goto lib1x_authRSN_parseIE_error;
	}

#ifdef CONFIG_IEEE80211W	
	if( pDot11RSNIESuite->Type == DOT11_AuthKeyType_RSN
	  ||pDot11RSNIESuite->Type == DOT11_AuthKeyType_RSNPSK
	  ||pDot11RSNIESuite->Type == DOT11_AuthKeyType_802_1X_SHA256
#ifdef CONFIG_IEEE80211R	
	   || pDot11RSNIESuite->Type == DOT11_AuthKeyType_FT
#endif
	  ||pDot11RSNIESuite->Type == DOT11_AuthKeyType_PSK_SHA256)
	{
		// Only Implement these algorithm?
	}
	else
#else
	if( pDot11RSNIESuite->Type < DOT11_AuthKeyType_RSN
	  ||pDot11RSNIESuite->Type > DOT11_AuthKeyType_RSNPSK)
#endif	  	
	{
		retVal = ERROR_INVALID_AUTHKEYMANAGE;
		goto lib1x_authRSN_parseIE_error;
	}

#ifdef CONFIG_IEEE80211R	
	if (pDot11RSNIESuite->Type == DOT11_AuthKeyType_FT) 	
		global->akm_sm->isFT = 1;
#endif

	//pDot11RSNConfig->ulNumOfAuthenticationSuite = 1;
	global->AuthKeyMethod = pDot11RSNIESuite->Type;
	ulIELength -= sizeof(pDot11RSNIECountSuite->SuiteCount) + sizeof(DOT11_RSN_IE_SUITE);
	pucIE += sizeof(pDot11RSNIECountSuite->SuiteCount) + sizeof(DOT11_RSN_IE_SUITE);

        // RSN Capability
	if (ulIELength < sizeof(DOT11_RSN_CAPABILITY)) {
		global->RSNVariable.NumOfRxTSC = 2;
		retVal = 0;
		goto lib1x_authRSN_parseIE_success;
	}

#ifndef RTL_WPA2
	//----------------------------------------------------------------------------------
        // Capability field
	//----------------------------------------------------------------------------------
	pDot11RSNCapability = (DOT11_RSN_CAPABILITY * )pucIE;
	global->RSNVariable.isSuppSupportPreAuthentication = pDot11RSNCapability->field.PreAuthentication;
	global->RSNVariable.isSuppSupportPairwiseAsDefaultKey = pDot11RSNCapability->field.PairwiseAsDefaultKey;

	switch (pDot11RSNCapability->field.NumOfReplayCounter) {
	case 0:
		global->RSNVariable.NumOfRxTSC = 1;
		break;
	case 1:
		global->RSNVariable.NumOfRxTSC = 2;
		break;
	case 2:
		global->RSNVariable.NumOfRxTSC = 4;
		break;
	case 3:
		global->RSNVariable.NumOfRxTSC = 16;
		break;
	default:
		global->RSNVariable.NumOfRxTSC = 1;
	}
#endif /* RTL_WPA2 */

#ifdef CONFIG_IEEE80211W
	pDot11RSNCapability = (DOT11_RSN_CAPABILITY * )pucIE;
	if (auth->RSNVariable.ieee80211w == MGMT_FRAME_PROTECTION_REQUIRED)
	{
		if (!pDot11RSNCapability->field.MFPC) {
			printf("Management frame protection Required, but client did not enable it\n");
			return ERROR_MGMT_FRAME_PROTECTION_VIOLATION;
		}
	}
	
	if (auth->RSNVariable.ieee80211w == NO_MGMT_FRAME_PROTECTION ||
	    !(pDot11RSNCapability->field.MFPC))
		global->mgmt_frame_prot = 0;
	else
		global->mgmt_frame_prot = 1;
		
	HS2DEBUG("mgmt_frame_prot=%d\n",global->mgmt_frame_prot);

#endif // CONFIG_IEEE80211W
lib1x_authRSN_parseIE_success:

        return retVal;
lib1x_authRSN_parseIE_error:

        global->RSNVariable.RSNEnabled = FALSE;
        return retVal;
}


#ifdef RTL_WPA2
int chk_RSN_Suite(unsigned char suite_type){

    #ifdef CONFIG_IEEE80211W
    
    if( suite_type == DOT11_AuthKeyType_RSN   
        ||suite_type == DOT11_AuthKeyType_RSNPSK      
        ||suite_type == DOT11_AuthKeyType_802_1X_SHA256   
        ||suite_type == DOT11_AuthKeyType_PSK_SHA256)   
    {       
        return 1; /*support*/ 
    }else{
        return 0; /*no support*/ 
    }   
    
    #else
    
    if( suite_type < DOT11_AuthKeyType_RSN ||   suite_type > DOT11_AuthKeyType_RSNPSK )
    {       
        return 0; /*support*/ 
    }else{
        return 1; /*no support*/ 
    }   
    
    #endif

}

//--------------------------------------------------------------------------
// Save Association Request info
//--------------------------------------------------------------------------
int lib1x_authWPA2_parseIE(Dot1x_Authenticator * auth,
				Global_Params * global,
				u_char * pucIE, u_long ulIELength)
{

        int retVal = 0;
	u_short	usVersion;
	u_short	usSuitCount;

        DOT11_WPA2_IE_HEADER * pDot11WPA2IEHeader = NULL;
	DOT11_RSN_IE_SUITE  * pDot11RSNIESuite = NULL;
	DOT11_RSN_IE_COUNT_SUITE * pDot11RSNIECountSuite = NULL;
	DOT11_RSN_CAPABILITY * pDot11RSNCapability = NULL;

	AUTHDEBUG(" OSEN[%d]\n",auth->RSNVariable.bOSEN);
	//wpa2_hexdump("lib1x_authWPA2_parseIE: RSN IE", pucIE, ulIELength);

    if( ulIELength < sizeof(DOT11_WPA2_IE_HEADER) ) {
		retVal = ERROR_INVALID_RSNIE;
		goto lib1x_authWPA2_parseIE_error;
	}
	pDot11WPA2IEHeader = (DOT11_WPA2_IE_HEADER *)pucIE;
	lib1x_Little_N2S((u_char*)&pDot11WPA2IEHeader->Version, usVersion);

#ifdef HS2_SUPPORT
	if(auth->RSNVariable.bOSEN)
	{
		// Check Before, No Check again
		ulIELength -= 6; // ElementID(B1) + LEN(B1) + OI(B3) + TYPE(B1)
		pucIE += 6;
	}
	else
#endif
	{
		//AUTHDEBUG("lib1x_authWPA2_parseIE, path1\n");
		if (usVersion != RSN_VER1)
		{
			retVal = ERROR_UNSUPPORTED_RSNEVERSION;
			goto lib1x_authWPA2_parseIE_error;
		}
		
		if (pDot11WPA2IEHeader->ElementID != WPA2_ELEMENT_ID ||
			pDot11WPA2IEHeader->Length != ulIELength -2 )
		{
			retVal = ERROR_INVALID_RSNIE;
			goto lib1x_authWPA2_parseIE_error;
		}
		ulIELength -= sizeof(DOT11_WPA2_IE_HEADER);
		pucIE += sizeof(DOT11_WPA2_IE_HEADER);
	}
	
	global->RSNVariable.RSNEnabled= TRUE;
#ifdef RTL_WPA2
	global->RSNVariable.PMKCached= FALSE;  // init
#endif

	


	//----------------------------------------------------------------------------------
 	// Multicast Cipher Suite processing
	//----------------------------------------------------------------------------------

	if(ulIELength < sizeof(DOT11_RSN_IE_SUITE)) {
		retVal = 0;
		goto lib1x_authWPA2_parseIE_success;
	}

	pDot11RSNIESuite = (DOT11_RSN_IE_SUITE *)pucIE;
	if (pDot11RSNIESuite->OUI[0] != 0x00 ||
		pDot11RSNIESuite->OUI[1] != 0x0F ||
		pDot11RSNIESuite->OUI[2] != 0xAC)
	{
		AUTHDEBUG("ERROR_INVALID_RSNIE, Multicast Cipher Suite\n");
		retVal = ERROR_INVALID_RSNIE;
		goto lib1x_authWPA2_parseIE_error;
	}
#ifdef CONFIG_IEEE80211W	
	if(pDot11RSNIESuite->Type > DOT11_ENC_NOGA)
#else
	if(pDot11RSNIESuite->Type > DOT11_ENC_WEP104)
#endif	
	{
		retVal = ERROR_INVALID_MULTICASTCIPHER;
		goto lib1x_authWPA2_parseIE_error;
	}

#ifdef HS2_SUPPORT
	if(auth->RSNVariable.bOSEN)
		global->RSNVariable.MulticastCipher = DOT11_ENC_CCMP;	
	else
#endif
	global->RSNVariable.MulticastCipher = pDot11RSNIESuite->Type;
#ifdef CONFIG_IEEE80211W
	if (auth->RSNVariable.ieee80211w == MGMT_FRAME_PROTECTION_REQUIRED)	{		
		if (global->RSNVariable.MulticastCipher != auth->RSNVariable.MulticastCipher) {			
			HS2DEBUG("Invalid WPA group cipher %d\n", global->RSNVariable.MulticastCipher);			
			return ERROR_MGMT_FRAME_PROTECTION_VIOLATION;		
		}	
	}
#endif
	ulIELength -= sizeof(DOT11_RSN_IE_SUITE);
	pucIE += sizeof(DOT11_RSN_IE_SUITE);

	//----------------------------------------------------------------------------------
        // Pairwise Cipher Suite processing
	//----------------------------------------------------------------------------------
	if(ulIELength < sizeof(u_short) + sizeof(DOT11_RSN_IE_SUITE)) {
		retVal = 0;
		goto lib1x_authWPA2_parseIE_success;
	}

	pDot11RSNIECountSuite = (PDOT11_RSN_IE_COUNT_SUITE)pucIE;
	pDot11RSNIESuite = pDot11RSNIECountSuite->dot11RSNIESuite;
	lib1x_Little_N2S((u_char*)&pDot11RSNIECountSuite->SuiteCount, usSuitCount);

	if (    usSuitCount != 1 ||
		pDot11RSNIESuite->OUI[0] != 0x00 ||
		pDot11RSNIESuite->OUI[1] != 0x0F ||
		pDot11RSNIESuite->OUI[2] != 0xAC)
	{
		AUTHDEBUG("RSN IE Suite =[0x %x]\n", pDot11RSNIESuite->Type);
		retVal = ERROR_INVALID_RSNIE;
		goto lib1x_authWPA2_parseIE_error;
	}
	if(pDot11RSNIESuite->Type > DOT11_ENC_WEP104)
	{
		retVal = ERROR_INVALID_UNICASTCIPHER;
		goto lib1x_authWPA2_parseIE_error;
	}
	global->RSNVariable.UnicastCipher = pDot11RSNIESuite->Type;

#ifdef CONFIG_IEEE80211W
	global->RSNVariable.UnicastCipher = pDot11RSNIESuite->Type;							
	if (auth->RSNVariable.ieee80211w == MGMT_FRAME_PROTECTION_REQUIRED)	{		
		if (global->RSNVariable.UnicastCipher == DOT11_ENC_TKIP) {			
			HS2DEBUG("Management frame protection cannot use TKIP\n");			
			return ERROR_MGMT_FRAME_PROTECTION_VIOLATION;		
		}	
	}
#endif  

        global->RSNVariable.UnicastCipher = pDot11RSNIESuite->Type;
	//pDot11SSNConfig->ulPairwiseSuite[0] = pDot11SSNIESuite->Type;
	ulIELength -= sizeof(pDot11RSNIECountSuite->SuiteCount) + sizeof(DOT11_RSN_IE_SUITE);
	pucIE += sizeof(pDot11RSNIECountSuite->SuiteCount) + sizeof(DOT11_RSN_IE_SUITE);
	//----------------------------------------------------------------------------------
        // Authentication suite
	//----------------------------------------------------------------------------------
	if(ulIELength < sizeof(u_short) + sizeof(DOT11_RSN_IE_SUITE)) {
		retVal = 0;
		goto lib1x_authWPA2_parseIE_success;
	}
	pDot11RSNIECountSuite = (PDOT11_RSN_IE_COUNT_SUITE)pucIE;
	pDot11RSNIESuite = pDot11RSNIECountSuite->dot11RSNIESuite;
	lib1x_Little_N2S((u_char*)&pDot11RSNIECountSuite->SuiteCount, usSuitCount);
#ifdef HS2_SUPPORT	
	HS2DEBUG("lib1x_authWPA2_parseIE, bOSEN=%d\n", auth->RSNVariable.bOSEN);
	if(auth->RSNVariable.bOSEN == 1) {
		if (usSuitCount != 1 ||
			pDot11RSNIESuite->OUI[0] != 0x50 ||
			pDot11RSNIESuite->OUI[1] != 0x6F ||
			pDot11RSNIESuite->OUI[2] != 0x9A )
		{
			HS2DEBUG("ERROR_INVALID_RSNIE, OSEN\n");
			retVal = ERROR_INVALID_RSNIE;
			goto lib1x_authWPA2_parseIE_error;
		}	
	}
	else
#endif
	{
	if (usSuitCount != 1 ||
		pDot11RSNIESuite->OUI[0] != 0x00 ||
		pDot11RSNIESuite->OUI[1] != 0x0F ||
		pDot11RSNIESuite->OUI[2] != 0xAC )
	{
		retVal = ERROR_INVALID_RSNIE;
		goto lib1x_authWPA2_parseIE_error;
	}
	}

    #ifdef HS2_SUPPORT	
	if(auth->RSNVariable.bOSEN) {
		if( pDot11RSNIESuite->Type != 1) { // WFA Anonymous Client 802.1X AKM
			retVal = ERROR_INVALID_AUTHKEYMANAGE;
			goto lib1x_authWPA2_parseIE_error;
		}
	}
	else
    #endif
	{

        if(chk_RSN_Suite(pDot11RSNIESuite->Type)==0)
		{
			retVal = ERROR_INVALID_AUTHKEYMANAGE;
			goto lib1x_authWPA2_parseIE_error;
		}
	}


	//pDot11RSNConfig->ulNumOfAuthenticationSuite = 1;
	global->AuthKeyMethod = pDot11RSNIESuite->Type;
	HS2DEBUG("lib1x_authWPA2_parseIE..AuthKeyMethod=%d\n",pDot11RSNIESuite->Type);

	ulIELength -= sizeof(pDot11RSNIECountSuite->SuiteCount) + sizeof(DOT11_RSN_IE_SUITE);
	pucIE += sizeof(pDot11RSNIECountSuite->SuiteCount) + sizeof(DOT11_RSN_IE_SUITE);

    /* RSN Capability*/
	if (ulIELength < sizeof(DOT11_RSN_CAPABILITY)) {
		global->RSNVariable.NumOfRxTSC = 2;
		retVal = 0;
		goto lib1x_authWPA2_parseIE_success;
	}

	/*-------------------------------------------------------------
        PMKID Count field
	--------------------------------------------------------------*/

	
	pDot11RSNCapability = (DOT11_RSN_CAPABILITY * )pucIE;
	global->RSNVariable.isSuppSupportPreAuthentication = pDot11RSNCapability->field.PreAuthentication;

    #if 0   //def RTL_WPA2_PREAUTH  // kenny temp
	//wpa2_hexdump("WPA2 IE Capability", pucIE, 2);
	//global->RSNVariable.isSuppSupportPreAuthentication = (pDot11RSNCapability->charData[0] & 0x01)?TRUE:FALSE;
    #endif

    #ifdef RTL_WPA2
	global->RSNVariable.NumOfRxTSC = 1;
    #else
	global->RSNVariable.isSuppSupportPairwiseAsDefaultKey = pDot11RSNCapability->field.PairwiseAsDefaultKey;
	switch (pDot11RSNCapability->field.NumOfReplayCounter) {
    	case 0:
    		global->RSNVariable.NumOfRxTSC = 1;
    		break;
    	case 1:
    		global->RSNVariable.NumOfRxTSC = 2;
    		break;
    	case 2:
    		global->RSNVariable.NumOfRxTSC = 4;
    		break;
    	case 3:
    		global->RSNVariable.NumOfRxTSC = 16;
    		break;
    	default:
    		global->RSNVariable.NumOfRxTSC = 1;
	}
    #endif

    #ifdef CONFIG_IEEE80211W
	pDot11RSNCapability = (DOT11_RSN_CAPABILITY * )pucIE;
	if (auth->RSNVariable.ieee80211w == MGMT_FRAME_PROTECTION_REQUIRED)
	{
		if (!pDot11RSNCapability->field.MFPC) {
			PMFDEBUG("      CHK!!! myself PMF is Required[2], but STA did not support \n\n");
			return ERROR_MGMT_FRAME_PROTECTION_VIOLATION;
		}
	}
	if (auth->RSNVariable.ieee80211w == NO_MGMT_FRAME_PROTECTION ||
		!(pDot11RSNCapability->field.MFPC))
		global->mgmt_frame_prot = 0;
	else
		global->mgmt_frame_prot = 1;

	PMFDEBUG("PMF enable=[%d]\n",global->mgmt_frame_prot);
	
    #endif // end of CONFIG_IEEE80211W
    
	pucIE += 2;
	ulIELength -= 2;
	
	global->RSNVariable.cached_pmk_node = NULL;
	// PMKID
	if((ulIELength < PMKID_LEN)) {
		retVal = 0;
		goto lib1x_authWPA2_parseIE_success;
	}
    //wpa2_hexdump("PMKID Count", pucIE, 2);



	/*-------------------------------------------------------------
        PMKID Count field
	--------------------------------------------------------------*/
	
	lib1x_Little_N2S((u_char*)pucIE, usSuitCount);
	//printf("PMKID Count = %d\n",usSuitCount);
	
	pucIE += 2;
	ulIELength -= 2;
	if ( usSuitCount > 0) {
		struct _WPA2_PMKSA_Node* pmksa_node;
		int i;
		for (i=0; i < usSuitCount; i++) {
			ulIELength -= PMKID_LEN;
			pmksa_node = find_pmksa(pucIE+(PMKID_LEN*i));

			if ( pmksa_node != NULL && pmksa_node->pmksa.SessionTimeout == 0) {
				wpa2_hexdump("\nCached PMKID: ", pmksa_node->pmksa.pmkid, PMKID_LEN);
				global->RSNVariable.PMKCached = TRUE;
				global->RSNVariable.cached_pmk_node = pmksa_node;
				break;
			} else {
				//printf("PMKID not cached!!\n");
			}
		}

	}
#ifdef CONFIG_IEEE80211W

    pucIE += PMKID_LEN*usSuitCount;
	//HS2DEBUG("usSuitCount=%d, ulIELength=%d\n",usSuitCount,ulIELength);


	//----------------------------------------------------------------------------------
    /*Group Management Cipher field (IGTK)*/ 
	//----------------------------------------------------------------------------------
	if((ulIELength < sizeof(DOT11_RSN_IE_SUITE))) {
		retVal = 0;
		goto lib1x_authWPA2_parseIE_success;
	}

    #ifdef HS2_SUPPORT	
	if(auth->RSNVariable.bOSEN) 		
		global->RSNVariable.mgmt_group_cipher = 0; // Group Management Cipher Suite may be set to any value since DGAF is disabled for OSEN
	else
    #endif
	{
		pDot11RSNIESuite = (DOT11_RSN_IE_SUITE*)pucIE;

		if (pDot11RSNIESuite->OUI[0] != 0x00 ||
			pDot11RSNIESuite->OUI[1] != 0x0F ||
			pDot11RSNIESuite->OUI[2] != 0xAC)
		{
			HS2DEBUG("RSNIE Suite OUI = %02x:%02x:%02x\n", pDot11RSNIESuite->OUI[0],pDot11RSNIESuite->OUI[1],pDot11RSNIESuite->OUI[2]);
			retVal = ERROR_INVALID_RSNIE;
			goto lib1x_authWPA2_parseIE_error;
		}
		if(pDot11RSNIESuite->Type != DOT11_ENC_BIP)
		{
			retVal = ERROR_MGMT_FRAME_PROTECTION_VIOLATION;
			goto lib1x_authWPA2_parseIE_error;
		}

		global->RSNVariable.mgmt_group_cipher = pDot11RSNIESuite->Type;	
	}
#endif // CONFIG_IEEE80211W

lib1x_authWPA2_parseIE_success:

        return retVal;
lib1x_authWPA2_parseIE_error:

        global->RSNVariable.RSNEnabled = FALSE;
        return retVal;
}
#endif /* RTL_WPA2 */

//----------------------------------------------------------------------------------------
//  Compare RSNVariable of STA with security policy to see if the it is allowed to associate
//  Return 0 : match successfully or RSN Disabled,
//	       withch means, association request is allowed
//----------------------------------------------------------------------------------------
#ifdef RTL_WPA2
int lib1x_authRSN_match(Dot1x_Authenticator * auth, Global_Params * global, BOOLEAN bWPA2)
#else
int lib1x_authRSN_match(Dot1x_Authenticator * auth, Global_Params * global)
#endif
{

        int retVal = 0;
        u_long ulIndex = 0, uCipherAlgo = 0, uAuthAlgo = 0;
        DOT11_AlgoSuit * pUnicastCipherAlgo = NULL;
        DOT11_AlgoSuit * pMulticastCipherAlgo = NULL;
        DOT11_AlgoSuit * pAuthenticationAlgo = NULL;
        BOOLEAN bCipherAlgoEnabled = FALSE, bAuthAlgoEnabled = FALSE;


        if(!auth->RSNVariable.RSNEnabled)
	//---- Association Request is allowed ----
                return retVal;

	//----------------------------------------------------------------------------------
        // Pairwise Cipher Suite processing
	//----------------------------------------------------------------------------------
#ifdef RTL_WPA2
	if (bWPA2)
                pUnicastCipherAlgo = &auth->RSNVariable.WPA2UniCastCipherSuit;
	else
#endif
        pUnicastCipherAlgo = &auth->RSNVariable.UniCastCipherSuit;

        for (ulIndex = 0; ulIndex < pUnicastCipherAlgo->NumOfAlgo; ulIndex++) {
                uCipherAlgo = pUnicastCipherAlgo->AlgoTable[ulIndex].AlgoId;
                bCipherAlgoEnabled = pUnicastCipherAlgo->AlgoTable[ulIndex].Enabled;

                if(global->RSNVariable.UnicastCipher == uCipherAlgo) {
                        break;
                }
    	}
        if (!bCipherAlgoEnabled) {
		retVal = ERROR_INVALID_UNICASTCIPHER;
		goto lib1x_authRSN_match_end;
	}

	//----------------------------------------------------------------------------------
        // Multicast Cipher Suite processing
	//----------------------------------------------------------------------------------
        pMulticastCipherAlgo = &auth->RSNVariable.MulticastCipherSuit;
    	for (ulIndex = 0; ulIndex < pMulticastCipherAlgo->NumOfAlgo; ulIndex++) {
		uCipherAlgo = pMulticastCipherAlgo->AlgoTable[ulIndex].AlgoId;
		bCipherAlgoEnabled = pMulticastCipherAlgo->AlgoTable[ulIndex].Enabled;

		if(global->RSNVariable.MulticastCipher == uCipherAlgo) {
			break;
		}
	}
	if (!bCipherAlgoEnabled) {
		// kenny
		// retVal = ERROR_INVALID_AUTHKEYMANAGE;
		retVal = ERROR_INVALID_MULTICASTCIPHER;
		goto lib1x_authRSN_match_end;
	}

 	//----------------------------------------------------------------------------------
        // Authentication suite
	//----------------------------------------------------------------------------------
        pAuthenticationAlgo = &auth->RSNVariable.AuthenticationSuit;
        for (ulIndex = 0; ulIndex < pAuthenticationAlgo->NumOfAlgo; ulIndex++) {
                uAuthAlgo = pAuthenticationAlgo->AlgoTable[ulIndex].AlgoId;
                bAuthAlgoEnabled = pAuthenticationAlgo->AlgoTable[ulIndex].Enabled;

		if(global->AuthKeyMethod == uAuthAlgo) {
			break;
		}
	}

	if (!bAuthAlgoEnabled) {
            retVal = ERROR_INVALID_AUTHKEYMANAGE;
            goto lib1x_authRSN_match_end;
        }
lib1x_authRSN_match_end:
        return retVal;
}
