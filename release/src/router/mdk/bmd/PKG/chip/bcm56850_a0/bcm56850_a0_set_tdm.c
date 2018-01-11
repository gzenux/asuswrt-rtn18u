#include <bmd_config.h>
#if CDK_CONFIG_INCLUDE_BCM56850_A0 == 1

/*
 * $Id: bcm56850_a0_set_tdm.c,v 1.1 Broadcom SDK $
 * 
 * $Copyright: Copyright 2013 Broadcom Corporation.
 * This program is the proprietary software of Broadcom Corporation
 * and/or its licensors, and may only be used, duplicated, modified
 * or distributed pursuant to the terms and conditions of a separate,
 * written license agreement executed between you and Broadcom
 * (an "Authorized License").  Except as set forth in an Authorized
 * License, Broadcom grants no license (express or implied), right
 * to use, or waiver of any kind with respect to the Software, and
 * Broadcom expressly reserves all rights in and to the Software
 * and all intellectual property rights therein.  IF YOU HAVE
 * NO AUTHORIZED LICENSE, THEN YOU HAVE NO RIGHT TO USE THIS SOFTWARE
 * IN ANY WAY, AND SHOULD IMMEDIATELY NOTIFY BROADCOM AND DISCONTINUE
 * ALL USE OF THE SOFTWARE.  
 *  
 * Except as expressly set forth in the Authorized License,
 *  
 * 1.     This program, including its structure, sequence and organization,
 * constitutes the valuable trade secrets of Broadcom, and you shall use
 * all reasonable efforts to protect the confidentiality thereof,
 * and to use this information only in connection with your use of
 * Broadcom integrated circuit products.
 *  
 * 2.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, THE SOFTWARE IS
 * PROVIDED "AS IS" AND WITH ALL FAULTS AND BROADCOM MAKES NO PROMISES,
 * REPRESENTATIONS OR WARRANTIES, EITHER EXPRESS, IMPLIED, STATUTORY,
 * OR OTHERWISE, WITH RESPECT TO THE SOFTWARE.  BROADCOM SPECIFICALLY
 * DISCLAIMS ANY AND ALL IMPLIED WARRANTIES OF TITLE, MERCHANTABILITY,
 * NONINFRINGEMENT, FITNESS FOR A PARTICULAR PURPOSE, LACK OF VIRUSES,
 * ACCURACY OR COMPLETENESS, QUIET ENJOYMENT, QUIET POSSESSION OR
 * CORRESPONDENCE TO DESCRIPTION. YOU ASSUME THE ENTIRE RISK ARISING
 * OUT OF USE OR PERFORMANCE OF THE SOFTWARE.
 * 
 * 3.     TO THE MAXIMUM EXTENT PERMITTED BY LAW, IN NO EVENT SHALL
 * BROADCOM OR ITS LICENSORS BE LIABLE FOR (i) CONSEQUENTIAL,
 * INCIDENTAL, SPECIAL, INDIRECT, OR EXEMPLARY DAMAGES WHATSOEVER
 * ARISING OUT OF OR IN ANY WAY RELATING TO YOUR USE OF OR INABILITY
 * TO USE THE SOFTWARE EVEN IF BROADCOM HAS BEEN ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGES; OR (ii) ANY AMOUNT IN EXCESS OF
 * THE AMOUNT ACTUALLY PAID FOR THE SOFTWARE ITSELF OR USD 1.00,
 * WHICHEVER IS GREATER. THESE LIMITATIONS SHALL APPLY NOTWITHSTANDING
 * ANY FAILURE OF ESSENTIAL PURPOSE OF ANY LIMITED REMEDY.$
 *
 * TDM algorithms imported from HW team.
 */

#include <bmd/bmd.h>

#include <cdk/cdk_debug.h>
#include <cdk/cdk_string.h>

#include "bcm56850_a0_internal.h"

#define TDM_VERBOSE(a) CDK_VVERB(a)
#define TDM_ERROR3(a,b,c,d) CDK_ERR((a, b, c, d))
#define TDM_ERROR2(a,b,c) CDK_ERR((a, b, c))
#define TDM_ERROR1(a,b) CDK_ERR((a, b))
#define TDM_ERROR0(a) CDK_ERR((a))
#define TDM_WARN3(a,b,c,d) CDK_WARN((a, b, c, d))
#define TDM_WARN2(a,b,c) CDK_WARN((a, b, c))
#define TDM_WARN1(a,b) CDK_WARN((a, b))
#define TDM_WARN0(a) CDK_WARN((a))
#define TDM_VERBOSE8(a,b,c,d,e,f,g,h,i) /* NOP */
#define TDM_VERBOSE7(a,b,c,d,e,f,g,h) /* NOP */
#define TDM_VERBOSE6(a,b,c,d,e,f,g) /* NOP */
#define TDM_VERBOSE5(a,b,c,d,e,f) /* NOP */
#define TDM_VERBOSE4(a,b,c,d,e) TDM_VERBOSE((a, b, c, d, e))
#define TDM_VERBOSE3(a,b,c,d) TDM_VERBOSE((a, b, c, d))
#define TDM_VERBOSE2(a,b,c) TDM_VERBOSE((a, b, c))
#define TDM_VERBOSE1(a,b) TDM_VERBOSE((a, b))
#define TDM_VERBOSE0(a) TDM_VERBOSE((a))
#define TDM_ALLOC(_nm,_t,_sz,_id) _t _nm[_sz]
#define TDM_FREE(_nm)
#define TDM_MEMCPY(_s1,_s2,_sz) CDK_MEMCPY(_s1,_s2,_sz)


/* number of physical ports plus CPU and loopback */
#define NUM_EXT_PORTS 130
/* number of TSCs in chip */
#define NUM_WC 32

/* pgw/mmu table oversubscription token */
#define OVS_TOKEN (NUM_EXT_PORTS+1)
/* mmu table idle token */
#define IDL_TOKEN (NUM_EXT_PORTS+2)
/* tsc transcription management port token */
#define MGM_TOKEN (NUM_EXT_PORTS+3)
/* port scanning microsub token */
#define U1G_TOKEN (NUM_EXT_PORTS+4)

#define TOKEN_CHECK(a)  			\
			if (a!=NUM_EXT_PORTS && \
			a!=OVS_TOKEN && 	\
			a!=IDL_TOKEN && 	\
			a!=MGM_TOKEN && 	\
			a!=U1G_TOKEN && 	\
			a!=0 &&			\
			a!=129) 		\

/* mmu table accessory token */
#define ACC_TOKEN (NUM_EXT_PORTS+5)
#define CMIC(a) {				\
			mmu_tdm_tbl[a]=0; 	\
			TDM_VERBOSE0("CMIC\n"); \
			break;			\
		}
#define LPBK(a) {					\
			mmu_tdm_tbl[a]=129; 		\
			TDM_VERBOSE0("LOOPBACK\n"); 	\
			break;				\
		}
#define ANCL(a) {					\
			mmu_tdm_tbl[a]=IDL_TOKEN; 	\
			TDM_VERBOSE0("ANCILLARY\n");	\
			break;				\
		}
#define MM13(a) {						\
			mmu_tdm_tbl[a]=13; 			\
			TDM_VERBOSE0("management phyport 13\n");\
			break;					\
		}
#define MM14(a) {						\
			mmu_tdm_tbl[a]=14; 			\
			TDM_VERBOSE0("management phyport 14\n");\
			break;					\
		}
#define MM15(a) {						\
			mmu_tdm_tbl[a]=15; 			\
			TDM_VERBOSE0("management phyport 15\n");\
			break;					\
		}
#define MM16(a) {						\
			mmu_tdm_tbl[a]=16; 			\
			TDM_VERBOSE0("management phyport 16\n");\
			break;					\
		}

#define IARB_MAIN_TDM__TDM_SLOT_PGW_0         0
#define IARB_MAIN_TDM__TDM_SLOT_PGW_1         1
#define IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT     2
#define IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK   3
#define IARB_MAIN_TDM__TDM_SLOT_QGP_PORT      4
#define IARB_MAIN_TDM__TDM_SLOT_RESERVED      6
#define IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT  7

#define TRUE 1
#define PASS 1
#define FALSE 0
#define FAIL 0

enum port_speed {SPEED_0=0, SPEED_10M=10, SPEED_20M=20, SPEED_25M=25, SPEED_33M=33, SPEED_40M=40, SPEED_50M=50, SPEED_100M=100, SPEED_100M_FX=101, SPEED_120M=120,SPEED_400M=400, SPEED_1G=1000, SPEED_1G_FX=1001, SPEED_1p2G=1200, SPEED_2G=2000, SPEED_2p5G=2500, SPEED_4G=4000, SPEED_5G=5000, SPEED_7p5G=7500, SPEED_10G=10000, SPEED_10G_DUAL=10001, SPEED_10G_XAUI=10002, SPEED_12G=12000, SPEED_12p5G=12500, SPEED_13G=13000, SPEED_15G=15000, SPEED_16G=16000, SPEED_20G=20000, SPEED_21G=21000, SPEED_21G_DUAL=21010, SPEED_24G=24000, SPEED_25G=25000, SPEED_30G=30000, SPEED_40G=40000, SPEED_42G=40005, SPEED_50G=50000,SPEED_75G=75000, SPEED_82G=82000, SPEED_100G=100000, SPEED_120G=120000, SPEED_126G=126000};


/**
@name: TSC_port_transcription
@param: int[][], enum

physical port transcriber for tsc subports into physical port numbers

	40G 	- xxxx
      	20G 	- xx
	      	    xx
      	10G	- x
		   x
		    x
		     x
     	1X0G 	- xxxx_xxxx_xxxx
**/
static void TSC_port_transcription(int wc_array[NUM_WC][4], int speed[NUM_EXT_PORTS], int port_state_array[128]) 
{
  int i;
  /*char tmp_str[16];*/
  /*sprintf (cmd_str, "soc setmem -index %x %s {", index->d, addr);*/
  for (i = 1; i < NUM_EXT_PORTS-1; i+=4) 
  {
	if (((i-1)/4==3) && wc_array[(i-1)/4][0]==MGM_TOKEN)
	{
		if (speed[i] == speed[i+1])
		{
/* 			wc_array[(i-1)/4][0] = MGM_TOKEN;*/
			wc_array[(i-1)/4][1] = MGM_TOKEN;
			wc_array[(i-1)/4][2] = MGM_TOKEN;
			wc_array[(i-1)/4][3] = MGM_TOKEN;
		}
		else
		{
/* 			wc_array[(i-1)/4][0] = MGM_TOKEN;*/
			wc_array[(i-1)/4][1] = NUM_EXT_PORTS;
			wc_array[(i-1)/4][2] = NUM_EXT_PORTS;
			wc_array[(i-1)/4][3] = NUM_EXT_PORTS;
		}
	}
	else
	{
		if (speed[i] == SPEED_0) 
		{
			wc_array[(i-1)/4][0] = NUM_EXT_PORTS;
			wc_array[(i-1)/4][1] = NUM_EXT_PORTS;
			wc_array[(i-1)/4][2] = NUM_EXT_PORTS;
			wc_array[(i-1)/4][3] = NUM_EXT_PORTS;
		} 
		else if (speed[i] < SPEED_10G) 
		{
			wc_array[(i-1)/4][0] = i;
			wc_array[(i-1)/4][1] = i+1;
			wc_array[(i-1)/4][2] = i+2;
			wc_array[(i-1)/4][3] = i+3;
		} 
		else if (speed[i] <= SPEED_21G_DUAL) 
		{
			if (speed[i]==speed[i+1] && speed[i]==speed[i+2]) 
			{ 				/*quad mode*/
				wc_array[(i-1)/4][0] = i;
				wc_array[(i-1)/4][1] = i+1;
				wc_array[(i-1)/4][2] = i+2;
				wc_array[(i-1)/4][3] = i+3;
			} 
			else if (speed[i]==speed[i+1] && speed[i]!=speed[i+2]) 
			{ 				/*tri mode xxx_*/
				wc_array[(i-1)/4][0] = i;
				wc_array[(i-1)/4][1] = i+2;
				wc_array[(i-1)/4][2] = i+1;
				wc_array[(i-1)/4][3] = i+2;
			} 
/* 			else if (speed[i]==speed[i+1] && speed[i]==speed[i+3]) */
/* 			{ */				/* single mode */
/* 				wc_array[(i-1)/4][0] = i; */
/* 				wc_array[(i-1)/4][1] = i; */
/* 				wc_array[(i-1)/4][2] = i; */
/* 				wc_array[(i-1)/4][3] = i; */
/* 			}							*/
			else if (speed[i]!=speed[i+1] && speed[i]==speed[i+2]) 
			{				/*dual mode*/
				wc_array[(i-1)/4][0] = i;
				wc_array[(i-1)/4][1] = i+2;
				wc_array[(i-1)/4][2] = i;
				wc_array[(i-1)/4][3] = i+2;
			}
			else if (speed[i]!=speed[i+1] && speed[i+1]==speed[i+2] && speed[i+2]==speed[i+3])
			{				/*XFI mode*/
				wc_array[(i-1)/4][0] = i;
				wc_array[(i-1)/4][1] = NUM_EXT_PORTS;
				wc_array[(i-1)/4][2] = NUM_EXT_PORTS;
				wc_array[(i-1)/4][3] = NUM_EXT_PORTS;
			}
			else if (speed[i]!=speed[i+2] && speed[i+2]==speed[i+3])
			{				/*tri mode x_xx*/
				wc_array[(i-1)/4][0] = i;
				wc_array[(i-1)/4][1] = i+2;
				wc_array[(i-1)/4][2] = i;
				wc_array[(i-1)/4][3] = i+3;
			}
		}
		else if (speed[i] <= SPEED_42G)
		{
			wc_array[(i-1)/4][0] = i;
			wc_array[(i-1)/4][1] = i;
			wc_array[(i-1)/4][2] = i;
			wc_array[(i-1)/4][3] = i;
		}
		else 
		{
			/*true 100G port*/
			if (speed[i] <= SPEED_100G && port_state_array[i+10] != 3)
			{
				wc_array[(i-1)/4][0] = i;
				wc_array[(i-1)/4][1] = i;
				wc_array[(i-1)/4][2] = i;
				wc_array[(i-1)/4][3] = i;
				wc_array[(i+3)/4][0] = i;
				wc_array[(i+3)/4][1] = i;
				wc_array[(i+3)/4][2] = i;
				wc_array[(i+3)/4][3] = i;
				wc_array[(i+7)/4][0] = i;
				wc_array[(i+7)/4][1] = i;
				wc_array[(i+7)/4][2] = NUM_EXT_PORTS;
				wc_array[(i+7)/4][3] = NUM_EXT_PORTS;
			}
			/*120G and stretched 100G port*/
			else
			{
				wc_array[(i-1)/4][0] = i;	
				wc_array[(i-1)/4][1] = i;
				wc_array[(i-1)/4][2] = i;
				wc_array[(i-1)/4][3] = i;
				wc_array[(i+3)/4][0] = i;
				wc_array[(i+3)/4][1] = i;
				wc_array[(i+3)/4][2] = i;
				wc_array[(i+3)/4][3] = i;
				wc_array[(i+7)/4][0] = i;
				wc_array[(i+7)/4][1] = i;
				wc_array[(i+7)/4][2] = i;
				wc_array[(i+7)/4][3] = i;	
			}
			i += 8;
		}
	}
  }
}


/**
@name: print_port
@param: int[NUM_WC][4]

prints summary of all warp cores and their associated subports
 **/
static void print_port(int wc_array[NUM_WC][4]) 
{
	int i,j;
  	for(i=0; i<NUM_WC; i++)
	{
      		for (j=0; j<4; j++)
		{
         		TDM_VERBOSE3("TDM: Warpcore #%0d, subport #%0d, contains physical port #%0d\n", i, j, wc_array[i][j]);
/* 	 		printf("%0d,%0d,%0d\n",i,j,wc_array[i][j]);*/
      		}
   	}
}


/**
@name: parse_mmu_tdm_tbl
@param: 

converts accessory tokens and prints debug form summary of pipe mmu table
 **/
/* void parse_mmu_tdm_tbl(int bw, int mmu_tdm_tbl[256], int mmu_tdm_ovs_1[16], int mmu_tdm_ovs_2[16], int mmu_tdm_ovs_3[16], int mmu_tdm_ovs_4[16], const char* name) */
static void parse_mmu_tdm_tbl(int bw, int mgmt_bw, int mmu_tdm_tbl[256], int mmu_tdm_ovs_1[16], int mmu_tdm_ovs_2[16], int mmu_tdm_ovs_3[16], int mmu_tdm_ovs_4[16], int pipe)
{
   int j, k=256, m=0;
   const char *name;
   int oversub=FALSE;
   
   name = (pipe==0) ? "X-PIPE" : "Y-PIPE";
   
   for (j=0; j<16; j++) if (mmu_tdm_ovs_1[j]!=NUM_EXT_PORTS || mmu_tdm_ovs_2[j]!=NUM_EXT_PORTS || mmu_tdm_ovs_3[j]!=NUM_EXT_PORTS || mmu_tdm_ovs_4[j]!=NUM_EXT_PORTS) oversub=TRUE;
   
      for (j=0; j<k; j++) {
	 if (mmu_tdm_tbl[j]!=ACC_TOKEN) {TDM_VERBOSE3("TDM: PIPE: %s, MMU TDM TABLE, element #%0d, contains physical port #%0d\n", name, j, mmu_tdm_tbl[j]);}
	 else 
	 {
		TDM_VERBOSE2("TDM: PIPE: %s, MMU TDM TABLE, element #%0d, CONTAINS ACCESSORY TOKEN - elaborated as ", name, j);
		/* hierarchically determine how to elaborate the accessory token */
		m++;
		if (bw==960)
		{
			if (oversub==FALSE)
			{
				if (pipe==0)
				{
					if (mgmt_bw==0)
					{
						switch (m)
						{
							case 1:
							case 3:
							case 5:
							case 7:
								CMIC(j)
							case 2:
							case 4:
							case 6:
							case 8:
								ANCL(j)
						}
					}
					else if (mgmt_bw==4)
					{
						switch (m)
						{
							case 1:
								MM13(j)
							case 3:
								MM14(j)
							case 5:
								MM15(j)
							case 7:
								MM16(j)
							case 2:
							case 6:
								ANCL(j)
							case 4:
							case 8:
								CMIC(j)
						}
					}
					else if (mgmt_bw==1)
					{
						switch (m)
						{
							case 2:
							case 4:
							case 6:
							case 8:
								MM13(j)
							case 1:
							case 3:
							case 5:
							case 7:
								ANCL(j)
						}
					}
				}
				else if (pipe==1)
				{
					switch (m)
					{
						case 1:
						case 3:
						case 5:
						case 7:
							LPBK(j)
						case 2:
						case 4:
						case 6:
						case 8:
							ANCL(j)
					}
				}
			}
			else if (oversub==TRUE)
			{
				if (pipe==0)
				{
					if (mgmt_bw==0)
					{
						switch (m)
						{
							case 1:
							case 3:
							case 6:
								CMIC(j)
							case 2:
							case 4:
							case 5:
							case 7:
							case 8:
								ANCL(j)
						}
					}
					else if (mgmt_bw==4)
					{
						switch (m)
						{
							case 1: MM13(j)
							case 3: MM14(j)
							case 5: MM15(j)
							case 7: MM16(j)
							case 2: 
							case 4:
							case 6:
								ANCL(j)
							case 8: CMIC(j)
						}
					}
					else if (mgmt_bw==1)
					{
						TDM_VERBOSE0("UNSUPPORTED\n");
					}
				}
				else if (pipe==1)
				{
					switch (m)
					{
						case 1:
						case 3:
						case 6:
							LPBK(j)
						case 2:
						case 4:
						case 5:
						case 7:
						case 8:
							ANCL(j)
					}
				}
			}
		}
		else if (bw==720)
		{
			if (pipe==0)
			{
				if (mgmt_bw==0)
				{
					switch (m)
					{
						case 1:
						case 3:
						case 5:
						case 7:
						case 9:
							CMIC(j)
						case 2:
						case 4:
						case 6:
						case 8:
						case 10:
							ANCL(j)
					}
				}
				else if (mgmt_bw==4)
				{
					switch (m)
					{
						case 1: MM13(j)
						case 3: MM14(j) 
						case 6: MM15(j)
						case 8: MM16(j)
						case 2:
						case 5:
						case 9:
							ANCL(j)
						case 4:
						case 7:
						case 10: CMIC(j)
					}
				}
				else if (mgmt_bw==1)
				{
					switch (m)
					{
						case 2:
						case 4:
						case 7:
						case 9:
							MM13(j)
						case 1:
						case 3:
						case 5:
						case 6:
						case 8:
							ANCL(j)
						case 10: CMIC(j)
					}
				}
			}
			else if (pipe==1)
			{
				switch (m)
				{
					case 1:
					case 3:
					case 5:
					case 7:
					case 9:
						LPBK(j)
					case 2:
					case 4:
					case 6:
					case 8:
					case 10:
						ANCL(j)
				}
			}
		}
		else if (bw==640)
		{
			if (oversub==FALSE)
			{
				if (pipe==0)
				{
					if (mgmt_bw==0)
					{
						switch (m)
						{
							case 1:
							case 3:
							case 5:
							case 7:
								CMIC(j)
							case 2:
							case 4:
							case 6:
							case 8:
								ANCL(j)
						}
					}
					else if (mgmt_bw==4)
					{
						switch (m)
						{
							case 1: MM13(j)
							case 3: MM14(j)
							case 5: MM15(j)
							case 7: MM16(j)
							case 2:
							case 6:
								ANCL(j)
							case 4:
							case 8:
								CMIC(j)
						}
					}
					else if (mgmt_bw==1)
					{
						switch (m)
						{
							case 2:
							case 4:
							case 6:
							case 8:
								MM13(j)
							case 1:
							case 3:
							case 5:
							case 7:
								ANCL(j)
						}
					}
				}
				else if (pipe==1)
				{
					switch (m)
					{
						case 1:
						case 3:
						case 5:
						case 7:
							LPBK(j)
						case 2:
						case 4:
						case 6:
						case 8:
							ANCL(j)
					}
				}
			}
			else if (oversub==TRUE)
			{
				if (pipe==0)
				{
					if (mgmt_bw==0)
					{
						switch (m)
						{
							case 1:
							case 3:
							case 6:
								CMIC(j)
							case 2:
							case 4:
							case 5:
							case 7:
							case 8:
								ANCL(j)
						}
					}
					else if (mgmt_bw==4)
					{
						switch (m)
						{
							case 1: MM13(j)
							case 3: MM14(j)
							case 5: MM15(j)
							case 7: MM16(j)
							case 2:
							case 4:
							case 6:
								ANCL(j)
							case 8: CMIC(j)
						}
					}
					else if (mgmt_bw==1)
					{
						TDM_VERBOSE0("UNSUPPORTED\n");
					}
				}
				else if (pipe==1)
				{
					switch (m)
					{
						case 1:
						case 3:
						case 6:
							LPBK(j)
						case 2:
						case 4:
						case 5:
						case 7:
						case 8:
							ANCL(j)
					}
				}
			}
		}
		else if (bw==480)
		{
			if (pipe==0)
			{
				if (mgmt_bw==0)
				{
					switch (m)
					{
						case 1:
						case 3:
						case 5:
						case 7:
						case 9:
							CMIC(j)
						case 2:
						case 4:
						case 6:
						case 8:
						case 10:
							ANCL(j)
					}
				}
				else if (mgmt_bw==4)
				{
					switch (m)
					{
						case 1: MM13(j)
						case 3: MM14(j)
						case 6: MM15(j)
						case 8: MM16(j)
						case 2:
						case 5:
						case 9:
							ANCL(j)
						case 4:
						case 7:
						case 10:
							CMIC(j)
					}
				}
				else if (mgmt_bw==1)
				{
					switch (m)
					{
						case 2:
						case 4:
						case 7:
						case 9:
							MM13(j)
						case 1:
						case 3:
						case 5:
						case 6:
						case 8:
							ANCL(j)
						case 10: CMIC(j)
					}
				}
			}
			else if (pipe==1)
			{
				switch (m)
				{
					case 1:
					case 3:
					case 5:
					case 7:
					case 9:
						LPBK(j)
					case 2:
					case 4:
					case 6:
					case 8:
					case 10:
						ANCL(j)
				}
			}
		}
		else
		{
			TDM_VERBOSE0("INVALID PARAMETERS\n");
		}
	 }
      }
	for (j=0; j<16; j++)
	{
		TDM_VERBOSE3("TDM: PIPE: %s, MMU OVS BUCKET 1, element #%0d, contains physical port #%0d\n", name, j, mmu_tdm_ovs_1[j]);
	}
	for (j=0; j<16; j++)
	{
		TDM_VERBOSE3("TDM: PIPE: %s, MMU OVS BUCKET 2, element #%0d, contains physical port #%0d\n", name, j, mmu_tdm_ovs_2[j]);
	}
	for (j=0; j<16; j++)
	{
		TDM_VERBOSE3("TDM: PIPE: %s, MMU OVS BUCKET 3, element #%0d, contains physical port #%0d\n", name, j, mmu_tdm_ovs_3[j]);
	}
	for (j=0; j<16; j++)
	{
		TDM_VERBOSE3("TDM: PIPE: %s, MMU OVS BUCKET 4, element #%0d, contains physical port #%0d\n", name, j, mmu_tdm_ovs_4[j]);
	}
}


/**
@name: print_tdm_tbl
@param: int[32], const char*

prints debug form summary of quadrant's table
**/
static void print_tdm_tbl(int pgw_tdm_tbl[32], const char* name)
{
	int j;
      	for (j = 0; j < 32; j++)
	{
		switch (pgw_tdm_tbl[j])
		{
			case 130:
				TDM_VERBOSE2("TDM: PIPE: %s, TDM Calendar, element #%0d, contains an invalid or disabled port\n", name, j);
				break;
			case 131:
				TDM_VERBOSE2("TDM: PIPE: %s, TDM Calendar, element #%0d, contains an oversubscription token\n", name, j);
				break;
			default:
				TDM_VERBOSE3("TDM: PIPE: %s, TDM Calendar, element #%0d, contains physical port #%0d\n", name, j, pgw_tdm_tbl[j]);
				break;
		}
      	}
}


/**
@name: print_tbl_summary
@param: int[32], int[32], int[32], int[32], int[32], int[32], int[32], int[32], int

prints short form final summary of all tables generated
**/
static void print_tbl_summary(int x0[32], int x1[32], int y0[32], int y1[32], int ox0[32], int ox1[32], int oy0[32], int oy1[32], int sx0[32], int sx1[32], int sy0[32], int sy1[32], int bw)
{
	int t;
	TDM_VERBOSE1("TDM: core bandwidth is %0d\n", bw);
	TDM_VERBOSE0("TDM: X0, TDM Calendar\n");
	for (t = 0; t < 32; t++)
	{
		switch (x0[t])
		{
			case 130:
				TDM_VERBOSE0(" x");
				break;
			case 131:
				TDM_VERBOSE0(" O");
				break;
			default:
				TDM_VERBOSE1(" %0d", x0[t]);
				break;
		}
	}
	TDM_VERBOSE0("\nTDM: X0, OVS Calendar\n");
	for (t = 0; t < 32; t++)
	{
		switch (ox0[t])
		{
			case 130:
				TDM_VERBOSE0(" x");
				break;
			default:
				TDM_VERBOSE1(" %0d", ox0[t]);
				break;
		}
	}
	TDM_VERBOSE0("\nTDM: X0, OVS Spacing Info\n");
	for (t = 0; t < 32; t++)
	{
		switch (sx0[t])
		{
			case 130:
				TDM_VERBOSE0(" x");
				break;
			default:
				TDM_VERBOSE1(" %0d", sx0[t]);
				break;
		}
	}
	TDM_VERBOSE0("\nTDM: X1, TDM Calendar\n");
	for (t = 0; t < 32; t++)
	{
		switch (x1[t])
		{
			case 130:
				TDM_VERBOSE0(" x");
				break;
			case 131:
				TDM_VERBOSE0(" O");
				break;
			default:
				TDM_VERBOSE1(" %0d", x1[t]);
				break;
		}
	}
	TDM_VERBOSE0("\nTDM: X1, OVS Calendar\n");
	for (t = 0; t < 32; t++)
	{
		switch (ox1[t])
		{
			case 130:
				TDM_VERBOSE0(" x");
				break;
			default:
				TDM_VERBOSE1(" %0d", ox1[t]);
				break;
		}
	}
	TDM_VERBOSE0("\nTDM: X1, OVS Spacing Info\n");
	for (t = 0; t < 32; t++)
	{
		switch (sx1[t])
		{
			case 130:
				TDM_VERBOSE0(" x");
				break;
			default:
				TDM_VERBOSE1(" %0d", sx1[t]);
				break;
		}
	}
	TDM_VERBOSE0("\nTDM: Y0, TDM Calendar\n");
	for (t = 0; t < 32; t++)
	{
		switch (y0[t])
		{
			case 130:
				TDM_VERBOSE0(" x");
				break;
			case 131:
				TDM_VERBOSE0(" O");
				break;
			default:
				TDM_VERBOSE1(" %0d", y0[t]);
				break;
		}
	}
	TDM_VERBOSE0("\nTDM: Y0, OVS Calendar\n");
	for (t = 0; t < 32; t++)
	{
		switch (oy0[t])
		{
			case 130:
				TDM_VERBOSE0(" x");
				break;
			default:
				TDM_VERBOSE1(" %0d", oy0[t]);
				break;
		}
	}
	TDM_VERBOSE0("\nTDM: Y0, OVS Spacing Info\n");
	for (t = 0; t < 32; t++)
	{
		switch (sy0[t])
		{
			case 130:
				TDM_VERBOSE0(" x");
				break;
			default:
				TDM_VERBOSE1(" %0d", sy0[t]);
				break;
		}
	}
	TDM_VERBOSE0("\nTDM: Y1, TDM Calendar\n");
	for (t = 0; t < 32; t++)
	{
		switch (y1[t])
		{
			case 130:
				TDM_VERBOSE0(" x");
				break;
			case 131:
				TDM_VERBOSE0(" O");
				break;
			default:
				TDM_VERBOSE1(" %0d", y1[t]);
				break;
		}
	}
	TDM_VERBOSE0("\nTDM: Y1, OVS Calendar\n");
	for (t = 0; t < 32; t++)
	{
		switch (oy1[t])
		{
			case 130:
				TDM_VERBOSE0(" x");
				break;
			default:
				TDM_VERBOSE1(" %0d", oy1[t]);
				break;
		}
	}
	TDM_VERBOSE0("\nTDM: Y1, OVS Spacing Info\n");
	for (t = 0; t < 32; t++)
	{
		switch (sy1[t])
		{
			case 130:
				TDM_VERBOSE0(" x");
				break;
			default:
				TDM_VERBOSE1(" %0d", sy1[t]);
				break;
		}
	}
	TDM_VERBOSE0("\n");
}


/**
@name: TDM_scheduler_PQ
@param: int

customizable partial quotient ceiling function
**/
/* int TDM_scheduler_PQ(float f) { return (int)((f < 0.0f) ? f - 0.5f : f + 0.5f); }*/
static int TDM_scheduler_PQ(int f) { return ((int)((f+5)/10)); }


/**
@name: TDM_scheduler
@param: int[][], int*, *int, *int, int, int[32], int[32], int, int, int, int[128], int, int, *int, int[32], *int

populate bilayer TDM calender
**/
static int TDM_scheduler(int wc_array[NUM_WC][4], int speed[NUM_EXT_PORTS], int *cur_idx, int *pgw_tdm_idx, int *ovs_tdm_idx, int subp, int pgw_tdm_tbl[32], int ovs_tdm_tbl[32], int upperlimit, int iter1, int bw, int port_state_map[128], int iter3, int stop1, int swap_array[32], int *z, int subport)
{
	int max_tdm_len=bw/40, pgw_tdm_idx_sub;
	int p, l;
	int num_lr = 0, num_lr_1 = 0, num_lr_10 = 0, num_lr_20 = 0, num_lr_40 = 0, num_lr_100 = 0, num_lr_120 = 0, num_ovs = 0, num_off = 0;
	int l1_tdm_len, l1_ovs_cnt = 0;
	int gestalt_iter, gestalt_id_iter, gestalt_id = 0, gestalt_tag;
	int sm_iter = 0;
	int microsub = FALSE;
	
	TDM_VERBOSE0("TDM: ----------------------------------------------------------------\n");
	/* set layer 1 TDM max subspace length */
	switch(bw) 
	{
		  case 480:  
			pgw_tdm_idx_sub = 3;
			break;
		  case 640:  
			pgw_tdm_idx_sub = 4;
			break;
		  case 720:
			if ((iter3 == 32 || iter3 == 64) && (stop1 == 64 || stop1 == 96)) {pgw_tdm_idx_sub = 5; max_tdm_len = 20;}
			else {pgw_tdm_idx_sub = 4; max_tdm_len = 16;}
			break;
		  case 800:
			pgw_tdm_idx_sub = 5;
			break;
		  case 960:
			pgw_tdm_idx_sub = 6;
			break;
		  case 1120:
			pgw_tdm_idx_sub = 7;
			break;
		  case 1280:
			pgw_tdm_idx_sub = 8;
			break;
		  default:
			pgw_tdm_idx_sub = 8;
			break;
	}
	
	/* port state diagnostics */
	for (p = iter3; p < stop1; p++) 
	{
		if (port_state_map[p] == 1)
		{
			num_lr++;
			if (port_state_map[p+1] != 3)
			{
				if (speed[p+1]<SPEED_10G) num_lr_1++;
				else if (speed[p+1]==SPEED_10G || speed[p+1]==SPEED_10G_DUAL || speed[p+1]==SPEED_10G_XAUI) num_lr_10++;
			}
		   else if (port_state_map[p+1] == 3 && 
			    port_state_map[p+2] != 3) num_lr_20++;
		   else if (port_state_map[p+1] == 3 && 
			    port_state_map[p+2] == 3 &&
			    port_state_map[p+4] != 3) num_lr_40++;
		   else if (port_state_map[p+1] == 3 && 
			    port_state_map[p+2] == 3 && 
			    port_state_map[p+4] == 3 &&
			    port_state_map[p+9] == 3 &&
			    port_state_map[p+11] != 3) num_lr_100++;
		   else if (port_state_map[p+1] == 3 && 
			    port_state_map[p+2] == 3 && 
			    port_state_map[p+4] == 3 &&
			    port_state_map[p+9] == 3 &&
			    port_state_map[p+11] == 3) num_lr_120++;
		}
		else if (port_state_map[p] == 2) num_ovs++;
		else if (port_state_map[p] == 0) num_off++;
	}
	if (iter3 < 17)
	{
		for (p=0; p<4; p++) if (wc_array[3][p]==MGM_TOKEN)
		{
			num_lr--;
			if (speed[p+13]==SPEED_2p5G || speed[p+13]==SPEED_1G) num_lr_1--;
			else if (speed[p+13]==SPEED_10G || speed[p+13]==SPEED_10G_XAUI) num_lr_10--;
		}
	}
	/* assert( (num_lr_10+num_lr_20+num_lr_40+num_lr_100+num_lr_120) <= num_lr ); */
	if ((num_lr_1+num_lr_10+num_lr_20+num_lr_40+num_lr_100+num_lr_120) != num_lr)
	{
		TDM_ERROR0("TDM: _____FATAL ERROR: port allocation mismatch detected\n");
		return 0;
	}

	/* number of 10G slots required */
	l1_tdm_len = ((num_lr_1)+(num_lr_10)+((num_lr_20)*2)+((num_lr_40)*4)+((num_lr_100)*10)+((num_lr_120)*12));
	
	/* check bandwidth overloading */
	if (l1_tdm_len > max_tdm_len)
	{
		if (num_lr_1==0)
		{
			TDM_ERROR0("TDM: _____FATAL ERROR: bandwidth overloaded\n");
			return 0;
		}
		/* if this quadrant has too many 1G ports, override slot settings and implicitly downscale each slot's resolution */
		else if (num_lr_1!=0 && num_lr_10==0)
		{
			max_tdm_len=num_lr_1;
			if (num_lr_1 % 4 != 0)
			{
				TDM_ERROR0("TDM: _____FATAL ERROR: illegal 1G configuration\n");
				return 0;
			}
			else pgw_tdm_idx_sub=num_lr_1/4;
		}
		else if (num_lr_1!=0 && num_lr_10!=0)
		{
			TDM_VERBOSE0("TDM: _____VERBOSE: bandwidth granularity insufficient, using 1G microscheduling\n");
			microsub=TRUE;
		}
	}
	
	/* calculate base number of OVS tokens required */
	if (num_ovs > 0)
	{
		TDM_VERBOSE0("TDM: _____VERBOSE: oversub detected\n");
		
		if (num_lr_100!=1 && l1_tdm_len!=0)
		{
			if ( (max_tdm_len-l1_tdm_len)%4==0 ) l1_ovs_cnt=((max_tdm_len-l1_tdm_len)/4);
			else if ( (max_tdm_len-l1_tdm_len)%2==0 )
			{
				if (subport == 1 || subport == 3) l1_ovs_cnt=(max_tdm_len-l1_tdm_len+((max_tdm_len-l1_tdm_len)%4))/4;
				else l1_ovs_cnt = ((max_tdm_len-l1_tdm_len)/4);
			}
			else l1_ovs_cnt = ((max_tdm_len - l1_tdm_len - (4 - l1_tdm_len % 4))/4);
		}
		else if (num_lr_100==1) l1_ovs_cnt = 1;
		else if (l1_tdm_len == 0) l1_ovs_cnt = max_tdm_len;
		
		/*
		else if (num_lr_100 != 1)
		{
			if (l1_ovs_cnt%2==0) if (subport==1||subport==3) l1_ovs_cnt = l1_ovs_cnt/2;
			else l1_ovs_cnt = max_tdm_len - l1_tdm_len - (4 - num_lr_10 % 4);
		}
		else if (num_lr_100 != 1)
		{
			if (num_lr_10 % 4 == 0) l1_ovs_cnt = max_tdm_len - l1_tdm_len;
			else if (num_lr_10 % 4 != 0) l1_ovs_cnt = max_tdm_len - l1_tdm_len - (4 - num_lr_10 % 4);
		}
		if (num_lr_100 != 1 && l1_ovs_cnt < 4 && l1_ovs_cnt != 2) TDM_ERROR0("TDM: _____ERROR: unable to partition oversubscription tokens\n");
		else if (num_lr_100 != 1 && l1_ovs_cnt == 2)
		{
			if (subport == 1 || subport == 3) l1_ovs_cnt = 1;
			else l1_ovs_cnt = 0;
		} 
		*/
		if (l1_ovs_cnt==0) TDM_ERROR0("TDM: _____ERROR: unable to partition oversubscription tokens\n");
	}
	TDM_VERBOSE1("TDM: _____VERBOSE: base oversubscription token pool is %0d\n", l1_ovs_cnt);
	
	TDM_VERBOSE0("TDM: ----------------------------------------------------------------\n");
	TDM_VERBOSE1("TDM: _____VERBOSE: 1G line rate ports in this quadrant is %0d\n", num_lr_1);
	TDM_VERBOSE1("TDM: _____VERBOSE: 10G line rate ports in this quadrant is %0d\n", num_lr_10);
	TDM_VERBOSE1("TDM: _____VERBOSE: 20G line rate ports in this quadrant is %0d\n", num_lr_20);
	TDM_VERBOSE1("TDM: _____VERBOSE: 40G line rate ports in this quadrant is %0d\n", num_lr_40);
	TDM_VERBOSE1("TDM: _____VERBOSE: 100G gestalt line rate ports in this quadrant is %0d\n", num_lr_100);
	TDM_VERBOSE1("TDM: _____VERBOSE: 120G gestalt line rate ports in this quadrant is %0d\n", num_lr_120);
	TDM_VERBOSE1("TDM: _____VERBOSE: oversubscribed ports in this quadrant is %0d\n", num_ovs);
	TDM_VERBOSE1("TDM: _____VERBOSE: disabled subports in this quadrent is %0d\n", num_off);
	TDM_VERBOSE2("TDM: _____VERBOSE: COVERAGE FROM PHYSICAL PORTS %0d to %0d\n", iter3, stop1);

	if (microsub==TRUE)
	{
		TDM_WARN0("TDM: _____WARNING: using microscheduling (per quadrant granularity reduction)\n");
		max_tdm_len=((num_lr_1)+10*num_lr_10);
		pgw_tdm_idx_sub=8;
		for (gestalt_id_iter = iter3; gestalt_id_iter < stop1; gestalt_id_iter++) 
		{
			if ( port_state_map[gestalt_id_iter] == 1 &&
			     port_state_map[gestalt_id_iter+1] != 3 &&
						  (speed[gestalt_id_iter+1]==SPEED_10G || speed[gestalt_id_iter+1]==SPEED_10G_DUAL || speed[gestalt_id_iter+1]==SPEED_10G_XAUI) )
				gestalt_id = (gestalt_id_iter + 1);
		}
		if (num_lr_10 > 2)
		/* if (num_lr_10 > 3) */ /* there is no single or dual lane 1G, max number of mixed 10G is 2 */
		{
			TDM_ERROR0("TDM: __________FATAL ERROR: bandwidth overloaded\n");
			return 0;
		}
		else
		{
			for (l=0; l<num_lr_10; l++)
			{
				for (gestalt_iter = 0; gestalt_iter < 5; gestalt_iter++)
				{
					gestalt_tag = TDM_scheduler_PQ((((max_tdm_len/2)*10)/5) * gestalt_iter);
					pgw_tdm_tbl[gestalt_tag+l] = gestalt_id;
					pgw_tdm_tbl[gestalt_tag+11+l] = gestalt_id;
				}
			}
		}
		while (sm_iter < NUM_EXT_PORTS)
		{
			/* chopping block */
			while ((*cur_idx < upperlimit) && ((wc_array[*cur_idx][subp] == NUM_EXT_PORTS) || (wc_array[*cur_idx][subp] == MGM_TOKEN)))
			{
				(*cur_idx)++;
			}
			if (*cur_idx >= upperlimit) 
			{
				int pp_iter;
				for (pp_iter = 0; pp_iter < max_tdm_len; pp_iter++) if (pgw_tdm_tbl[pp_iter] == NUM_EXT_PORTS) pgw_tdm_tbl[pp_iter] = OVS_TOKEN;
				return 1;
			}
			
			TDM_VERBOSE0("TDM: ----------------------------------------------------------------\n");
			TDM_VERBOSE1("TDM: _____VERBOSE: the present x1G port is %0d\n", wc_array[*cur_idx][subp]);

			/* port state machine */
			switch(port_state_map[(wc_array[*cur_idx][subp])-1])
			{
				case 0:
					TDM_VERBOSE0("TDM: _____VERBOSE: the port is DISABLED\n");
					TDM_VERBOSE2("TDM: Pipe : %0d the pgw tdm tbl element #0%0d would be an invalid port\n", upperlimit, *pgw_tdm_idx);
					if (pgw_tdm_tbl[*pgw_tdm_idx] != gestalt_id)
					{
						pgw_tdm_tbl[*pgw_tdm_idx] = OVS_TOKEN;
						(*pgw_tdm_idx)++;
						(*cur_idx)++;
					}
					else if (num_ovs > 0)
					{
						(*z)++;
						swap_array[*z] = OVS_TOKEN;
						TDM_VERBOSE2("TDM: Pipe : %0d pushed an OVS token into LIFO swap buffer at index %0d\n", upperlimit, *z);
						(*cur_idx)++;
					}
					break;
				/* case 3:
					TDM_VERBOSE0("TDM: _____VERBOSE: the port is part of a DUAL/QUAD/100G\n"); */
				case 1:
					TDM_VERBOSE0("TDM: _____VERBOSE: the port is LINE RATE\n");
					while (pgw_tdm_tbl[(*pgw_tdm_idx)] == gestalt_id) (*pgw_tdm_idx)++;
					while (swap_array[*z] == gestalt_id)
					{
						swap_array[*z] = 0;
						(*z)--;
					}
					if (num_ovs == 0)
					{
						TDM_VERBOSE1("TDM: the cur_idx is %0d\n", *cur_idx);

						while ((*z) > 0 && 
									pgw_tdm_tbl[(*pgw_tdm_idx)-1] != swap_array[*z])
						{
							TDM_VERBOSE4("TDM: Pipe : %0d priority dequeuing from LIFO swap buffer, pointer index %0d, to pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *z, *pgw_tdm_idx, swap_array[*z]);
							pgw_tdm_tbl[*pgw_tdm_idx] = swap_array[*z];
							(*pgw_tdm_idx)++;
							(*z)--;
							TDM_VERBOSE1("TDM: _____DEBUG: LIFO index pointer is %0d\n", *z);
						}
						if ((wc_array[*cur_idx][subp] != pgw_tdm_tbl[(*pgw_tdm_idx)-1] || (*pgw_tdm_idx)==0))
						{
							pgw_tdm_tbl[*pgw_tdm_idx] = wc_array[*cur_idx][subp];
							TDM_VERBOSE3("TDM: Pipe : %0d the pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *pgw_tdm_idx, pgw_tdm_tbl[*pgw_tdm_idx]);
							(*pgw_tdm_idx)++;
							(*cur_idx)++;
						}
						else if (wc_array[*cur_idx][subp] != gestalt_id)
						{
							(*z)++;
							swap_array[*z] = wc_array[*cur_idx][subp];
							TDM_VERBOSE3("TDM: Pipe : %0d pushed port %0d into LIFO swap buffer at index %0d\n", upperlimit, wc_array[*cur_idx][subp], *z);
							(*cur_idx)++;
						}
						else (*cur_idx)++;
					}
					else if (num_ovs > 0)
					{
						TDM_VERBOSE1("TDM: the cur_idx is %0d\n", *cur_idx);

						if ((*z) > 0 && 
								pgw_tdm_tbl[(*pgw_tdm_idx)-2] != swap_array[*z] &&
								pgw_tdm_tbl[(*pgw_tdm_idx)-1] == OVS_TOKEN)
						{
							TDM_VERBOSE4("TDM: Pipe : %0d priority dequeuing from LIFO swap buffer, pointer index %0d, to pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *z, *pgw_tdm_idx, swap_array[*z]);
							pgw_tdm_tbl[*pgw_tdm_idx] = swap_array[*z];
							(*pgw_tdm_idx)++;
							(*z)--;
							TDM_VERBOSE1("TDM: _____DEBUG: LIFO index pointer is %0d\n", *z);
						}
						while ((*z) > 0 && 
									pgw_tdm_tbl[(*pgw_tdm_idx)-1] != swap_array[*z] && 
									pgw_tdm_tbl[(*pgw_tdm_idx)-1] != OVS_TOKEN)
						{
							TDM_VERBOSE4("TDM: Pipe : %0d priority dequeuing from LIFO swap buffer, pointer index %0d, to pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *z, *pgw_tdm_idx, swap_array[*z]);
							pgw_tdm_tbl[*pgw_tdm_idx] = swap_array[*z];
							(*pgw_tdm_idx)++;
							(*z)--;
							TDM_VERBOSE1("TDM: _____DEBUG: LIFO index pointer is %0d\n", *z);
						}
						if ((wc_array[*cur_idx][subp] != pgw_tdm_tbl[(*pgw_tdm_idx)-1] || (*pgw_tdm_idx)==0) &&
										wc_array[*cur_idx][subp] != gestalt_id)
						{
							pgw_tdm_tbl[*pgw_tdm_idx] = wc_array[*cur_idx][subp];
							TDM_VERBOSE3("TDM: Pipe : %0d the pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *pgw_tdm_idx, pgw_tdm_tbl[*pgw_tdm_idx]);
							(*pgw_tdm_idx)++;
							(*cur_idx)++;
						}
						else if (wc_array[*cur_idx][subp] != gestalt_id)
						{
							(*z)++;
							swap_array[*z] = wc_array[*cur_idx][subp];
							TDM_VERBOSE3("TDM: Pipe : %0d pushed port %0d into LIFO swap buffer at index %0d\n", upperlimit, wc_array[*cur_idx][subp], *z);
							(*cur_idx)++;
						}
						else (*cur_idx)++;
					}
					break;
				case 2:
					TDM_VERBOSE0("TDM: _____VERBOSE: the port is OVERSUBSCRIBED\n");
					TDM_VERBOSE1("TDM: the ovs_tdm_idx is %0d\n", *ovs_tdm_idx);
					TDM_VERBOSE1("TDM: the cur_idx is %0d\n", *cur_idx);
					ovs_tdm_tbl[*ovs_tdm_idx] = wc_array[*cur_idx][subp];
					TDM_VERBOSE3("TDM: Pipe : %0d the ovs tdm tbl element #0%0d, content is %0d\n", upperlimit, *ovs_tdm_idx,  ovs_tdm_tbl[*ovs_tdm_idx]);
					(*ovs_tdm_idx)++;
					(*cur_idx)++;
					break;
			}

			/* chopping block */
			while ((*cur_idx < upperlimit) && ((wc_array[*cur_idx][subp] == NUM_EXT_PORTS) || (wc_array[*cur_idx][subp] == MGM_TOKEN))) 
			{
				(*cur_idx)++;
			}
			if (*cur_idx >= upperlimit) 
			{
				int pp_iter;
				for (pp_iter = 0; pp_iter < max_tdm_len; pp_iter++) if (pgw_tdm_tbl[pp_iter] == NUM_EXT_PORTS) pgw_tdm_tbl[pp_iter] = OVS_TOKEN;
				return 1;
			}
			
			sm_iter++;
		}
		return 1;
	}
	
	/* fringe case - obligate oversubscription */
	else if ((l1_tdm_len > max_tdm_len) && (num_ovs == 0))
	{
		int xcount;
		/* printf("TDM: _____WARNING: applying obligate oversubscription correction\n"); */
		TDM_WARN0("TDM: _____WARNING: applying obligate oversubscription correction\n");
		for (xcount = 0; xcount < max_tdm_len; xcount++)
		{
			/* chopping block */
			while ((*cur_idx < upperlimit) && ((wc_array[*cur_idx][subp] == NUM_EXT_PORTS) || (wc_array[*cur_idx][subp] == MGM_TOKEN))) 
			{	
				(*cur_idx)++;
			}
			if (*cur_idx >= upperlimit) 
			{
				return 1;
			}
			if ((*pgw_tdm_idx) < max_tdm_len)
			{
				pgw_tdm_tbl[*pgw_tdm_idx] = OVS_TOKEN;
				/* printf("CPRINT: Pipe : %0d the pgw tdm tbl element #0%0d has an oversub token placed\n", upperlimit, *pgw_tdm_idx); */
				TDM_VERBOSE2("TDM: _____VERBOSE: Pipe : %0d the pgw tdm tbl element #0%0d has an oversub token placed\n", upperlimit, *pgw_tdm_idx);
				(*pgw_tdm_idx)++;
			}
			ovs_tdm_tbl[*ovs_tdm_idx] = wc_array[*cur_idx][subp];
			/* TDM_VERBOSE3("TDM: Pipe : %0d the ovs tdm tbl element #0%0d, content is %0d\n", upperlimit, *ovs_tdm_idx,  ovs_tdm_tbl[*ovs_tdm_idx]); */
			TDM_VERBOSE3("TDM: _____VERBOSE: Pipe : %0d the ovs tdm tbl element #0%0d, content is %0d\n", upperlimit, *ovs_tdm_idx,  ovs_tdm_tbl[*ovs_tdm_idx]);
			(*ovs_tdm_idx)++;
			(*cur_idx)++;
			/* chopping block */
			while ((*cur_idx < upperlimit) && ((wc_array[*cur_idx][subp] == NUM_EXT_PORTS) || (wc_array[*cur_idx][subp] == MGM_TOKEN))) 
			{	
				(*cur_idx)++;
			}
			if (*cur_idx >= upperlimit) 
			{
				return 1;
			}
		}
		return 1;
	}
	/* invalid case */
	else if (l1_tdm_len >= max_tdm_len && num_ovs != 0)
	{
		/* printf("TDM: _____WARNING: Pipe : %0d, FATAL error, invalid configuration\n", upperlimit); */
		TDM_ERROR1("TDM: _____ERROR: Pipe : %0d, FATAL error, invalid configuration\n", upperlimit);
		return 0;
	}
	/* 100G dominating case */
	else if ((num_lr_100 + num_lr_120 == 1) && (num_lr_10)+((num_lr_20)*2)+((num_lr_40)*4) < ((num_lr_100)*10)+((num_lr_120)*12))
	{
		TDM_WARN0("TDM: _____WARNING: applying dominant 100G correction\n");
		/* preemptively find the 100G port */
		for (gestalt_id_iter = iter3; gestalt_id_iter < stop1; gestalt_id_iter++) 
		{
			if (port_state_map[gestalt_id_iter] == 1 &&
			    port_state_map[gestalt_id_iter+1] == 3 && 
		            port_state_map[gestalt_id_iter+2] == 3 && 
			    port_state_map[gestalt_id_iter+4] == 3 &&
			    port_state_map[gestalt_id_iter+9] == 3) gestalt_id = (gestalt_id_iter + 1);
		}
		if (num_lr_100 == 1 && num_lr_120 == 0)
		{
			for (gestalt_iter = 0; gestalt_iter < 5; gestalt_iter++)
			{
				gestalt_tag = TDM_scheduler_PQ((((max_tdm_len/2)*10)/5) * gestalt_iter);
/* 				gestalt_tag = TDM_scheduler_PQ((((float) (max_tdm_len/2))/((float) 5.0)) * gestalt_iter); */
				pgw_tdm_tbl[gestalt_tag] = gestalt_id;
				pgw_tdm_tbl[gestalt_tag+12] = gestalt_id;
			}
/* 			for (gestalt_iter = 0; gestalt_iter < 10; gestalt_iter++) */
/* 			{ */
/* 				gestalt_tag = TDM_scheduler_PQ((((float) max_tdm_len-1)/((float) 9.0)) * gestalt_iter); */
/* 				pgw_tdm_tbl[gestalt_tag] = gestalt_id; */
/* 			} 												*/
			
		}
		else if (num_lr_100 == 0 && num_lr_120 == 1)
		{
			for (gestalt_iter = 0; gestalt_iter < 12; gestalt_iter++)
			{
				gestalt_tag = TDM_scheduler_PQ((((max_tdm_len-1)*10)/11) * gestalt_iter);
/* 				gestalt_tag = TDM_scheduler_PQ((((float) max_tdm_len-1)/((float) 11.0)) * gestalt_iter); */
				pgw_tdm_tbl[gestalt_tag] = gestalt_id;
			}
		}
		while (sm_iter < NUM_EXT_PORTS)
		{
			/* chopping block */
			while ((*cur_idx < upperlimit) && ((wc_array[*cur_idx][subp] == NUM_EXT_PORTS) || (wc_array[*cur_idx][subp] == MGM_TOKEN)))
			{
				(*cur_idx)++;
			}
			if (*cur_idx >= upperlimit) 
			{
				int pp_iter;
				for (pp_iter = 0; pp_iter < max_tdm_len; pp_iter++) if (pgw_tdm_tbl[pp_iter] == NUM_EXT_PORTS) pgw_tdm_tbl[pp_iter] = OVS_TOKEN;
				return 1;
			}
			
			TDM_VERBOSE0("TDM: ----------------------------------------------------------------\n");
			TDM_VERBOSE1("TDM: _____VERBOSE: the present x10G port is %0d\n", wc_array[*cur_idx][subp]);

			/* port state machine */
			switch(port_state_map[(wc_array[*cur_idx][subp])-1])
			{
				case 0:
					TDM_VERBOSE0("TDM: _____VERBOSE: the port is DISABLED\n");
					TDM_VERBOSE2("TDM: Pipe : %0d the pgw tdm tbl element #0%0d would be an invalid port\n", upperlimit, *pgw_tdm_idx);
					if (pgw_tdm_tbl[*pgw_tdm_idx] != gestalt_id)
					{
						pgw_tdm_tbl[*pgw_tdm_idx] = OVS_TOKEN;
						(*pgw_tdm_idx)++;
						(*cur_idx)++;
					}
					else if (num_ovs > 0)
					{
						(*z)++;
						swap_array[*z] = OVS_TOKEN;
						TDM_VERBOSE2("TDM: Pipe : %0d pushed an OVS token into LIFO swap buffer at index %0d\n", upperlimit, *z);
						(*cur_idx)++;
					}
					break;
				/* case 3:
					TDM_VERBOSE0("TDM: _____VERBOSE: the port is part of a DUAL/QUAD/100G\n"); */
				case 1:
					TDM_VERBOSE0("TDM: _____VERBOSE: the port is LINE RATE\n");
					while (pgw_tdm_tbl[(*pgw_tdm_idx)] == gestalt_id) (*pgw_tdm_idx)++;
					while (swap_array[*z] == gestalt_id)
					{
						swap_array[*z] = 0;
						(*z)--;
					}
					if (num_ovs == 0)
					{
						TDM_VERBOSE1("TDM: the cur_idx is %0d\n", *cur_idx);

						while ((*z) > 0 && 
						        pgw_tdm_tbl[(*pgw_tdm_idx)-1] != swap_array[*z])
						{
							TDM_VERBOSE4("TDM: Pipe : %0d priority dequeuing from LIFO swap buffer, pointer index %0d, to pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *z, *pgw_tdm_idx, swap_array[*z]);
							pgw_tdm_tbl[*pgw_tdm_idx] = swap_array[*z];
							(*pgw_tdm_idx)++;
							(*z)--;
							TDM_VERBOSE1("TDM: _____DEBUG: LIFO index pointer is %0d\n", *z);
						}
						if ((wc_array[*cur_idx][subp] != pgw_tdm_tbl[(*pgw_tdm_idx)-1] || (*pgw_tdm_idx)==0))
						{
							pgw_tdm_tbl[*pgw_tdm_idx] = wc_array[*cur_idx][subp];
							TDM_VERBOSE3("TDM: Pipe : %0d the pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *pgw_tdm_idx, pgw_tdm_tbl[*pgw_tdm_idx]);
							(*pgw_tdm_idx)++;
							(*cur_idx)++;
						}
						else if (wc_array[*cur_idx][subp] != gestalt_id)
						{
							(*z)++;
							swap_array[*z] = wc_array[*cur_idx][subp];
							TDM_VERBOSE3("TDM: Pipe : %0d pushed port %0d into LIFO swap buffer at index %0d\n", upperlimit, wc_array[*cur_idx][subp], *z);
							(*cur_idx)++;
						}
						else (*cur_idx)++;
					}
					else if (num_ovs > 0)
					{
						TDM_VERBOSE1("TDM: the cur_idx is %0d\n", *cur_idx);

						if ((*z) > 0 && 
						    pgw_tdm_tbl[(*pgw_tdm_idx)-2] != swap_array[*z] &&
						    pgw_tdm_tbl[(*pgw_tdm_idx)-1] == OVS_TOKEN)
						{
							TDM_VERBOSE4("TDM: Pipe : %0d priority dequeuing from LIFO swap buffer, pointer index %0d, to pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *z, *pgw_tdm_idx, swap_array[*z]);
							pgw_tdm_tbl[*pgw_tdm_idx] = swap_array[*z];
							(*pgw_tdm_idx)++;
							(*z)--;
							TDM_VERBOSE1("TDM: _____DEBUG: LIFO index pointer is %0d\n", *z);
						}
						while ((*z) > 0 && 
							pgw_tdm_tbl[(*pgw_tdm_idx)-1] != swap_array[*z] && 
							pgw_tdm_tbl[(*pgw_tdm_idx)-1] != OVS_TOKEN)
						{
							TDM_VERBOSE4("TDM: Pipe : %0d priority dequeuing from LIFO swap buffer, pointer index %0d, to pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *z, *pgw_tdm_idx, swap_array[*z]);
							pgw_tdm_tbl[*pgw_tdm_idx] = swap_array[*z];
							(*pgw_tdm_idx)++;
							(*z)--;
							TDM_VERBOSE1("TDM: _____DEBUG: LIFO index pointer is %0d\n", *z);
						}
						if ((wc_array[*cur_idx][subp] != pgw_tdm_tbl[(*pgw_tdm_idx)-1] || (*pgw_tdm_idx)==0) &&
						    wc_array[*cur_idx][subp] != gestalt_id)
						{
							pgw_tdm_tbl[*pgw_tdm_idx] = wc_array[*cur_idx][subp];
							TDM_VERBOSE3("TDM: Pipe : %0d the pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *pgw_tdm_idx, pgw_tdm_tbl[*pgw_tdm_idx]);
							(*pgw_tdm_idx)++;
							(*cur_idx)++;
						}
						else if (wc_array[*cur_idx][subp] != gestalt_id)
						{
							(*z)++;
							swap_array[*z] = wc_array[*cur_idx][subp];
							TDM_VERBOSE3("TDM: Pipe : %0d pushed port %0d into LIFO swap buffer at index %0d\n", upperlimit, wc_array[*cur_idx][subp], *z);
							(*cur_idx)++;
						}
						else (*cur_idx)++;
					}
					break;
				case 2:
					TDM_VERBOSE0("TDM: _____VERBOSE: the port is OVERSUBSCRIBED\n");
					TDM_VERBOSE1("TDM: the ovs_tdm_idx is %0d\n", *ovs_tdm_idx);
					TDM_VERBOSE1("TDM: the cur_idx is %0d\n", *cur_idx);
					ovs_tdm_tbl[*ovs_tdm_idx] = wc_array[*cur_idx][subp];
					TDM_VERBOSE3("TDM: Pipe : %0d the ovs tdm tbl element #0%0d, content is %0d\n", upperlimit, *ovs_tdm_idx,  ovs_tdm_tbl[*ovs_tdm_idx]);
					(*ovs_tdm_idx)++;
					(*cur_idx)++;
					break;
			}

			/* chopping block */
			while ((*cur_idx < upperlimit) && ((wc_array[*cur_idx][subp] == NUM_EXT_PORTS) || (wc_array[*cur_idx][subp] == MGM_TOKEN))) 
			{
				(*cur_idx)++;
			}
			if (*cur_idx >= upperlimit) 
			{
				int pp_iter;
				for (pp_iter = 0; pp_iter < max_tdm_len; pp_iter++) if (pgw_tdm_tbl[pp_iter] == NUM_EXT_PORTS) pgw_tdm_tbl[pp_iter] = OVS_TOKEN;
				return 1;
			}
			
			sm_iter++;
		}
		return 1;
	}

	/* standard case */
	else
	{
		int pgw_tdm_idx_lookback = 0;
		sm_iter = 0;
		while (sm_iter < NUM_EXT_PORTS)
		{
			/* chopping block */
			while ((*cur_idx < upperlimit) && ((wc_array[*cur_idx][subp] == NUM_EXT_PORTS) || (wc_array[*cur_idx][subp] == MGM_TOKEN)))
			{
				(*cur_idx)++;
			}
			if (*cur_idx >= upperlimit) 
			{
				/* table post processing */
				TDM_VERBOSE2("TDM: _____DEBUG: entering post-processing 1, executing lookback %0d against subset limit %0d\n", pgw_tdm_idx_lookback, pgw_tdm_idx_sub);
				if (l1_ovs_cnt > 0)
				{
					int ovs_pad_iter = 0;
					while (ovs_pad_iter < l1_ovs_cnt && pgw_tdm_idx_lookback < pgw_tdm_idx_sub)
					{
						pgw_tdm_tbl[*pgw_tdm_idx] = OVS_TOKEN;
						TDM_VERBOSE2("TDM: Pipe : %0d the pgw tdm tbl element #0%0d, insert OVS token\n", upperlimit, *pgw_tdm_idx);
						(*pgw_tdm_idx)++;
						pgw_tdm_idx_lookback++;
						ovs_pad_iter++;
					}
				}
				return 1;
			}
			
			TDM_VERBOSE0("TDM: ----------------------------------------------------------------\n");
			TDM_VERBOSE1("TDM: _____DEBUG: the present x10G port is %0d\n", wc_array[*cur_idx][subp]);

			/* port state machine */
			switch(port_state_map[(wc_array[*cur_idx][subp])-1])
			{
				case 0:
					TDM_VERBOSE0("TDM: _____VERBOSE: the port is DISABLED\n");
					TDM_VERBOSE2("TDM: Pipe : %0d the pgw tdm tbl element #0%0d would be an invalid port\n", upperlimit, *pgw_tdm_idx);
					if (num_lr > 0 && num_ovs > 0)
					{
						pgw_tdm_tbl[*pgw_tdm_idx] = OVS_TOKEN;
						(*pgw_tdm_idx)++;
						pgw_tdm_idx_lookback++;
					}
					(*cur_idx)++;
					break;
				/* case 3:
					TDM_VERBOSE0("TDM: _____VERBOSE: the port is part of a DUAL/QUAD/100G\n"); */
				case 1:
					TDM_VERBOSE0("TDM: _____VERBOSE: the port is LINE RATE\n");
					if (num_ovs == 0)
					{
						TDM_VERBOSE1("TDM: the cur_idx is %0d\n", *cur_idx);

						while ((*z) > 0 && pgw_tdm_tbl[(*pgw_tdm_idx)-1] != swap_array[*z])
						{
							TDM_VERBOSE4("TDM: Pipe : %0d priority dequeuing from LIFO swap buffer, pointer index %0d, to pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *z, *pgw_tdm_idx, swap_array[*z]);
							pgw_tdm_tbl[*pgw_tdm_idx] = swap_array[*z];
							(*pgw_tdm_idx)++;
							(*z)--;
							TDM_VERBOSE1("TDM: _____DEBUG: LIFO index pointer is %0d\n", *z);
						}
						if ((wc_array[*cur_idx][subp] != pgw_tdm_tbl[(*pgw_tdm_idx)-1] || (*pgw_tdm_idx)==0))
						{
							pgw_tdm_tbl[*pgw_tdm_idx] = wc_array[*cur_idx][subp];
							TDM_VERBOSE3("TDM: Pipe : %0d the pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *pgw_tdm_idx, pgw_tdm_tbl[*pgw_tdm_idx]);
							(*pgw_tdm_idx)++;
							(*cur_idx)++;
						}
						else
						{
							(*z)++;
							swap_array[*z] = wc_array[*cur_idx][subp];
							TDM_VERBOSE3("TDM: Pipe : %0d pushed port %0d into LIFO swap buffer at index %0d\n", upperlimit, wc_array[*cur_idx][subp], *z);
							(*cur_idx)++;
						}
						pgw_tdm_idx_lookback = pgw_tdm_idx_sub;
					}
					else if (num_ovs > 0)
					{
						TDM_VERBOSE1("TDM: the cur_idx is %0d\n", *cur_idx);

						if ((*z) > 0 && 
						    pgw_tdm_tbl[(*pgw_tdm_idx)-2] != swap_array[*z] &&
						    pgw_tdm_tbl[(*pgw_tdm_idx)-1] == OVS_TOKEN &&
						    (pgw_tdm_idx_lookback < (pgw_tdm_idx_sub-l1_ovs_cnt)))
						{
							TDM_VERBOSE4("TDM: Pipe : %0d priority dequeuing from LIFO swap buffer, pointer index %0d, to pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *z, *pgw_tdm_idx, swap_array[*z]);
							pgw_tdm_tbl[*pgw_tdm_idx] = swap_array[*z];
							(*pgw_tdm_idx)++;
							(*z)--;
							pgw_tdm_idx_lookback++;
							TDM_VERBOSE1("TDM: _____DEBUG: LIFO index pointer is %0d\n", *z);
						}
						while ((*z) > 0 && 
							pgw_tdm_tbl[(*pgw_tdm_idx)-1] != swap_array[*z] && 
							pgw_tdm_tbl[(*pgw_tdm_idx)-1] != OVS_TOKEN &&
							(pgw_tdm_idx_lookback < (pgw_tdm_idx_sub-l1_ovs_cnt)))
						{
							TDM_VERBOSE4("TDM: Pipe : %0d priority dequeuing from LIFO swap buffer, pointer index %0d, to pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *z, *pgw_tdm_idx, swap_array[*z]);
							pgw_tdm_tbl[*pgw_tdm_idx] = swap_array[*z];
							(*pgw_tdm_idx)++;
							(*z)--;
							pgw_tdm_idx_lookback++;
							TDM_VERBOSE1("TDM: _____DEBUG: LIFO index pointer is %0d\n", *z);
						}
						if ((wc_array[*cur_idx][subp] != pgw_tdm_tbl[(*pgw_tdm_idx)-1] || (*pgw_tdm_idx)==0) && 
						    (pgw_tdm_idx_lookback < (pgw_tdm_idx_sub-l1_ovs_cnt)))
						{
							pgw_tdm_tbl[*pgw_tdm_idx] = wc_array[*cur_idx][subp];
							TDM_VERBOSE3("TDM: Pipe : %0d the pgw tdm tbl element #0%0d, content is %0d\n", upperlimit, *pgw_tdm_idx, pgw_tdm_tbl[*pgw_tdm_idx]);
							(*pgw_tdm_idx)++;
							(*cur_idx)++;
							pgw_tdm_idx_lookback++;
						}
						else
						{
							(*z)++;
							swap_array[*z] = wc_array[*cur_idx][subp];
							TDM_VERBOSE3("TDM: Pipe : %0d pushed port %0d into LIFO swap buffer at index %0d\n", upperlimit, wc_array[*cur_idx][subp], *z);
							(*cur_idx)++;
						}
					}
					break;
				case 2:
					TDM_VERBOSE0("TDM: _____VERBOSE: the port is OVERSUBSCRIBED\n");
					TDM_VERBOSE1("TDM: the ovs_tdm_idx is %0d\n", *ovs_tdm_idx);
					TDM_VERBOSE1("TDM: the cur_idx is %0d\n", *cur_idx);
					ovs_tdm_tbl[*ovs_tdm_idx] = wc_array[*cur_idx][subp];
					TDM_VERBOSE3("TDM: Pipe : %0d the ovs tdm tbl element #0%0d, content is %0d\n", upperlimit, *ovs_tdm_idx,  ovs_tdm_tbl[*ovs_tdm_idx]);
					(*ovs_tdm_idx)++;
					if (subp != 0 && port_state_map[(wc_array[*cur_idx][subp-1])-1] == 1)
					{
						pgw_tdm_tbl[*pgw_tdm_idx] = OVS_TOKEN;
						(*pgw_tdm_idx)++;
						pgw_tdm_idx_lookback++;
					}
					(*cur_idx)++;
					break;
			}

			/* chopping block */
			while ((*cur_idx < upperlimit) && ((wc_array[*cur_idx][subp] == NUM_EXT_PORTS) || (wc_array[*cur_idx][subp] == MGM_TOKEN))) 
			{
				(*cur_idx)++;
			}
			if (*cur_idx >= upperlimit) 
			{
				/* table post processing */
				TDM_VERBOSE2("TDM: _____DEBUG: entering post-processing 2, executing lookback %0d against subset limit %0d\n", pgw_tdm_idx_lookback, pgw_tdm_idx_sub);
				if (l1_ovs_cnt > 0)
				{
					int ovs_pad_iter = 0;
					while (ovs_pad_iter < l1_ovs_cnt && pgw_tdm_idx_lookback < pgw_tdm_idx_sub)
					{
						pgw_tdm_tbl[*pgw_tdm_idx] = OVS_TOKEN;
						TDM_VERBOSE2("TDM: Pipe : %0d the pgw tdm tbl element #0%0d, insert OVS token\n", upperlimit, *pgw_tdm_idx);
						(*pgw_tdm_idx)++;
						pgw_tdm_idx_lookback++;
						ovs_pad_iter++;
					}
				}
				return 1;
			}
			sm_iter++;
		}
	}
	TDM_VERBOSE1("TDM: the pgw_tdm_idx is %0d\n", *pgw_tdm_idx);
	TDM_VERBOSE1("TDM: the cur_idx is %0d\n", *cur_idx);
	return 1;
}


/**
@name: write_mmu_tdm_tbl
@param: 

MMU table collector function
 **/
static int write_mmu_tdm_tbl(int pgw0[32], int pgw1[32], int ovs0[32], int ovs1[32], int mmu[256], int bucket1[16], int bucket2[16], int bucket3[16], int bucket4[16], int x_pipe, int port_state_map[128], int tsc[NUM_WC][4], int bw, int speed[NUM_EXT_PORTS])
{
	long int clk;
	int temp_10G[4], temp_1G[4], temp_20G[4];
	long int s1, s2, s3, limiter;
	static int a, x;
	int b, c=0, d, e, f, g, i=0, j, k=0, l, m, v, w, y, microsubbed10G=FALSE, overload10G=0, lr_idx_limit, proxcheck;
	/* create unified pgw buffer - 7 local pointers, 1 schedule pointer, 1 error buffer pointer */
	int pgw_buffer[64], u1g=0, y0=0, y1=0, y2=0, y3=0, y4=0, y5=0, yy=0, ye=0;
	/* create unified ovs buffer - 5 local pointers, 4 bucket pointers */
	int ovs_buffer[64], z1=0, z2=0, z3=0, z4=0, z5=0, z11=0, z22=0, z33=0, z44=0;
	/* int z_shuffle_gap, z_shuffle_map[16],zSS,z_shuffle_done=FALSE, z_shuffle_idx[4], z_shuffle_swap[16]; */
	int pgw_120=FALSE, pgw_100=FALSE, pgw_10=FALSE, pgw_1=FALSE, pgw_20=FALSE, pgw_40=FALSE;
	int pgw01[64], pgw10[64], pgw20[32], pgw40[16], pgw100[8], pgw120[8];
#if 0
        int err_buffer[64], err_speeds[64], err_swap[64];
#endif
	int ovs_10=FALSE, ovs_20=FALSE, ovs_40=FALSE, ovs_100=FALSE, ovs_120=FALSE;
	int num_ovs_10 = 0, num_ovs_20 = 0, num_ovs_40 = 0, num_ovs_100 = 0, num_ovs_120 = 0;
	int ovs10[64], ovs20[32], ovs40[16], ovs100[8], ovs120[8];
	int y4_loopback_style_46=FALSE, y4_loopback_style_54=FALSE;
	int jjj;
	/* int ep_idl_cnt = 0, ep_idl_put, ep_idl_idx; */
	int tsc_swap[4];
	int accessories;

	switch (bw)
	{
		case 960: clk=76000; accessories=8; break;
		case 720: clk=59878; accessories=10; break;
		/* case 720: clk=60833; accessories=10; break; */
		case 640: clk=51786; accessories=8; break;
		case 480: clk=39000; accessories=10; break;
		/* case 480: clk=41563; accessories=10; break; */
		default: clk=76000; accessories=8; break;
	}
	
/* 	printf("TDM: _____VERBOSE: CLOCK SPEED IN Hz = %0d\n", clk); */
	
	/* buffer both quadrant tables at once */
	for (j = 0; j < 64; j++)
	{
		pgw10[j] = 144;
		pgw01[j] = 144;
		pgw_buffer[j] = NUM_EXT_PORTS;
		ovs_buffer[j] = NUM_EXT_PORTS;
#if 0
		err_buffer[j] = 0;
		err_speeds[j] = 0;
		err_swap[j] = 0;
#endif
	}
	while ((i<32) && ((pgw0[i] != NUM_EXT_PORTS) || (pgw1[i] != NUM_EXT_PORTS)))
	{
		pgw_buffer[k] = pgw0[i];
		pgw_buffer[k+1] = pgw1[i];
		k+=2;
		i++;
	}
	for (j = 0; j < 32; j++)
	{
		ovs_buffer[j] = ovs0[j];
		ovs_buffer[j+32] = ovs1[j];
	}

	/* port state heuristic machine */
	for (j = 0; j < 64; j++)
	{
		/* real port is pgw_buffer[j] */
		if (pgw_buffer[j] != NUM_EXT_PORTS && pgw_buffer[j] != OVS_TOKEN && port_state_map[pgw_buffer[j]-1] == 1)
		{
/* 			printf("PGW bucket sort: line rate port index %0d has %0d\n", j, pgw_buffer[j]); */
			if (port_state_map[pgw_buffer[j]] != 3 && (speed[pgw_buffer[j]]==SPEED_10G || speed[pgw_buffer[j]]==SPEED_10G_DUAL || speed[pgw_buffer[j]]==SPEED_10G_XAUI))
			{
				pgw_10 = TRUE;
				/* ignore all repeats of microsubbed 10G */
				for (y=0; y<64; y++) if (pgw10[y]==pgw_buffer[j]) microsubbed10G=TRUE;
				if (microsubbed10G==FALSE) {y1++; pgw10[y1] = pgw_buffer[j];}
				microsubbed10G=FALSE;
			}
			else if (port_state_map[pgw_buffer[j]] != 3 && speed[pgw_buffer[j]]<SPEED_10G)
			{
				pgw_1 = TRUE;
				y0++;
				u1g++;
				pgw01[y0] = pgw_buffer[j];
			}
			else if (port_state_map[pgw_buffer[j]] == 3 &&
				 port_state_map[pgw_buffer[j]+1] != 3)
			{
				pgw_20 = TRUE;
				y2++;
				pgw20[y2] = pgw_buffer[j];
				pgw20[0] = NUM_EXT_PORTS;
				for (m=0; m<y2; m++) if (pgw20[m] == pgw_buffer[j]) y2--;
			}
			else if (port_state_map[pgw_buffer[j]] == 3 &&
				 port_state_map[pgw_buffer[j]+1] == 3 &&
				 port_state_map[pgw_buffer[j]+3] != 3)
			{
				pgw_40 = TRUE;
				y3++;
				pgw40[y3] = pgw_buffer[j];
				pgw40[0] = NUM_EXT_PORTS;
				for (m=0; m<y3; m++) if (pgw40[m] == pgw_buffer[j]) y3--;
			}
			else if ((port_state_map[pgw_buffer[j]] == 3 &&
				 port_state_map[pgw_buffer[j]+1] == 3 &&
				 port_state_map[pgw_buffer[j]+3] == 3 &&
				 port_state_map[pgw_buffer[j]+8] == 3 &&
				 port_state_map[pgw_buffer[j]+10] != 3) || speed[pgw_buffer[j]]==SPEED_100G)
			{
				pgw_100 = TRUE;
				y4++;
				pgw100[y4] = pgw_buffer[j];
				pgw100[0] = NUM_EXT_PORTS;
				for (m=0; m<y4; m++) if (pgw100[m] == pgw_buffer[j]) y4--;
			}
			else if ((port_state_map[pgw_buffer[j]] == 3 &&
				 port_state_map[pgw_buffer[j]+1] == 3 &&
				 port_state_map[pgw_buffer[j]+3] == 3 &&
				 port_state_map[pgw_buffer[j]+8] == 3 &&
				 port_state_map[pgw_buffer[j]+10] == 3) && speed[pgw_buffer[j]]==SPEED_120G)
			{
				pgw_120 = TRUE;
				y5++;
				pgw120[y5] = pgw_buffer[j];
				pgw120[0] = NUM_EXT_PORTS;
				for (m=0; m<y5; m++) if (pgw120[m] == pgw_buffer[j]) y5--;
			}
		}
		else if (pgw_buffer[j] != NUM_EXT_PORTS && pgw_buffer[j] != OVS_TOKEN) TDM_ERROR2("TDM: _____ERROR: FAILURE TO LOCK PGW PORT %0d to state mapping %0d\n", pgw_buffer[j], port_state_map[pgw_buffer[j]-1]);
		/* real port is ovs_buffer[j] */
		if (ovs_buffer[j] != NUM_EXT_PORTS && port_state_map[ovs_buffer[j]-1] == 2)
		{
			/* printf("MMU bucket sort: index %0d oversubbed port %0d\n", j, ovs_buffer[j]); */
			if (port_state_map[ovs_buffer[j]] != 3 && (speed[ovs_buffer[j]]==SPEED_10G || speed[ovs_buffer[j]]==SPEED_10G_DUAL || speed[ovs_buffer[j]]==SPEED_10G_XAUI) )
			{
				ovs_10 = TRUE;
				num_ovs_10++;
				z1++;
				ovs10[z1] = ovs_buffer[j];
				/*
				ovs_10 = TRUE;
				for (y=1; y<64; y++) if (ovs10[y]==ovs_buffer[j]) microsubbed10G=TRUE;
				if (microsubbed10G==FALSE) {num_ovs_10++; z1++; ovs10[z1] = ovs_buffer[j];}
				microsubbed10G=FALSE;
				*/
			}
			else if (port_state_map[ovs_buffer[j]] != 3 && speed[ovs_buffer[j]]<SPEED_10G)
			{
				TDM_ERROR0("TDM: __________FATAL ERROR: cannot egress oversub 1G\n");
				return 0;
			}
			else if (port_state_map[ovs_buffer[j]] == 3 &&
				 port_state_map[ovs_buffer[j]+1] != 3)
			{
				ovs_20 = TRUE;
				num_ovs_20++;
				z2++;
				ovs20[z2] = ovs_buffer[j];
				ovs20[0] = NUM_EXT_PORTS;
				for (m=0; m<z2; m++) if (ovs20[m] == ovs_buffer[j]) z2--;
			}
			else if (port_state_map[ovs_buffer[j]] == 3 &&
				 port_state_map[ovs_buffer[j]+1] == 3 &&
				 port_state_map[ovs_buffer[j]+3] != 3)
			{
				ovs_40 = TRUE;
				num_ovs_40++;
				z3++;
				ovs40[z3] = ovs_buffer[j];
				ovs40[0] = NUM_EXT_PORTS;
				for (m=0; m<z3; m++) if (ovs40[m] == ovs_buffer[j]) z3--;
			}
			else if (port_state_map[ovs_buffer[j]] == 3 &&
				 port_state_map[ovs_buffer[j]+1] == 3 &&
				 port_state_map[ovs_buffer[j]+3] == 3 &&
				 port_state_map[ovs_buffer[j]+8] == 3 &&
				 port_state_map[ovs_buffer[j]+10] != 3)
			{
				ovs_100 = TRUE;
				num_ovs_100++;
				z4++;
				ovs100[z4] = ovs_buffer[j];
				ovs100[0] = NUM_EXT_PORTS;
				for (m=0; m<z4; m++) if (ovs100[m] == ovs_buffer[j]) z4--;
			}
			else if (port_state_map[ovs_buffer[j]] == 3 &&
				 port_state_map[ovs_buffer[j]+1] == 3 &&
				 port_state_map[ovs_buffer[j]+3] == 3 &&
				 port_state_map[ovs_buffer[j]+8] == 3 &&
				 port_state_map[ovs_buffer[j]+10] == 3)
			{
				ovs_120 = TRUE;
				num_ovs_120++;
				z5++;
				ovs120[z5] = ovs_buffer[j];
				ovs120[0] = NUM_EXT_PORTS;
				for (m=0; m<z5; m++) if (ovs120[m] == ovs_buffer[j]) z5--;
			}
		}
		else if (ovs_buffer[j] != NUM_EXT_PORTS) TDM_ERROR2("TDM: _____ERROR: FAILURE TO LOCK OVS PORT #%0d to state mapping %0d\n", ovs_buffer[j], port_state_map[ovs_buffer[j]-1]);
	}

	/* for (y=0; y<64; y++) printf("pgw01 index %0d has %0d\n",y,pgw01[y]); */
	
	TDM_VERBOSE7("TDM: _____VERBOSE: (1G - %0d) (10G - %0d) (20G - %0d) (40G - %0d) (100G - %0d) (120G - %0d) LR Variety - %0d\n", y0, y1, y2, y3, y4, y5, (pgw_1+pgw_10+pgw_20+pgw_40+pgw_100+pgw_120));
	if (pgw_1==TRUE)
	{
		/* no such thing as 1G single/dual mode */
		u1g/=4;
		TDM_VERBOSE1("TDM: _____VERBOSE: microsubbed 1G detected, number of TSCs is %0d\n", u1g);
		while (u1g>0)
		{
			for (j=63; j>1; j--) pgw10[j]=pgw10[j-1];
			y1++;
			pgw10[1] = U1G_TOKEN;
			u1g--;
		}
	}
	/*
	if (tsc[3][0] == MGM_TOKEN && x_pipe)
	{
		if (tsc[3][1] == MGM_TOKEN) { TDM_VERBOSE0("TDM: _____VERBOSE: management detected, 4x1G/4x2.5G style\n"); }
		else { TDM_VERBOSE0("TDM: _____VERBOSE: management detected, 1x10G style\n"); }
		for (j=63; j>1; j--) pgw10[j]=pgw10[j-1];
		y1++;
		pgw10[1] = MGM_TOKEN;
	}
	*/
	
	switch (bw)
	{
		case 960: lr_idx_limit=48; break;
		case 720: lr_idx_limit=37; break;
		case 640: lr_idx_limit=33; break;
		case 480: lr_idx_limit=25; break;
		default: lr_idx_limit=48; break;
	}
	
	/*
		100G
	*/
	if (y4 > 0)
	{
		TDM_VERBOSE0("TDM: __________VERBOSE: 100G scheduling pass\n");
		if (y4==2)
		{
			y4_loopback_style_46=TRUE;
			while (y4 > 0)
			{
				/* populate #10 harmonic with 0 offset */
				for (j=yy; j<yy+50; j+=10) 
				{
					if (mmu[j] == NUM_EXT_PORTS)
						mmu[j] = pgw100[y4];
					else
						TDM_ERROR3("TDM: _____ERROR: FAILURE TO WRITE 100G PORT #%0d at index %0d already has %0d\n", pgw100[y4], j, mmu[j]);
				}
				/* populate #10 harmonic with 6 (%6) offset */
				for (j=(yy+6); j<yy+56; j+=10) 
				{
					if (mmu[j] == NUM_EXT_PORTS)
						mmu[j] = pgw100[y4];
					else
						TDM_ERROR3("TDM: _____ERROR: FAILURE TO WRITE 100G PORT #%0d at index %0d already has %0d\n", pgw100[y4], j, mmu[j]);
				}
				/* 		for (j=yy; j<yy+50; j+=10) if (mmu[j] != NUM_EXT_PORTS) {yy++; continue;} */
				/* 		for (j=yy; j<yy+56; j+=10) if (mmu[j] != NUM_EXT_PORTS) {yy++; continue;} */
				/* 		while (mmu[yy] != NUM_EXT_PORTS || yy % 4 == 0) yy++; */
				/* 				while (mmu[yy]!=NUM_EXT_PORTS||mmu[yy+10]!=NUM_EXT_PORTS||mmu[yy+20]!=NUM_EXT_PORTS||mmu[yy+30]!=NUM_EXT_PORTS||mmu[yy+40]!=NUM_EXT_PORTS||mmu[yy+6]!=NUM_EXT_PORTS||mmu[yy+16]!=NUM_EXT_PORTS||mmu[yy+26]!=NUM_EXT_PORTS||mmu[yy+36]!=NUM_EXT_PORTS||mmu[yy+46]!=NUM_EXT_PORTS) yy++; */
				yy+=2;
				y4--;
			}
		}
		else
		{
			y4_loopback_style_54=TRUE;
			while (y4 > 0)
			{
				/* populate 5/5/5/5/4 period 48 */
				for (j=yy; j<yy+45; j+=5)
				{
					if (j==yy+25) j=(yy+24);
					if (mmu[j] == NUM_EXT_PORTS)
						mmu[j] = pgw100[y4];
					else
						TDM_ERROR3("TDM: _____ERROR: FAILURE TO WRITE 100G PORT #%0d at index %0d already has %0d\n", pgw100[y4], j, mmu[j]);
				}
				while (mmu[yy]!=NUM_EXT_PORTS||mmu[yy+5]!=NUM_EXT_PORTS||mmu[yy+10]!=NUM_EXT_PORTS||mmu[yy+15]!=NUM_EXT_PORTS||mmu[yy+20]!=NUM_EXT_PORTS||mmu[yy+24]!=NUM_EXT_PORTS||mmu[yy+29]!=NUM_EXT_PORTS||mmu[yy+34]!=NUM_EXT_PORTS||mmu[yy+39]!=NUM_EXT_PORTS||mmu[yy+44]!=NUM_EXT_PORTS) yy++;
				y4--;
			}
		}
	}

	/*
		120G
	*/
	if (y5 > 0)
	{
		TDM_VERBOSE0("TDM: __________VERBOSE: 120G scheduling pass\n");
		if (y5 == 2)
		{
			for (j=yy; j<yy+48; j+=2) if (mmu[j] != NUM_EXT_PORTS) {yy++; continue;}
			while (y5 > 0) 
			{
				for (j=yy; j<yy+48; j+=4) 
				{
					if (mmu[j] == NUM_EXT_PORTS)
						mmu[j] = pgw120[y5];
					else
						TDM_ERROR3("TDM: _____ERROR: FAILURE TO WRITE 120G #%0d PORT at index %0d already has %0d\n", pgw120[y5], j, mmu[j]);	
				}
				yy+=2; y5--;
			}
		}
		else
		{
			for (v=0; v<yy; v++)
			{
				x=0;
				for (w=v; w<v+48; w+=4) if (mmu[w] == NUM_EXT_PORTS) x++;
				if (x==12) {yy=v; break;}
			}
			while (y5 > 0) 
			{
				for (j=yy; j<yy+48; j+=4) 
				{
					if (mmu[j] == NUM_EXT_PORTS)
						mmu[j] = pgw120[y5];
					else
						TDM_ERROR3("TDM: _____ERROR: FAILURE TO WRITE 120G #%0d PORT at index %0d already has %0d\n", pgw120[y5], j, mmu[j]);	
				}
				while (mmu[yy]!=NUM_EXT_PORTS||mmu[yy+4]!=NUM_EXT_PORTS||mmu[yy+8]!=NUM_EXT_PORTS||mmu[yy+12]!=NUM_EXT_PORTS||mmu[yy+16]!=NUM_EXT_PORTS||mmu[yy+20]!=NUM_EXT_PORTS||mmu[yy+24]!=NUM_EXT_PORTS||mmu[yy+28]!=NUM_EXT_PORTS||mmu[yy+32]!=NUM_EXT_PORTS||mmu[yy+36]!=NUM_EXT_PORTS||mmu[yy+40]!=NUM_EXT_PORTS||mmu[yy+44]!=NUM_EXT_PORTS) yy++;
	/* 			for (j=yy; j<yy+48; j+=4) if (mmu[j] != NUM_EXT_PORTS) {yy++; continue;} */
		/* 		if (pgw_100==TRUE) while (mmu[yy] != NUM_EXT_PORTS) yy++; */
		/*		if (pgw_100==TRUE) while (mmu[yy] != NUM_EXT_PORTS || yy % 2 == 0) yy++; */
		/* 		else while (mmu[yy] != NUM_EXT_PORTS) yy++; */
				/* 		else while (mmu[yy] != NUM_EXT_PORTS || yy % 4 == 0) yy++; */
				y5--;
			}
		}
	}

	/*
		40G
	*/
	s3=(((12*((clk/76))))/1000);
	if (y3 > 0)
	{
		TDM_VERBOSE0("TDM: __________VERBOSE: 40G scheduling pass\n");
		TDM_VERBOSE1("TDM: _____VERBOSE: LLS MMU spacing for 40G: %ld\n", s3);
		/*
		if ( (y1==0 && y2==0 && y3==2 && ovs_40==TRUE && bw==720) ) 
		{
		TDM_WARN0("TDM: _____WARNING: applying 40G overload +1 hack\n");
		(s3)++;
	}
		*/
		/* rollback table pointer for different spacing rule */
		for (v=0; v<lr_idx_limit; v++) {x=0; for (w=v; w<v+(4*s3); w+=s3) if (mmu[w] == NUM_EXT_PORTS) x++; if (x==4) {yy=v; break;}}

			while (y3 > 0) 
			{
				/* look ahead to line rate table length */

				if ((yy+(s3*3))<lr_idx_limit)
					for (j=yy; j<yy+(4*s3); j+=s3) mmu[j] = pgw40[y3];
				else
				{
					TDM_WARN2("TDM: _____WARNING: 40G PORT #%0d at index %0d, failed to schedule, push into error buffer\n", pgw40[y3], j);
					ye++;
#if 0
					err_buffer[ye]=pgw40[y3];
					err_speeds[ye]=40;
#endif
				}

				while (mmu[yy]!=NUM_EXT_PORTS||mmu[yy+s3]!=NUM_EXT_PORTS||mmu[yy+(2*s3)]!=NUM_EXT_PORTS||mmu[yy+(3*s3)]!=NUM_EXT_PORTS) yy++;

				y3--;
			}
	}
	
	
	/*
		20G
	*/
	s2=(((24*((clk/76))))/1000);
	if (y2 > 0)
	{
		TDM_VERBOSE0("TDM: __________VERBOSE: 20G scheduling pass\n");
		/* s2=(int)((24.0*(clk/755.0))+0.5); */
		TDM_VERBOSE1("TDM: _____VERBOSE: LLS MMU spacing for 20G: %ld\n", s2);
		/* Rollback table pointer for different spacing rule */
		for (v=0; v<yy; v++) {x=0; for (w=v; w<v+(2*s2); w+=s2) if (mmu[w] == NUM_EXT_PORTS) x++; if (x==2) {yy=v; break;}}

			while (y2 > 0)
			{
				proxcheck=FAIL;
				e = 0;
				temp_20G[e] = pgw20[y2];
				y2--;
					/* search for its parent TSC */
					for (a=0; a<NUM_WC; a++) for (b=0; b<4; b++) if (tsc[a][b] == pgw20[y2+1]) c=a;
					/* retrieve all ports from bucket that originate from the same TSC */
					for (b=0; b<4; b++) if (tsc[c][b]!=temp_20G[0] && tsc[c][b]!=NUM_EXT_PORTS) for (a=1; a<(y2+1); a++) if (pgw20[a]==tsc[c][b])
					{
						d=a;
						e++;
						temp_20G[e] = tsc[c][b];
						for (f=d; f<y2; f++) pgw20[f] = pgw20[f+1];
						y2--;
					}
				b=e+1;
				limiter=65535;
				while (b>0)
				{
					for (v=0; v<lr_idx_limit-s2; v++) 
					{
						x=0; 
						for (w=v; w<v+(2*s2); w+=s2) if (mmu[w] == NUM_EXT_PORTS) x++; 
						if (x==2) 
						{
							yy=v;
							proxcheck=PASS;
							for (a=1; a<6; a++) for (jjj=0; jjj<4; jjj++) 
							{
								if (yy<lr_idx_limit-a){
									if (mmu[yy+a]!=NUM_EXT_PORTS && mmu[yy+a]==tsc[c][jjj]) proxcheck=FAIL;}
								else {
									if (mmu[(-1)+(a-(lr_idx_limit-yy-1))]!=NUM_EXT_PORTS && mmu[(-1)+(a-(lr_idx_limit-yy-1))]==tsc[c][jjj]) proxcheck=FAIL;}
								if (yy>=a) if (mmu[yy-a]!=NUM_EXT_PORTS && mmu[yy-a]==tsc[c][jjj]) proxcheck=FAIL;
								if ((yy+s2)<lr_idx_limit-a){
									if (mmu[(yy+s2)+a]!=NUM_EXT_PORTS && mmu[(yy+s2)+a]==tsc[c][jjj]) proxcheck=FAIL;}
								else {
									if (mmu[(-1)+(a-(lr_idx_limit-(yy+s2)-1))]!=NUM_EXT_PORTS && mmu[(-1)+(a-(lr_idx_limit-(yy+s2)-1))]==tsc[c][jjj]) proxcheck=FAIL; }
								if ((yy+s2)>=a) if (mmu[(yy+s2)-a]!=NUM_EXT_PORTS && mmu[(yy+s2)-a]==tsc[c][jjj]) proxcheck=FAIL;
							}
							if (proxcheck==FAIL) continue;
							else break;
						}
					}
					if (proxcheck==PASS) {for (j=yy; j<yy+(2*s2); j+=s2) mmu[j] = temp_20G[b-1]; b--;}
					limiter--;
					if (limiter==0) break;
				}
				if (b>0)
				{
					TDM_ERROR1("scheduling 20G has failed, y2 pointer is at %0d\n",y2);
					for (jjj=0; jjj<lr_idx_limit-s2; jjj++) if (mmu[jjj]==NUM_EXT_PORTS) x++;
					if (x<=1) {TDM_ERROR0("TDM for this port config has no solution\n"); return 0;}
				}

			}
	}

	/*
		10G
	*/
	if (y1 > 0)
	{
		TDM_VERBOSE0("TDM: __________VERBOSE: 10G scheduling pass\n");
		if ( pgw_120==FALSE && pgw_100==FALSE && pgw_40==FALSE && pgw_20==FALSE && pgw_1==FALSE )
		{
			overload10G = (y1/4 > 6) ? ((y1/4)-6) : 0;
			TDM_VERBOSE1("TDM: _____VERBOSE: overloaded 10G slots by +%0d\n",overload10G);
			while (y1 > 0)
			{
				proxcheck=FAIL;
				e = 0;
				temp_10G[e] = pgw10[y1];
				y1--;
				if (temp_10G[e]!=U1G_TOKEN)
				{
					for (a=0; a<NUM_WC; a++) for (b=0; b<4; b++) if (tsc[a][b] == pgw10[y1+1]) c=a;
					for (b=0; b<4; b++) if (tsc[c][b]!=temp_10G[0] && tsc[c][b]!=NUM_EXT_PORTS) for (a=1; a<(y1+1); a++) if (pgw10[a]==tsc[c][b])
					{
						d=a;
						e++;
						temp_10G[e] = tsc[c][b];
						for (f=d; f<y1; f++) pgw10[f] = pgw10[f+1];
						y1--;
					}
				}
							
				for (v=0; v<50; v++) if (mmu[v]==NUM_EXT_PORTS) {yy=v; break;}
				while (proxcheck!=PASS)
				{
					proxcheck=PASS;
					for (v=yy; v<(yy+(6+overload10G)*(e+1)); v+=(6+overload10G))
					{
						if (mmu[v]!=NUM_EXT_PORTS) proxcheck=FAIL;

					}
					if (proxcheck==FAIL) {yy++; while (mmu[yy] != NUM_EXT_PORTS) yy++;}
				}
				
				if ((yy+(e*(6+overload10G))<lr_idx_limit))
					for (a=0; a<(e+1); a++) 
					{
						if (mmu[yy] == NUM_EXT_PORTS) {
							mmu[yy] = temp_10G[a]; yy+=(6+overload10G);}
						else
							TDM_WARN3("TDM: _____WARNING: 10G PORT #%0d at index %0d, already has %0d, buffering for rescheduling\n", temp_10G[a], yy, mmu[yy]);
					}
				else
				{
					TDM_WARN2("TDM: _____WARNING: 10G PORT #%0d at index %0d, failed to schedule, push into error buffer\n", temp_10G[a], yy);
					for (a=0; a<(e+1); a++)
					{
						ye++;
#if 0
						err_speeds[ye]=10;
						err_buffer[ye]=temp_10G[a];
#endif
					}
				}
			}
		}

		else
		{
			while (y1 > 0)
			{
				proxcheck=FAIL;
				/* dequeue from pgw10 bucket */
				e = 0;
				temp_10G[e] = pgw10[y1];
				/* printf("TDM: _____VERBOSE: temp_10G index %0d is %0d from pgw10 bucket index %0d\n", e, temp_10G[e], y1); */
				y1--;
				if (temp_10G[e]!=U1G_TOKEN)
				{
					/* search for its parent TSC */
					for (a=0; a<NUM_WC; a++) for (b=0; b<4; b++) if (tsc[a][b] == pgw10[y1+1]) c=a;

				}

				b=e+1;
				limiter=65535;
				while (b>0)
				{
					for (v=0; v<lr_idx_limit; v++) if (mmu[v]==NUM_EXT_PORTS) 
					{
						yy=v;
						proxcheck=PASS;
						for (a=1; a<6; a++) for (jjj=0; jjj<4; jjj++) 
						{
							if (yy<lr_idx_limit-a){
								if (mmu[yy+a]!=NUM_EXT_PORTS && mmu[yy+a]==tsc[c][jjj]) proxcheck=FAIL;}
							else{
								if (mmu[(-1)+(a-(lr_idx_limit-yy-1))]!=NUM_EXT_PORTS && mmu[(-1)+(a-(lr_idx_limit-yy-1))]==tsc[c][jjj]) proxcheck=FAIL;}	
							if (yy>=a) if (mmu[yy-a]!=NUM_EXT_PORTS && mmu[yy-a]==tsc[c][jjj]) proxcheck=FAIL;
						}
						if (proxcheck==FAIL) continue;
						else break;
					}
					if (proxcheck==PASS) {/*printf("scheduled 10G port %0d\n",temp_10G[b-1]); */mmu[yy] = temp_10G[b-1]; b--;}
					limiter--;
					if (limiter==0) break;
				}
				if (b>0)
				{
					TDM_ERROR1("scheduling 10G has failed, y1 pointer is at %0d\n",y1);
					for (jjj=0; jjj<lr_idx_limit; jjj++) if (mmu[jjj]==NUM_EXT_PORTS) x++;
					if (x<=1) {TDM_ERROR0("TDM for this port config has no solution\n"); return 0;}
				}
	
	

			}
		}
	}

 	/* port scan for last entry */
	i=0;
	for (j=255; j>0; j--)
	{
		if (mmu[j]!=NUM_EXT_PORTS) {i=(j+1); break;}

	}
	TDM_VERBOSE1("TDM: _____VERBOSE: preprocessed MMU table terminates at index %0d\n", i);
	if (i==0) 
	{
		switch (bw)
		{
			case 960: i=48; break;
			case 720: i=37; break;
			case 640: i=32; break;
			case 480: i=24; break;
			default: i=48; break;
		}
	}
	else if (speed[mmu[i-1]]>=SPEED_20G)
	{
		/* prevent spacing violation on the loopback */
		a=-1; m=1; e=1;
		for (j=0; j<NUM_WC; j++)
		{
			for (k=0; k<4; k++)
			{
				if (tsc[j][k]==mmu[i-1]) {a=j; break;}
			}
			if (a!=-1) break;
		}
		TDM_VERBOSE1("TDM: _____VERBOSE: lookback warp core is %0d\n", a);
		/* find previous spacing */
		for (j=(i-2); j>=0; j--) 
		{
			if (mmu[j]!=tsc[a][0]&&mmu[j]!=tsc[a][1]&&mmu[j]!=tsc[a][2]&&mmu[j]!=tsc[a][3]) m++;
			else break;
		}
		TDM_VERBOSE1("TDM: _____VERBOSE: end of MMU table, previous spacing is %0d\n", m);
		/* find loopback spacing */
		for (j=0; j<i; j++) 
		{
			if (mmu[j]!=tsc[a][0]&&mmu[j]!=tsc[a][1]&&mmu[j]!=tsc[a][2]&&mmu[j]!=tsc[a][3]) e++;
			else break;
		}
		TDM_VERBOSE1("TDM: _____VERBOSE: end of MMU table, loopback spacing is %0d\n", e);
		if (pgw_100==TRUE)
		{
			if (y4_loopback_style_54==TRUE)
			{
				switch (m)
				{
					case 5: i+=(4-e); break;
					case 4: i+=(5-e); break;
				}
			}
			else if (y4_loopback_style_46==TRUE)
			{
				switch (m)
				{
					case 6: i+=(4-e); break;
					case 4: i+=(6-e); break;
				}
			}
		}
		else if (e > m) {}
		else i+=(m-e);
	}
	
	TDM_VERBOSE6("TDM: _____VERBOSE: OVS10-%0d, OVS20-%0d, OVS40-%0d, OVS100-%0d, OVS120-%0d, OVS Variety - %0d\n", ovs_10, ovs_20, ovs_40, ovs_100, ovs_120, (ovs_10 + ovs_20 + ovs_40 + ovs_100 + ovs_120));
	TDM_VERBOSE1("TDM: _____VERBOSE: postprocessed MMU table terminates at index %0d\n", i);
	
	s1=(((495*((clk/76))))/10000);
	if (pgw_10==TRUE)
	{
/* 		s1=(int)((49.5*(clk/755.0))+0.5); */
		TDM_VERBOSE1("TDM: _____VERBOSE: LLS MMU spacing for 10G: %ld\n", s1);
		if (i>s1) TDM_WARN0("TDM: _____WARNING: 10G ports underscheduled, may not satisfy line rate\n");
	}
	
	if (i>63) 
	{
		TDM_ERROR0("TDM: __________FATAL ERROR: long table causing stack overflow\n");
		return 0;
	}
	
	/* ensure line rate to TDM specs*/
	if ( (pgw_10==TRUE || pgw_1==TRUE) && (i < ((s1)-1)) ) {i = ((s1)-1); TDM_VERBOSE1("TDM: _____VERBOSE: tdm extended to slot %0d\n",i);}
	else if ( (pgw_40==TRUE) && (bw==720) && (i < 37) ) {i=37; TDM_VERBOSE1("TDM: _____VERBOSE: tdm extended to slot %0d\n",i);}
	/*{*/
		/*if ( tsc[3][0] == MGM_TOKEN && x_pipe ) i = s1;*/
		/*else*/ 
	/*}*/
	
	for (j=0; j<i; j++) if (mmu[j]==NUM_EXT_PORTS) mmu[j] = ((ovs_10 + ovs_20 + ovs_40 + ovs_100 + ovs_120)==0) ? IDL_TOKEN : OVS_TOKEN;
	/* if (ovs_variety != 0) for (j = 0; j < i; j++) if (mmu[j] == IDL_TOKEN) mmu[j] = OVS_TOKEN; */
		
	/*
	mmu[i] = (x_pipe) ? 0 : 129; i++;
	if (tsc[3][0] == MGM_TOKEN && x_pipe) i--;
	*/
	for (j=0; j<i; j++) {mmu[j+i]=mmu[j];mmu[j+(2*i)]=mmu[j];mmu[j+(3*i)]=mmu[j];}

	if (y0 > 0)
	{
		while (y0 > 0)
		{
			e = 0;
			temp_1G[e] = pgw01[y0];
			y0--;
			for (a=0; a<NUM_WC; a++) for (b=0; b<4; b++) if (tsc[a][b] == pgw01[y0+1]) c=a;
			for (b=0; b<4; b++) if (tsc[c][b]!=temp_1G[0] && tsc[c][b]!=NUM_EXT_PORTS) for (a=1; a<(y0+2); a++) if (pgw01[a]==tsc[c][b])
			{
				d=a;
				e++;
				temp_1G[e] = tsc[c][b];
				for (f=d; f<y0; f++) pgw01[f] = pgw01[f+1];
				y0--;
			}
			b=FALSE; f=0; j=0;
			for (v=0; v<64; v++)
			{
				x=0;
				for (w=v; w<=v+(e*(i)); w+=(i)) if (mmu[w] == U1G_TOKEN) x++;
				if (x==e+1) {yy=v; break;}
			}
			j=yy;
			for (a=0; a<(e+1); a++) 
			{
				if (mmu[j] == U1G_TOKEN) {
					mmu[j] = temp_1G[a]; j+=(i);}
				else
					TDM_ERROR2("TDM: _____ERROR: FAILURE TO WRITE 1G PORT at index %0d already has %0d\n", j, mmu[j]);
			}
			if (y0 > 0) while (mmu[yy] != U1G_TOKEN) yy++;
			else while (mmu[yy] != NUM_EXT_PORTS) yy++;
		}
	}

	
	for (j=1; j<=accessories; j++)
	{
		g=TDM_scheduler_PQ((((40*i)/accessories)*j))+(j-1);
		/* g=(((4*i)/accessories)*j)+(j-1); */
		for (l=255; l>g; l--) mmu[l]=mmu[l-1];
		mmu[g]=ACC_TOKEN;
	}		

	
	/* error cascade to weed out fatalities */
	if ((ovs_10 + ovs_20 + ovs_40 + ovs_100 + ovs_120) > 4)
	{
		TDM_ERROR0("TDM: _____FATAL ERROR: oversub variety limit exceeded\n");
		return 0;
	}
	if (((ovs_10 + ovs_20 + ovs_40 + ovs_100 + ovs_120)==4 && (z1>16 || z2>16)) || ((ovs_10 + ovs_20 + ovs_40 + ovs_100 + ovs_120)>=3 && (z1>32 || z2>32)) || ((ovs_10 + ovs_20 + ovs_40 + ovs_100 + ovs_120)>=2 && z1>48) || ((ovs_10 + ovs_20 + ovs_40 + ovs_100 + ovs_120)>=1 && z1>64))
	{
		TDM_ERROR0("TDM: _____FATAL ERROR: oversub bucket overflow\n");
		return 0;
	}
	
	/* dequeue from all non-empty ovs lists into buckets */
	while (z1 > 0)
	{
		while (z1>=16)
		{
			for (v=0; v<4; v++)
			{
				/* 10G and 20G need additional mutable stack to ensure no TSC splitting */
				for (i = 0; i < 4; i++) tsc_swap[i] = NUM_EXT_PORTS;
				i = 0; tsc_swap[0] = ovs10[z1]; ovs10[z1] = NUM_EXT_PORTS;
				for (a=0; a<NUM_WC; a++) for (b=0; b<4; b++) if (tsc[a][b] == tsc_swap[0]) c=a;
				for (b=0; b<4; b++) if (tsc[c][b]!=tsc_swap[0] && tsc[c][b]!=NUM_EXT_PORTS) for (a=1; a<(z1+1); a++) if (ovs10[a]==tsc[c][b])
				{
					d=a;
					i++;
					tsc_swap[i] = tsc[c][b];
					for (f=d; f<z1; f++) ovs10[f] = ovs10[f+1];
				}
				
				z1-=(1+i);
				/* dequeue into buckets subject to given constraints */
				if (z11 < 4)
				{
					for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS) bucket1[z11+(m*4)] = tsc_swap[m];
					z11++;
				}
				else if (z22 < 4)
				{
					for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS) bucket2[z22+(m*4)] = tsc_swap[m];
					z22++;
				}
				else if (z33 < 4)
				{
					for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS) bucket3[z33+(m*4)] = tsc_swap[m];
					z33++;
				}
				else if (z44 < 4)
				{
					for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS) bucket4[z44+(m*4)] = tsc_swap[m];
					z44++;
				}
			}
		}
		while (z1<16 && z1>0)
		{
			/* 10G and 20G need additional mutable stack to ensure no TSC splitting */
			for (i = 0; i < 4; i++) tsc_swap[i] = NUM_EXT_PORTS;
			i = 0; tsc_swap[0] = ovs10[z1]; ovs10[z1] = NUM_EXT_PORTS;
			for (a=0; a<NUM_WC; a++) for (b=0; b<4; b++) if (tsc[a][b] == tsc_swap[0]) c=a;
			for (b=0; b<4; b++) if (tsc[c][b]!=tsc_swap[0] && tsc[c][b]!=NUM_EXT_PORTS) for (a=1; a<(z1+1); a++) if (ovs10[a]==tsc[c][b])
			{
				d=a;
				i++;
				tsc_swap[i] = tsc[c][b];
				for (f=d; f<z1; f++) ovs10[f] = ovs10[f+1];
			}

			z1-=(1+i);
			/* dequeue into buckets subject to given constraints */
			if (z11 < 16-i && bucket1[z11]==NUM_EXT_PORTS)
			{
				for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS)
				{
					bucket1[z11] = tsc_swap[m];
					z11++;
				}
			}
			else if (z22 < 16-i && bucket2[z22]==NUM_EXT_PORTS)
			{
				for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS)
				{
					bucket2[z22] = tsc_swap[m];
					z22++;
				}
			}
			else if (z33 < 16-i && bucket3[z33]==NUM_EXT_PORTS)
			{
				for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS)
				{
					bucket3[z33] = tsc_swap[m];
					z33++;
				}
			}
			else if (z44 < 16-i && bucket4[z44]==NUM_EXT_PORTS)
			{
				for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS)
				{
					bucket4[z44] = tsc_swap[m];
					z44++;
				}
			}
		}
	}
	
	z11 = (z11>0) ? 16:0;
	z22 = (z22>0) ? 16:0;
	z33 = (z33>0) ? 16:0;
	z44 = (z44>0) ? 16:0;
	
	while (z2 > 0)
	{
		while (z2>=8)
		{
			for (v=0; v<4; v++)
			{
				/* 10G and 20G need additional mutable stack to ensure no TSC splitting */
				for (i = 0; i < 4; i++) tsc_swap[i] = NUM_EXT_PORTS;
				i = 0; tsc_swap[0] = ovs20[z2]; ovs20[z2] = NUM_EXT_PORTS;
				for (a=0; a<NUM_WC; a++) for (b=0; b<4; b++) if (tsc[a][b] == tsc_swap[0]) c=a;
				for (b=0; b<4; b++) if (tsc[c][b]!=tsc_swap[0] && tsc[c][b]!=NUM_EXT_PORTS) for (a=1; a<(z2+1); a++) if (ovs20[a]==tsc[c][b])
				{
					d=a;
					i++;
					tsc_swap[i] = tsc[c][b];
					for (f=d; f<z2; f++) ovs20[f] = ovs20[f+1];
				}

				z2-=(1+i);
				if ((3*z11) < 16-i)
				{
					for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS) bucket1[z11+(m*8)] = tsc_swap[m];
					z11++;
				}
				else if ((3*z22) < 16-i)
				{
					for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS) bucket2[z22+(m*8)] = tsc_swap[m];
					z22++;
				}
				else if ((3*z33) < 16-i)
				{
					for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS) bucket3[z33+(m*8)] = tsc_swap[m];
					z33++;
				}
				else if ((3*z44) < 16-i)
				{
					for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS) bucket4[z44+(m*8)] = tsc_swap[m];	
					z44++;
				}
			}
		}
		while (z2<8 && z2>0)
		{
			/* 10G and 20G need additional mutable stack to ensure no TSC splitting */
			for (i = 0; i < 4; i++) tsc_swap[i] = NUM_EXT_PORTS;
			i = 0; tsc_swap[0] = ovs20[z2]; ovs20[z2] = NUM_EXT_PORTS;

			for (a=0; a<NUM_WC; a++) for (b=0; b<4; b++) if (tsc[a][b] == tsc_swap[0]) c=a;
			for (b=0; b<4; b++) if (tsc[c][b]!=tsc_swap[0] && tsc[c][b]!=NUM_EXT_PORTS) for (a=1; a<(z2+1); a++) if (ovs20[a]==tsc[c][b])
			{
				d=a;
				i++;
				tsc_swap[i] = tsc[c][b];
				for (f=d; f<z2; f++) ovs20[f] = ovs20[f+1];
			}

			z2-=(1+i);
			if (z11 < 16-i)
			{
				for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS) 
				{
					bucket1[z11] = tsc_swap[m];
					z11++;
				}
			}
			else if (z22 < 16-i)
			{
				for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS)
				{
					bucket2[z22] = tsc_swap[m];
					z22++;
				}
			}
			else if (z33 < 16-i)
			{
				for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS)
				{
					bucket3[z33] = tsc_swap[m];
					z33++;
				}
			}
			else if (z44 < 16-i)
			{
				for (m = 0; m < 4; m++) if (tsc_swap[m] != NUM_EXT_PORTS)
				{
					bucket4[z44] = tsc_swap[m];
					z44++;
				}
			}
		}
	}
	z11 = (z11>0) ? 16:0;
	z22 = (z22>0) ? 16:0;
	z33 = (z33>0) ? 16:0;
	z44 = (z44>0) ? 16:0;
	while (z3 > 0)
	{
		if (z11 < 16)
		{
			bucket1[z11] = ovs40[z3];
			z11++;
			z3--;
		}
		else if (z22 < 16)
		{
			bucket2[z22] = ovs40[z3];
			z22++;
			z3--;
		}
		else if (z33 < 16)
		{
			bucket3[z33] = ovs40[z3];
			z33++;
			z3--;
		}
		/* else if (z44 < 16) */
		else
		{
			bucket4[z44] = ovs40[z3];
			z44++;
			z3--;
		}
	}
	z11 = (z11>0) ? 16:0;
	z22 = (z22>0) ? 16:0;
	z33 = (z33>0) ? 16:0;
	z44 = (z44>0) ? 16:0;
	while (z4 > 0)
	{
		if (z11 < 16)
		{
			bucket1[z11] = ovs100[z4];
			z11++;
			z4--;
		}
		else if (z22 < 16)
		{
			bucket2[z22] = ovs100[z4];
			z22++;
			z4--;
		}
		else if (z33 < 16)
		{
			bucket3[z33] = ovs100[z4];
			z33++;
			z4--;
		}
		/* else if (z44 < 16) */
		else
		{
			bucket4[z44] = ovs100[z4];
			z44++;
			z4--;
		}
	}
	z11 = (z11>0) ? 16:0;
	z22 = (z22>0) ? 16:0;
	z33 = (z33>0) ? 16:0;
	z44 = (z44>0) ? 16:0;
	while (z5 > 0)
	{
		if (z11 < 16)
		{
			bucket1[z11] = ovs120[z5];
			z11++;
			z5--;
		}
		else if (z22 < 16)
		{
			bucket2[z22] = ovs120[z5];
			z22++;
			z5--;
		}
		else if (z33 < 16)
		{
			bucket3[z33] = ovs120[z5];
			z33++;
			z5--;
		}
		/* else if (z44 < 16) */
		else
		{
			bucket4[z44] = ovs120[z5];
			z44++;
			z5--;
		}
	}
	return 1;
}


/**
@name: TDM_OVS_spacer
@param: int[32], int[32], int[128]

expands OVS table into Flexport configuration
**/
static void TDM_OVS_spacer(int wc[NUM_WC][4], int ovs_tdm_tbl[32], int ovs_spacing[32])
{
	int i, j, v=0, w=0, k=0;
	int pivot[32]; for (i=0; i<32; i++) pivot[i] = -1;
	/* spacing state machine */
	for (j=0; j<32; j++) if (ovs_tdm_tbl[j] == NUM_EXT_PORTS) k++;
	switch (k)
	{
		case 0:
			break;
		case 1:
			for (j=31; j>16; j--) ovs_tdm_tbl[j] = ovs_tdm_tbl[j-1];
			ovs_tdm_tbl[16] = NUM_EXT_PORTS;
			break;
		case 2:
			for (j=30; j>16; j--) ovs_tdm_tbl[j] = ovs_tdm_tbl[j-1];
			ovs_tdm_tbl[16] = NUM_EXT_PORTS;
			ovs_tdm_tbl[31] = NUM_EXT_PORTS;
			break;
		case 3:
			for (j=31; j>8; j--) ovs_tdm_tbl[j] = ovs_tdm_tbl[j-1];
			for (j=31; j>16; j--) ovs_tdm_tbl[j] = ovs_tdm_tbl[j-1];
			for (j=31; j>24; j--) ovs_tdm_tbl[j] = ovs_tdm_tbl[j-1];
			ovs_tdm_tbl[8] = NUM_EXT_PORTS;
			ovs_tdm_tbl[16] = NUM_EXT_PORTS;
			ovs_tdm_tbl[24] = NUM_EXT_PORTS;
			break;
		default:
			k/=4;
			/* TSC searching algorithm, expected singular result */
			for (i=0; i<NUM_WC; i++) for (j=0; j<4; j++) if (wc[i][j] == ovs_tdm_tbl[0]) w = i;
			/*. find pivot points */
			for (j=1; j<32; j++) if (ovs_tdm_tbl[j]==wc[w][0] || ovs_tdm_tbl[j]==wc[w][1] || ovs_tdm_tbl[j]==wc[w][2] || ovs_tdm_tbl[j]==wc[w][3])
			{
				pivot[v] = j;
				v++;
			}
			for (j=0; j<3; j++)
			{
				if (pivot[j]!=-1)
				{
					for (i=31; i>(pivot[j]+k-1); i--) ovs_tdm_tbl[i] = ovs_tdm_tbl[i-k];
					for (i=pivot[j]; i<(pivot[j]+k); i++) ovs_tdm_tbl[i] = NUM_EXT_PORTS;
					for (i=0; i<8; i++) if (pivot[i] != -1) pivot[i]+=k;
				}
				else break;
			}

			break;
	}
	/* populate spacing information array (to program PGW registers) */
	for (j=0; j<32; j++)
	{
		w=33; v=33;
		if (j<31) for (i=j+1; i<32; i++) if (ovs_tdm_tbl[j]==ovs_tdm_tbl[i]) {w=i-j; break;}
		if (j>0) for (k=j-1; k>=0; k--) if (ovs_tdm_tbl[j]==ovs_tdm_tbl[k]) {v=j-k; break;}
		ovs_spacing[j] = ((w <= v) ? w : v);
	}
	for (k=0; k<32; k++) 
	{
		if (ovs_spacing[k] == 33) ovs_spacing[k] = 32;
		if (ovs_tdm_tbl[k] == NUM_EXT_PORTS) ovs_spacing[k] = 32;
	}
}


/**
@name: TDM_scheduler_wrap
@param: int[][], int[32], int[32], int, int, int[128], int, int

wrapper for TDM populating function
**/
static int TDM_scheduler_wrap(int wc_array[NUM_WC][4], int speed[NUM_EXT_PORTS], int pgw_tdm_tbl[32], int ovs_tdm_tbl[32], int pgw_num, int bw, int port_state_map[128], int iter2, int stop) 
{
	int first_wc = 0;			/* the principle TSC */
	int cur_idx;			/* the current TSC */
	int pgw_tdm_idx = 0;		/* pgw tdm index */
	int ovs_tdm_idx = 0;		/* ovs tdm index */
	
	int swap_array[32];
	int i, j, z=0;
	
	int scheduler_state;
	
	for (i = 0; i < 32; i++) swap_array[i] = 0;

	switch(pgw_num) 
	{
		case 0: first_wc = 0; break;
		case 1: first_wc = 8; break;
		case 2: first_wc = 16; break;
		case 3: first_wc = 24; break;
	}
	for (j=0; j<4; j++)
	{
		cur_idx = first_wc;
		scheduler_state = TDM_scheduler(wc_array, speed, &cur_idx, &pgw_tdm_idx, &ovs_tdm_idx, j, pgw_tdm_tbl, ovs_tdm_tbl, first_wc+8, 100, bw, port_state_map, iter2, stop, swap_array, &z, j);
	}
	if (z!=0)
	{
		TDM_WARN1("TDM: _____WARNING: swap buffer not empty, index %0d, dumping all remaining entries\n", z);
		while (z!=0) {pgw_tdm_tbl[pgw_tdm_idx]=swap_array[z]; pgw_tdm_idx++; z--;}
	}
	TDM_VERBOSE0("TDM: ----------------------------------------------------------------\n");
	
	return scheduler_state;
}


/* ----------------------------------API------------------------------------- */

/**
@name: chk_tdm_tbl
@param: 

Self checks and feeds back into indicies of fail[7] the following information:

*0. TSC spacing
*1. explicit port spacing
*2. rate fidelity (average spacing)
*3. port identity (linerate, oversub, everything got scheduled, etc)
---
*4. oversub buckets (speeds, no 100G, etc)
---
*5. TSC transcription
---
*6. table corruption
---
*7. 100G ports subscribed to specific port numbers


2. oversubscription (speed buckets, no 100G/120G)
3. 100G ports are not oversubscribed
4. port transcription corruption
5. port overscheduled
(5. check CPU/loopback ports)
(6. check handling of management ports)
 **/
void bcm56850_a0_chk_tdm_tbl( int speed[NUM_EXT_PORTS], int core_bw,
		 int pgw_tdm_tbl_x0[32], int ovs_tdm_tbl_x0[32], int ovs_spacing_x0[32],
   		 int pgw_tdm_tbl_x1[32], int ovs_tdm_tbl_x1[32], int ovs_spacing_x1[32],
   		 int pgw_tdm_tbl_y0[32], int ovs_tdm_tbl_y0[32], int ovs_spacing_y0[32],
   		 int pgw_tdm_tbl_y1[32], int ovs_tdm_tbl_y1[32], int ovs_spacing_y1[32],
		 int mmu_tdm_tbl_x[256], int mmu_tdm_ovs_x_1[16], int mmu_tdm_ovs_x_2[16], int mmu_tdm_ovs_x_3[16], int mmu_tdm_ovs_x_4[16],
   		 int mmu_tdm_tbl_y[256], int mmu_tdm_ovs_y_1[16], int mmu_tdm_ovs_y_2[16], int mmu_tdm_ovs_y_3[16], int mmu_tdm_ovs_y_4[16],
      		 int port_state_map[128],
	 	 int fail[8]
		)
{
	int s1, s1xcnt=0, s1xavg=0, s1ycnt=0, s1yavg=0, s2, s2xcnt=0, s2xavg=0, s2ycnt=0, s2yavg=0, s3, s3xcnt=0, s3xavg=0, s3ycnt=0, s3yavg=0, s5=4, s5xcnt=0, s5xavg=0, s5ycnt=0, s5yavg=0, s4=5, s4xcnt=0, s4xavg=0, s4ycnt=0, s4yavg=0, t2x0=0, t2x1=0, t2y0=0, t2y1=0, t3x0=0, t3x1=0, t3y0=0, t3y1=0, t4t5=2;
	long int clk;
	int accessories;
	int wc_checker[NUM_WC][4];
	int b1x_spd, b2x_spd, b3x_spd, b4x_spd, b1y_spd, b2y_spd, b3y_spd, b4y_spd;
	int pgw_x0_len=0, pgw_x1_len=0, pgw_y0_len=0, pgw_y1_len=0, mmu_x_len=0, mmu_y_len=0;
	int msub_x0=0, msub_x1=0, msub_y0=0, msub_y1=0;
	int i, j, k, wc_principle=-1;
        TDM_ALLOC(pgw_x0_mtbl, int, 64, "pgw_x0_mtbl");
        TDM_ALLOC(pgw_x1_mtbl, int, 64, "pgw_x1_mtbl");
        TDM_ALLOC(pgw_y0_mtbl, int, 64, "pgw_y0_mtbl");
        TDM_ALLOC(pgw_y1_mtbl, int, 64, "pgw_y1_mtbl");
        TDM_ALLOC(mmu_x_mtbl, int, 512, "mmu_x_mtbl");
        TDM_ALLOC(mmu_y_mtbl, int, 512, "mmu_y_mtbl");
        TDM_ALLOC(pgw_x0_tracker, int, 130, "pgw_x0_tracker");
        TDM_ALLOC(pgw_x1_tracker, int, 130, "pgw_x1_tracker");
        TDM_ALLOC(pgw_y0_tracker, int, 130, "pgw_y0_tracker");
        TDM_ALLOC(pgw_y1_tracker, int, 130, "pgw_y1_tracker");
        TDM_ALLOC(mmu_x_tracker, int, 130, "mmu_x_tracker");
        TDM_ALLOC(mmu_y_tracker, int, 130, "mmu_y_tracker");

	TDM_VERBOSE0("TDM: ---------------------------------------------------------------------------\n");
	TDM_VERBOSE0("TDM: _____CHECKING TDM TABLES\n");

	TSC_port_transcription(wc_checker, speed, port_state_map);
	
	/*
		0. port spacing rules
	*/
	/*
		1. TSC calling proximity
	*/
	switch (core_bw)
	{
		case 960: clk=76000; accessories=8; break;
		case 720: clk=59878; accessories=10; break;
		/* case 720: clk=60833; accessories=10; break;  */
		case 640: clk=51786; accessories=8; break;
		case 480: clk=39000; accessories=10; break;
		/* case 480: clk=41563; accessories=10; break; */
		default: clk=76000; accessories=8; break;
	}
	TDM_VERBOSE3("TDM: _____VERBOSE: (clk - %0ld) (core bw - %0d) (mmu acc - %0d)\n", clk, core_bw, accessories);
	s3=(((12*((clk/76))))/1000); /*40G*/
	TDM_VERBOSE1("TDM: _____VERBOSE: calculated 40G MMU spacing as %0d\n", s3);
	s2=(((24*((clk/76))))/1000); /*20G*/
	TDM_VERBOSE1("TDM: _____VERBOSE: calculated 20G MMU spacing as %0d\n", s2);
	s1=(((495*((clk/76))))/10000); /*10G*/
	TDM_VERBOSE1("TDM: _____VERBOSE: calculated 10G MMU spacing as %0d\n", s1);
	
	/* mirror the tables */
	for (i=0; i<32; i++)
	{
		/* all tables are contiguous, unallocated slots are recycled */
		if (pgw_tdm_tbl_x0[i]!=NUM_EXT_PORTS) pgw_x0_len++;
		if (pgw_tdm_tbl_x1[i]!=NUM_EXT_PORTS) pgw_x1_len++;
		if (pgw_tdm_tbl_y0[i]!=NUM_EXT_PORTS) pgw_y0_len++;
		if (pgw_tdm_tbl_y1[i]!=NUM_EXT_PORTS) pgw_y1_len++;
	}
	TDM_VERBOSE1("TDM: _____VERBOSE: length of pgw table x0 is %0d\n", pgw_x0_len);
	TDM_VERBOSE1("TDM: _____VERBOSE: length of pgw table x1 is %0d\n", pgw_x1_len);
	TDM_VERBOSE1("TDM: _____VERBOSE: length of pgw table y0 is %0d\n", pgw_y0_len);
	TDM_VERBOSE1("TDM: _____VERBOSE: length of pgw table y1 is %0d\n", pgw_y1_len);
	
	t3x0 = (pgw_x0_len==(core_bw/40)) ? (((6*((clk/76))))/1000) : (pgw_x0_len/4);
	t3x1 = (pgw_x1_len==(core_bw/40)) ? (((6*((clk/76))))/1000) : (pgw_x1_len/4);
	t3y0 = (pgw_y0_len==(core_bw/40)) ? (((6*((clk/76))))/1000) : (pgw_y0_len/4);
	t3y1 = (pgw_y1_len==(core_bw/40)) ? (((6*((clk/76))))/1000) : (pgw_y1_len/4);
	TDM_VERBOSE4("TDM: _____VERBOSE: calculated 40G PGW spacing x0-%0d x1-%0d y0-%0d y1-%0d\n", t3x0, t3x1, t3y0, t3y1);
	t2x0 = (pgw_x0_len==(core_bw/40)) ? (((12*((clk/76))))/1000): (pgw_x0_len/2);
	t2x1 = (pgw_x1_len==(core_bw/40)) ? (((12*((clk/76))))/1000): (pgw_x1_len/2);
	t2y0 = (pgw_y0_len==(core_bw/40)) ? (((12*((clk/76))))/1000): (pgw_y0_len/2);
	t2y1 = (pgw_y1_len==(core_bw/40)) ? (((12*((clk/76))))/1000): (pgw_y1_len/2);
	TDM_VERBOSE4("TDM: _____VERBOSE: calculated 20G PGW spacing x0-%0d x1-%0d y0-%0d y1-%0d\n", t2x0, t2x1, t2y0, t2y1);
	
	for (i=0; i<256; i++)
	{
		/* all tables are contiguous, unallocated slots are recycled */
		if (mmu_tdm_tbl_x[i]!=NUM_EXT_PORTS) mmu_x_len++;
		if (mmu_tdm_tbl_y[i]!=NUM_EXT_PORTS) mmu_y_len++;
	}
	TDM_VERBOSE1("TDM: _____VERBOSE: length of mmu table x is %0d\n", mmu_x_len);
	TDM_VERBOSE1("TDM: _____VERBOSE: length of mmu table y is %0d\n", mmu_y_len);
	for (i=0; i<pgw_x0_len; i++) {pgw_x0_mtbl[i]=pgw_tdm_tbl_x0[i]; pgw_x0_mtbl[i+pgw_x0_len]=pgw_tdm_tbl_x0[i];}
	for (i=0; i<pgw_x1_len; i++) {pgw_x1_mtbl[i]=pgw_tdm_tbl_x1[i]; pgw_x1_mtbl[i+pgw_x1_len]=pgw_tdm_tbl_x1[i];}
	for (i=0; i<pgw_y0_len; i++) {pgw_y0_mtbl[i]=pgw_tdm_tbl_y0[i]; pgw_y0_mtbl[i+pgw_y0_len]=pgw_tdm_tbl_y0[i];}
	for (i=0; i<pgw_y1_len; i++) {pgw_y1_mtbl[i]=pgw_tdm_tbl_y1[i]; pgw_y1_mtbl[i+pgw_y1_len]=pgw_tdm_tbl_y1[i];}
	for (i=0; i<mmu_x_len; i++) {mmu_x_mtbl[i]=mmu_tdm_tbl_x[i]; mmu_x_mtbl[i+mmu_x_len]=mmu_tdm_tbl_x[i];}
	for (i=0; i<mmu_y_len; i++) {mmu_y_mtbl[i]=mmu_tdm_tbl_y[i]; mmu_y_mtbl[i+mmu_y_len]=mmu_tdm_tbl_y[i];}
	
	for (i=0; i<32; i++) {if (port_state_map[i] == 1) {if (port_state_map[i+1] != 3) {if (speed[i+1]<SPEED_10G) msub_x0++;}}}
	for (i=32; i<64; i++) {if (port_state_map[i] == 1) {if (port_state_map[i+1] != 3) {if (speed[i+1]<SPEED_10G) msub_x1++;}}}
	for (i=64; i<96; i++) {if (port_state_map[i] == 1) {if (port_state_map[i+1] != 3) {if (speed[i+1]<SPEED_10G) msub_y0++;}}}
	for (i=96; i<128; i++) {if (port_state_map[i] == 1) {if (port_state_map[i+1] != 3) {if (speed[i+1]<SPEED_10G) msub_y1++;}}}
	if (msub_x0!=0) for (i=0; i<32; i++) {if (port_state_map[i] == 1) {if (port_state_map[i+1] != 3) {if (speed[i+1]>=SPEED_10G) msub_x0+=10;}}}
	if (msub_x1!=0) for (i=32; i<64; i++) {if (port_state_map[i] == 1) {if (port_state_map[i+1] != 3) {if (speed[i+1]>=SPEED_10G) msub_x1+=10;}}}
	if (msub_y0!=0) for (i=64; i<96; i++) {if (port_state_map[i] == 1) {if (port_state_map[i+1] != 3) {if (speed[i+1]>=SPEED_10G) msub_y0+=10;}}}
	if (msub_y1!=0) for (i=96; i<128; i++) {if (port_state_map[i] == 1) {if (port_state_map[i+1] != 3) {if (speed[i+1]>=SPEED_10G) msub_y1+=10;}}}
	
	/* check length (overflow and symmetry) */
	if (msub_x0==0 && msub_x1==0 && msub_y0==0 && msub_y1==0)
	{
		switch (core_bw)
		{
			case 960:
				if (pgw_x0_len>24 || pgw_x1_len>24 || pgw_y0_len>24 || pgw_y1_len>24) {fail[6]=1; TDM_ERROR0("TDM: _____FATAL ERROR: PGW table overscheduled\n");}
				if (pgw_x0_len!=pgw_x1_len || pgw_y0_len!=pgw_y1_len) {/*fail[6]=1; */TDM_WARN0("TDM: _____WARNING: PGW table asymmetry on symmetrically subscribed core bw\n");}
				if (mmu_x_len>200 || mmu_y_len>200) {fail[6]=1; TDM_ERROR0("TDM: _____FATAL ERROR: MMU table overscheduled\n");}
				break;
			case 720:
				if (pgw_x0_len>16 || pgw_y1_len>16) {fail[6]=1; TDM_ERROR0("TDM: _____FATAL ERROR: PGW table short quadrant overscheduled\n");}
				if (pgw_x1_len>20 || pgw_y0_len>20) {fail[6]=1; TDM_ERROR0("TDM: _____FATAL ERROR: PGW table long quadrant overscheduled\n");}
				if (mmu_x_len>160 || mmu_y_len>160) {fail[6]=1; TDM_ERROR0("TDM: _____FATAL ERROR: MMU table overscheduled\n");}
				break;
			case 640:
				if (pgw_x0_len>16 || pgw_x1_len>16 || pgw_y0_len>16 || pgw_y1_len>16) {fail[6]=1; TDM_ERROR0("TDM: _____FATAL ERROR: PGW table overscheduled\n");}
				if (pgw_x0_len!=pgw_x1_len || pgw_y0_len!=pgw_y1_len) {/*fail[6]=1; */TDM_WARN0("TDM: _____WARNING: PGW table asymmetry on symmetrically subscribed core bw\n");}
				if (mmu_x_len>136 || mmu_y_len>136) {fail[6]=1; TDM_ERROR0("TDM: _____FATAL ERROR: MMU table overscheduled\n");}
				break;
			case 480:
				if (pgw_x0_len>12 || pgw_x1_len>12 || pgw_y0_len>12 || pgw_y1_len>12) {fail[6]=1; TDM_ERROR0("TDM: _____FATAL ERROR: PGW table overscheduled\n");}
				if (pgw_x0_len!=pgw_x1_len || pgw_y0_len!=pgw_y1_len) {/*fail[6]=1; */TDM_WARN0("TDM: _____WARNING: PGW table asymmetry on symmetrically subscribed core bw\n");}
				if (mmu_x_len>106 || mmu_y_len>106) {fail[6]=1; TDM_ERROR0("TDM: _____FATAL ERROR: MMU table overscheduled\n");}
				break;
			default: break;
		}
	}
	
	/* init bitmaps */
	for (i=0; i<130; i++) {pgw_x0_tracker[i]=0; pgw_x1_tracker[i]=0; pgw_y0_tracker[i]=0; pgw_y1_tracker[i]=0; mmu_x_tracker[i]=0; mmu_y_tracker[i]=0;}
	
	/* check pgw tables */
	/* length and loopback passes are implicitly combined */
	for (i=0; i<pgw_x0_len; i++)
	{
		TOKEN_CHECK(pgw_x0_mtbl[i])
		{
			pgw_x0_tracker[pgw_x0_mtbl[i]]=1;
			for (j=0; j<NUM_WC; j++)
			{
				for (k=0; k<4; k++) {if (wc_checker[j][k] == pgw_x0_mtbl[i]) {wc_principle = j; break;}}
				if (wc_principle != -1) break;
			}
			if (wc_principle == -1) {fail[5] = 1; TDM_ERROR1("TDM: _____FATAL ERROR: TSC transcription corruption pgw quadrant x0 port %0d\n", pgw_x0_mtbl[i]);}
			if (pgw_x0_len>8) if (pgw_x0_mtbl[i+1]==wc_checker[wc_principle][0] || pgw_x0_mtbl[i+1]==wc_checker[wc_principle][1] || pgw_x0_mtbl[i+1]==wc_checker[wc_principle][2] || pgw_x0_mtbl[i+1]==wc_checker[wc_principle][3]) {fail[0]=1; TDM_ERROR2("TDM: _____FATAL ERROR: TSC proximity violation at pgw x0 between index %0d and index %0d\n", i, (i+1));}
			for (j=1; j<=pgw_x0_len; j++) {if (pgw_x0_mtbl[i+j]!=pgw_x0_mtbl[i]) pgw_x0_tracker[pgw_x0_mtbl[i]]++; else break;}
			wc_principle=-1;
		}
	}
	for (i=0; i<pgw_x1_len; i++)
	{
		TOKEN_CHECK(pgw_x1_mtbl[i])
		{
			pgw_x1_tracker[pgw_x1_mtbl[i]]=1;
			for (j=0; j<NUM_WC; j++)
			{
				for (k=0; k<4; k++) {if (wc_checker[j][k] == pgw_x1_mtbl[i]) {wc_principle = j; break;}}
				if (wc_principle != -1) break;
			}
			if (wc_principle == -1) {fail[5] = 1; TDM_ERROR1("TDM: _____FATAL ERROR: TSC transcription corruption pgw quadrant x1 port %0d\n", pgw_x1_mtbl[i]);}
			if (pgw_x1_len>8) if (pgw_x1_mtbl[i+1]==wc_checker[wc_principle][0] || pgw_x1_mtbl[i+1]==wc_checker[wc_principle][1] || pgw_x1_mtbl[i+1]==wc_checker[wc_principle][2] || pgw_x1_mtbl[i+1]==wc_checker[wc_principle][3]) {fail[0]=1; TDM_ERROR2("TDM: _____FATAL ERROR: TSC proximity violation at pgw x1 between index %0d and index %0d\n", i, (i+1));}
			for (j=1; j<=pgw_x1_len; j++) {if (pgw_x1_mtbl[i+j]!=pgw_x1_mtbl[i]) pgw_x1_tracker[pgw_x1_mtbl[i]]++; else break;}
			wc_principle=-1;
		}
	}
	for (i=0; i<pgw_y0_len; i++)
	{
		TOKEN_CHECK(pgw_y0_mtbl[i])
		{
			pgw_y0_tracker[pgw_y0_mtbl[i]]=1;
			for (j=0; j<NUM_WC; j++)
			{
				for (k=0; k<4; k++) {if (wc_checker[j][k] == pgw_y0_mtbl[i]) {wc_principle = j; break;}}
				if (wc_principle != -1) break;
			}
			if (wc_principle == -1) {fail[5] = 1; TDM_ERROR1("TDM: _____FATAL ERROR: TSC transcription corruption pgw quadrant y0 port %0d\n", pgw_y0_mtbl[i]);}
			if (pgw_y0_len>8) if (pgw_y0_mtbl[i+1]==wc_checker[wc_principle][0] || pgw_y0_mtbl[i+1]==wc_checker[wc_principle][1] || pgw_y0_mtbl[i+1]==wc_checker[wc_principle][2] || pgw_y0_mtbl[i+1]==wc_checker[wc_principle][3]) {fail[0]=1; TDM_ERROR2("TDM: _____FATAL ERROR: TSC proximity violation at pgw y0 between index %0d and index %0d\n", i, (i+1));}
			for (j=1; j<=pgw_y0_len; j++) {if (pgw_y0_mtbl[i+j]!=pgw_y0_mtbl[i]) pgw_y0_tracker[pgw_y0_mtbl[i]]++; else break;}
			wc_principle=-1;
		}
	}
	for (i=0; i<pgw_y1_len; i++)
	{
		TOKEN_CHECK(pgw_y1_mtbl[i])
		{
			pgw_y1_tracker[pgw_y1_mtbl[i]]=1;
			for (j=0; j<NUM_WC; j++)
			{
				for (k=0; k<4; k++) {if (wc_checker[j][k] == pgw_y1_mtbl[i]) {wc_principle = j; break;}}
				if (wc_principle != -1) break;
			}
			if (wc_principle == -1) {fail[5] = 1; TDM_ERROR1("TDM: _____FATAL ERROR: TSC transcription corruption pgw quadrant y1 port %0d\n", pgw_y1_mtbl[i]);}
			if (pgw_y1_len>8) if (pgw_y1_mtbl[i+1]==wc_checker[wc_principle][0] || pgw_y1_mtbl[i+1]==wc_checker[wc_principle][1] || pgw_y1_mtbl[i+1]==wc_checker[wc_principle][2] || pgw_y1_mtbl[i+1]==wc_checker[wc_principle][3]) {fail[0]=1; TDM_ERROR2("TDM: _____FATAL ERROR: TSC proximity violation at pgw y1 between index %0d and index %0d\n", i, (i+1));}
			for (j=1; j<=pgw_y1_len; j++) {if (pgw_y1_mtbl[i+j]!=pgw_y1_mtbl[i]) pgw_y1_tracker[pgw_y1_mtbl[i]]++; else break;}
			wc_principle=-1;
		}
	}
	for (i=0; i<mmu_x_len; i++)
	{
		TOKEN_CHECK(mmu_x_mtbl[i])
		{
			mmu_x_tracker[mmu_x_mtbl[i]]=1;
			for (j=0; j<NUM_WC; j++)
			{
				for (k=0; k<4; k++) {if (wc_checker[j][k] == mmu_x_mtbl[i]) {wc_principle = j; break;}}
				if (wc_principle != -1) break;
			}
			if (wc_principle == -1) {fail[5] = 1; TDM_ERROR2("TDM: _____FATAL ERROR: TSC transcription corruption mmu pipe x port %0d index %0d\n", mmu_x_mtbl[i], i);}
			if (speed[mmu_x_mtbl[i]]!=SPEED_100G && speed[mmu_x_mtbl[i]]!=SPEED_120G) for (j=1; j<6; j++) if (mmu_x_mtbl[i+j]==wc_checker[wc_principle][0] || mmu_x_mtbl[i+j]==wc_checker[wc_principle][1] || mmu_x_mtbl[i+j]==wc_checker[wc_principle][2] || mmu_x_mtbl[i+j]==wc_checker[wc_principle][3]) {fail[0]=1; TDM_ERROR2("TDM: _____FATAL ERROR: TSC proximity violation at mmu x between index %0d and index %0d\n", i, (i+j));}
			for (j=1; j<=mmu_x_len; j++) {if (mmu_x_mtbl[i+j]!=mmu_x_mtbl[i]) mmu_x_tracker[mmu_x_mtbl[i]]++; else break;}
			wc_principle=-1;
		}
	}
	for (i=0; i<mmu_y_len; i++)
	{
		TOKEN_CHECK(mmu_y_mtbl[i])
		{
			mmu_y_tracker[mmu_y_mtbl[i]]=1;
			for (j=0; j<NUM_WC; j++)
			{
				for (k=0; k<4; k++) {if (wc_checker[j][k] == mmu_y_mtbl[i]) {wc_principle = j; break;}}
				if (wc_principle != -1) break;
			}
			if (wc_principle == -1) {fail[5] = 1; TDM_ERROR2("TDM: _____FATAL ERROR: TSC transcription corruption mmu pipe y port %0d index %0d\n", mmu_y_mtbl[i],i);}
			if (speed[mmu_y_mtbl[i]]!=SPEED_100G && speed[mmu_y_mtbl[i]]!=SPEED_120G) for (j=1; j<6; j++) if (mmu_y_mtbl[i+j]==wc_checker[wc_principle][0] || mmu_y_mtbl[i+j]==wc_checker[wc_principle][1] || mmu_y_mtbl[i+j]==wc_checker[wc_principle][2] || mmu_y_mtbl[i+j]==wc_checker[wc_principle][3]) {fail[0]=1; TDM_ERROR2("TDM: _____FATAL ERROR: TSC proximity violation at mmu y between index %0d and index %0d\n", i, (i+j));}
			for (j=1; j<=mmu_y_len; j++) {if (mmu_y_mtbl[i+j]!=mmu_y_mtbl[i]) mmu_x_tracker[mmu_y_mtbl[i]]++; else break;}
			wc_principle=-1;
		}
	}
	
	for (i=1; i<=32; i++)
	{
		if (pgw_x0_tracker[i]!=0)
		{
			switch (speed[i])
			{
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					if (pgw_x0_tracker[i] < t2x0-4 || pgw_x0_tracker[i] > t2x0+4) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 20G port spacing error pgw x0 port %0d (%0d)\n", i,pgw_x0_tracker[i]);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					if (pgw_x0_tracker[i] < t3x0-4 || pgw_x0_tracker[i] > t3x0+4) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 40G port spacing error pgw x0 port %0d (%0d)\n", i,pgw_x0_tracker[i]);}
					break;
				case SPEED_120G:
				case SPEED_100G:
					if (pgw_x0_tracker[i] < t4t5 || pgw_x0_tracker[i] > t4t5+1) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 100G/120G port spacing error pgw x0 port %0d (%0d)\n", i,pgw_x0_tracker[i]);}
					break;
				default:
					/* 10G/1G spacing is implicitly checked by both the TSC spacing and the spacing of all other speeds */ 
					break;
			}
		}
	}
	for (i=33; i<=64; i++)
	{
		if (pgw_x1_tracker[i]!=0)
		{
			switch (speed[i])
			{
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					if (pgw_x1_tracker[i] < t2x1-4 || pgw_x1_tracker[i] > t2x1+4) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 20G port spacing error pgw x1 port %0d (%0d)\n", i,pgw_x1_tracker[i]);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					if (pgw_x1_tracker[i] < t3x1-4 || pgw_x1_tracker[i] > t3x1+4) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 40G port spacing error pgw x1 port %0d (%0d)\n", i,pgw_x1_tracker[i]);}
					break;
				case SPEED_120G:
				case SPEED_100G:
					if (pgw_x1_tracker[i] < t4t5 || pgw_x1_tracker[i] > t4t5+1) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 100G/120G port spacing error pgw x1 port %0d (%0d)\n", i,pgw_x1_tracker[i]);}
					break;
				default:
					/* 10G/1G spacing is implicitly checked by both the TSC spacing and the spacing of all other speeds */ 
					break;
			}
		}
	}
	for (i=65; i<=96; i++)
	{
		if (pgw_y0_tracker[i]!=0)
		{
			switch (speed[i])
			{
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					if (pgw_y0_tracker[i] < t2y0-4 || pgw_y0_tracker[i] > t2y0+4) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 20G port spacing error pgw y0 port %0d (%0d)\n", i,pgw_y0_tracker[i]);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					if (pgw_y0_tracker[i] < t3y0-4 || pgw_y0_tracker[i] > t3y0+4) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 40G port spacing error pgw y0 port %0d (%0d)\n", i,pgw_y0_tracker[i]);}
					break;
				case SPEED_120G:
				case SPEED_100G:
					if (pgw_y0_tracker[i] < t4t5 || pgw_y0_tracker[i] > t4t5+1) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 100G/120G port spacing error pgw y0 port %0d (%0d)\n", i,pgw_y0_tracker[i]);}
					break;
				default:
					/* 10G/1G spacing is implicitly checked by both the TSC spacing and the spacing of all other speeds */ 
					break;
			}
		}
	}
	for (i=97; i<=128; i++)
	{	
		if (pgw_y1_tracker[i]!=0)
		{
			switch (speed[i])
			{
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					if (pgw_y1_tracker[i] < t2y1-4 || pgw_y1_tracker[i] > t2y1+4) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 20G port spacing error pgw y1 port %0d (%0d)\n", i,pgw_y1_tracker[i]);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					if (pgw_y1_tracker[i] < t3y1-4 || pgw_y1_tracker[i] > t3y1+4) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 40G port spacing error pgw y1 port %0d (%0d)\n", i,pgw_y1_tracker[i]);}
					break;
				case SPEED_120G:
				case SPEED_100G:
					if (pgw_y1_tracker[i] < t4t5 || pgw_y1_tracker[i] > t4t5+1) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 100G/120G port spacing error pgw y1 port %0d (%0d)\n", i,pgw_y1_tracker[i]);}
					break;
				default:
					/* 10G/1G spacing is implicitly checked by both the TSC spacing and the spacing of all other speeds */ 
					break;
			}
		}
	}
	for (i=1; i<=12; i++)
	{
		if (mmu_x_tracker[i]!=0 && mmu_x_tracker[i]!=1)
		{
			switch (speed[i])
			{
				case SPEED_10G:
					s1xcnt++;
					s1xavg+=mmu_x_tracker[i];
					if (mmu_x_tracker[i] < s1-3 || mmu_x_tracker[i] > s1+3) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 10G port spacing error mmu x pipe port %0d (spacing = %0d)\n", i,mmu_x_tracker[i]);}
					break;
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					s2xcnt++;
					s2xavg+=mmu_x_tracker[i];
					if (mmu_x_tracker[i] < s2-2 || mmu_x_tracker[i] > s2+2) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 20G port spacing error mmu x pipe port %0d (spacing = %0d)\n", i,mmu_x_tracker[i]);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					s3xcnt++;
					s3xavg+=mmu_x_tracker[i];
					if (mmu_x_tracker[i] < s3-2 || mmu_x_tracker[i] > s3+2) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 40G port spacing error mmu x pipe port %0d (spacing = %0d)\n", i,mmu_x_tracker[i]);}
					break;
				case SPEED_120G:
					s5xcnt++;
					s5xavg+=mmu_x_tracker[i];
					if (mmu_x_tracker[i] < s4 || mmu_x_tracker[i] > s5+1) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 120G port spacing error mmu x pipe port %0d (spacing = %0d)\n", i,mmu_x_tracker[i]);}
					break;
				case SPEED_100G:
					s4xcnt++;
					s4xavg+=mmu_x_tracker[i];
					if (mmu_x_tracker[i] < s4 || mmu_x_tracker[i] > s5+1) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 100G port spacing error mmu x pipe port %0d (spacing = %0d)\n", i,mmu_x_tracker[i]);}
					break;
				default:
					break;
			}
		}
	}
	for (i=17; i<=64; i++)
	{
		if (mmu_x_tracker[i]!=0 && mmu_x_tracker[i]!=1)
		{
			switch (speed[i])
			{
				case SPEED_10G:
					s1xcnt++;
					s1xavg+=mmu_x_tracker[i];
					if (mmu_x_tracker[i] < s1-3 || mmu_x_tracker[i] > s1+3) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 10G port spacing error mmu x pipe port %0d (spacing = %0d)\n", i,mmu_x_tracker[i]);}
					break;
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					s2xcnt++;
					s2xavg+=mmu_x_tracker[i];
					if (mmu_x_tracker[i] < s2-2 || mmu_x_tracker[i] > s2+2) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 20G port spacing error mmu x pipe port %0d (spacing = %0d)\n", i,mmu_x_tracker[i]);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					s3xcnt++;
					s3xavg+=mmu_x_tracker[i];
					if (mmu_x_tracker[i] < s3-2 || mmu_x_tracker[i] > s3+2) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 40G port spacing error mmu x pipe port %0d (spacing = %0d)\n", i,mmu_x_tracker[i]);}
					break;
				case SPEED_120G:
					s5xcnt++;
					s5xavg+=mmu_x_tracker[i];
					if (mmu_x_tracker[i] < s4 || mmu_x_tracker[i] > s5+1) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 120G port spacing error mmu x pipe port %0d (spacing = %0d)\n", i,mmu_x_tracker[i]);}
					break;
				case SPEED_100G:
					s4xcnt++;
					s4xavg+=mmu_x_tracker[i];
					if (mmu_x_tracker[i] < s4 || mmu_x_tracker[i] > s5+1) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 100G port spacing error mmu x pipe port %0d (spacing = %0d)\n", i,mmu_x_tracker[i]);}
					break;
				default:
					break;
			}
		}
	}
	for (i=65; i<=128; i++)
	{
		if (mmu_y_tracker[i]!=0 && mmu_y_tracker[i]!=1)
		{
			switch (speed[i])
			{
				case SPEED_10G:
					s1ycnt++;
					s1yavg+=mmu_y_tracker[i];
					if (mmu_y_tracker[i] < s1-3 || mmu_y_tracker[i] > s1+3) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 10G port spacing error mmu y pipe port %0d (spacing = %0d)\n", i,mmu_y_tracker[i]);}
					break;
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					s2ycnt++;
					s2yavg+=mmu_y_tracker[i];
					if (mmu_y_tracker[i] < s2-2 || mmu_y_tracker[i] > s2+2) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 20G port spacing error mmu y pipe port %0d (spacing = %0d)\n", i,mmu_y_tracker[i]);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					s3ycnt++;
					s3yavg+=mmu_y_tracker[i];
					if (mmu_y_tracker[i] < s3-2 || mmu_y_tracker[i] > s3+2) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 40G port spacing error mmu y pipe port %0d (spacing = %0d)\n", i,mmu_y_tracker[i]);}
					break;
				case SPEED_120G:
					s5ycnt++;
					s5yavg+=mmu_y_tracker[i];
					if (mmu_y_tracker[i] < s4 || mmu_y_tracker[i] > s5+1) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 120G port spacing error mmu y pipe port %0d (spacing = %0d)\n", i,mmu_y_tracker[i]);}
					break;
				case SPEED_100G:
					s4ycnt++;
					s4yavg+=mmu_y_tracker[i];
					if (mmu_y_tracker[i] < s4 || mmu_y_tracker[i] > s5+1) {fail[1]=1; TDM_ERROR2("TDM: _____ERROR: 100G port spacing error mmu y pipe port %0d (spacing = %0d)\n", i,mmu_y_tracker[i]);}
					break;
				default:
					break;
			}
		}
	}
	s1xavg = (s1xcnt==0) ? 0 : ((s1xavg*100)/s1xcnt);
	s2xavg = (s2xcnt==0) ? 0 : ((s2xavg*100)/s2xcnt);
	s3xavg = (s3xcnt==0) ? 0 : ((s3xavg*100)/s3xcnt);
	s4xavg = (s4xcnt==0) ? 0 : ((s4xavg*100)/s4xcnt);
	s5xavg = (s5xcnt==0) ? 0 : ((s5xavg*100)/s5xcnt);
	s1yavg = (s1ycnt==0) ? 0 : ((s1yavg*100)/s1ycnt);
	s2yavg = (s2ycnt==0) ? 0 : ((s2yavg*100)/s2ycnt);
	s3yavg = (s3ycnt==0) ? 0 : ((s3yavg*100)/s3ycnt);
	s4yavg = (s4ycnt==0) ? 0 : ((s4yavg*100)/s4ycnt);
	s5yavg = (s5ycnt==0) ? 0 : ((s5yavg*100)/s5ycnt);
	if (s1xavg>0) if ( (s1xavg > (s1*101) || s1xavg < (s1*99)) ) {fail[2]=1; TDM_WARN1("TDM: _____WARNING: 10G line rate not within 1 percent tolerance in x pipe, (s1xavg = %0d)\n", s1xavg);}
	if (s1yavg>0) if ( (s1yavg > (s1*101) || s1yavg < (s1*99)) ) {fail[2]=1; TDM_WARN1("TDM: _____WARNING: 10G line rate not within 1 percent tolerance in y pipe, (s1yavg = %0d)\n", s1yavg);}
	if (s2xavg>0) if ( (s2xavg > (s1*101) || s2xavg < (s1*99)) ) {fail[2]=1; TDM_WARN1("TDM: _____WARNING: 20G line rate not within 1 percent tolerance in x pipe, (s2xavg = %0d)\n", s2xavg);}
	if (s2yavg>0) if ( (s2yavg > (s1*101) || s2yavg < (s1*99)) ) {fail[2]=1; TDM_WARN1("TDM: _____WARNING: 20G line rate not within 1 percent tolerance in y pipe, (s2yavg = %0d)\n", s2yavg);}
	if (s3xavg>0) if ( (s3xavg > (s1*101) || s3xavg < (s1*99)) ) {fail[2]=1; TDM_WARN1("TDM: _____WARNING: 40G line rate not within 1 percent tolerance in x pipe, (s3xavg = %0d)\n", s3xavg);}
	if (s3yavg>0) if ( (s3yavg > (s1*101) || s3yavg < (s1*99)) ) {fail[2]=1; TDM_WARN1("TDM: _____WARNING: 40G line rate not within 1 percent tolerance in y pipe, (s3yavg = %0d)\n", s3yavg);}
	if (s4xavg>0) if ( (s4xavg > (s1*101) || s4xavg < (s1*99)) ) {fail[2]=1; TDM_WARN1("TDM: _____WARNING: 100G line rate not within 1 percent tolerance in x pipe, (s4xavg = %0d)\n", s4xavg);}
	if (s4yavg>0) if ( (s4yavg > (s1*101) || s4yavg < (s1*99)) ) {fail[2]=1; TDM_WARN1("TDM: _____WARNING: 100G line rate not within 1 percent tolerance in y pipe, (s4yavg = %0d)\n", s4yavg);}
	if (s5xavg>0) if ( (s5xavg > (s1*101) || s5xavg < (s1*99)) ) {fail[2]=1; TDM_WARN1("TDM: _____WARNING: 120G line rate not within 1 percent tolerance in x pipe, (s5xavg = %0d)\n", s5xavg);}
	if (s5yavg>0) if ( (s5yavg > (s1*101) || s5yavg < (s1*99)) ) {fail[2]=1; TDM_WARN1("TDM: _____WARNING: 120G line rate not within 1 percent tolerance in y pipe, (s5yavg = %0d)\n", s5yavg);}
	
	/*
		7. 100G ports
	*/
		for (i=1; i<129; i++)
		{
			if (speed[i]==SPEED_100G || speed[i]==SPEED_120G)
			{
				if (i!=1 && i!=21 && i!=33 && i!=53 && i!=65 && i!=85 && i!=97 && i!=117) {fail[7]=1; TDM_ERROR1("TDM: _____ERROR: port number %0d is a 100G port that is improperly subscribed\n",i);
			}
		}
	
	/*
		4. oversub
	*/
	    	b1x_spd=(mmu_tdm_ovs_x_1[0]==130) ? (-1) : speed[mmu_tdm_ovs_x_1[0]],
		b2x_spd=(mmu_tdm_ovs_x_2[0]==130) ? (-1) : speed[mmu_tdm_ovs_x_2[0]],
		b3x_spd=(mmu_tdm_ovs_x_3[0]==130) ? (-1) : speed[mmu_tdm_ovs_x_3[0]],
		b4x_spd=(mmu_tdm_ovs_x_4[0]==130) ? (-1) : speed[mmu_tdm_ovs_x_4[0]],
		b1y_spd=(mmu_tdm_ovs_y_1[0]==130) ? (-1) : speed[mmu_tdm_ovs_y_1[0]],
		b2y_spd=(mmu_tdm_ovs_y_2[0]==130) ? (-1) : speed[mmu_tdm_ovs_y_2[0]],
		b3y_spd=(mmu_tdm_ovs_y_3[0]==130) ? (-1) : speed[mmu_tdm_ovs_y_3[0]],
		b4y_spd=(mmu_tdm_ovs_y_4[0]==130) ? (-1) : speed[mmu_tdm_ovs_y_4[0]];
		if (b1x_spd==SPEED_100G || b1x_spd==SPEED_120G ||
		    b2x_spd==SPEED_100G || b2x_spd==SPEED_120G ||
		    b3x_spd==SPEED_100G || b3x_spd==SPEED_120G ||
		    b4x_spd==SPEED_100G || b4x_spd==SPEED_120G ||
		    b1y_spd==SPEED_100G || b1y_spd==SPEED_120G ||
		    b2y_spd==SPEED_100G || b2y_spd==SPEED_120G ||
		    b3y_spd==SPEED_100G || b3y_spd==SPEED_120G ||
		    b4y_spd==SPEED_100G || b4y_spd==SPEED_120G) fail[4]=1;
	TDM_VERBOSE8("TDM: _____VERBOSE: oversub bucket speeds (x1-%0d)(x2-%0d)(x3-%0d)(x4-%0d)(y1-%0d)(y2-%0d)(y3-%0d)(y4-%0d)\n",(b1x_spd==-1)?0:b1x_spd,(b2x_spd==-1)?0:b2x_spd,(b3x_spd==-1)?0:b3x_spd,(b4x_spd==-1)?0:b4x_spd,(b1y_spd==-1)?0:b1y_spd,(b2y_spd==-1)?0:b2y_spd,(b3y_spd==-1)?0:b3y_spd,(b4y_spd==-1)?0:b4y_spd);
	for (i=1; i<16; i++)
	{
		if (mmu_tdm_ovs_x_1[i]!=NUM_EXT_PORTS) if (speed[mmu_tdm_ovs_x_1[i]]>(b1x_spd+1010) || speed[mmu_tdm_ovs_x_1[i]]<(b1x_spd-1010)) {fail[4]=1; TDM_ERROR1("TDM: _____ERROR: x1 bucket slot #%0d\n",i);}
		if (mmu_tdm_ovs_x_2[i]!=NUM_EXT_PORTS) if (speed[mmu_tdm_ovs_x_2[i]]>(b2x_spd+1010) || speed[mmu_tdm_ovs_x_2[i]]<(b2x_spd-1010)) {fail[4]=1; TDM_ERROR1("TDM: _____ERROR: x2 bucket slot #%0d\n",i);}
		if (mmu_tdm_ovs_x_3[i]!=NUM_EXT_PORTS) if (speed[mmu_tdm_ovs_x_3[i]]>(b3x_spd+1010) || speed[mmu_tdm_ovs_x_3[i]]<(b3x_spd-1010)) {fail[4]=1; TDM_ERROR1("TDM: _____ERROR: x3 bucket slot #%0d\n",i);}
		if (mmu_tdm_ovs_x_4[i]!=NUM_EXT_PORTS) if (speed[mmu_tdm_ovs_x_4[i]]>(b4x_spd+1010) || speed[mmu_tdm_ovs_x_4[i]]<(b4x_spd-1010)) {fail[4]=1; TDM_ERROR1("TDM: _____ERROR: x4 bucket slot #%0d\n",i);}
		if (mmu_tdm_ovs_y_1[i]!=NUM_EXT_PORTS) if (speed[mmu_tdm_ovs_y_1[i]]>(b1y_spd+1010) || speed[mmu_tdm_ovs_y_1[i]]<(b1y_spd-1010)) {fail[4]=1; TDM_ERROR1("TDM: _____ERROR: y1 bucket slot #%0d\n",i);}
		if (mmu_tdm_ovs_y_2[i]!=NUM_EXT_PORTS) if (speed[mmu_tdm_ovs_y_2[i]]>(b2y_spd+1010) || speed[mmu_tdm_ovs_y_2[i]]<(b2y_spd-1010)) {fail[4]=1; TDM_ERROR1("TDM: _____ERROR: y2 bucket slot #%0d\n",i);}
		if (mmu_tdm_ovs_y_3[i]!=NUM_EXT_PORTS) if (speed[mmu_tdm_ovs_y_3[i]]>(b3y_spd+1010) || speed[mmu_tdm_ovs_y_3[i]]<(b3y_spd-1010)) {fail[4]=1; TDM_ERROR1("TDM: _____ERROR: y3 bucket slot #%0d\n",i);}
		if (mmu_tdm_ovs_y_4[i]!=NUM_EXT_PORTS) if (speed[mmu_tdm_ovs_y_4[i]]>(b4y_spd+1010) || speed[mmu_tdm_ovs_y_4[i]]<(b4y_spd-1010)) {fail[4]=1; TDM_ERROR1("TDM: _____ERROR: y4 bucket slot #%0d\n",i);}
	}
	
	/*
		3. port census
	*/
	for (i=0; i<12; i++)
	{
		k=0;
		if (port_state_map[i]==1)
		{
			switch (speed[i+1])
			{
				case SPEED_1G:
				case SPEED_2p5G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_10G:
				case SPEED_10G_XAUI:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=1 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=2) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=8) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=16) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_120G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=12) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=48) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_100G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=12 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=40) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				default:
					break;	
			}
		}
		if (port_state_map[i]==2)
		{
			switch (speed[i+1])
			{
				case SPEED_1G:
				case SPEED_2p5G:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_x_1[j]==(i+1)) k++; if (mmu_tdm_ovs_x_2[j]==(i+1)) k++; if (mmu_tdm_ovs_x_3[j]==(i+1)) k++; if (mmu_tdm_ovs_x_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_10G:
				case SPEED_10G_XAUI:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=1 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_x_1[j]==(i+1)) k++; if (mmu_tdm_ovs_x_2[j]==(i+1)) k++; if (mmu_tdm_ovs_x_3[j]==(i+1)) k++; if (mmu_tdm_ovs_x_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=2) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_x_1[j]==(i+1)) k++; if (mmu_tdm_ovs_x_2[j]==(i+1)) k++; if (mmu_tdm_ovs_x_3[j]==(i+1)) k++; if (mmu_tdm_ovs_x_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_x_1[j]==(i+1)) k++; if (mmu_tdm_ovs_x_2[j]==(i+1)) k++; if (mmu_tdm_ovs_x_3[j]==(i+1)) k++; if (mmu_tdm_ovs_x_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				default:
					break;
			}
		}
	}
	for (i=16; i<32; i++)
	{
		k=0;
		if (port_state_map[i]==1)
		{
			switch (speed[i+1])
			{
				case SPEED_1G:
				case SPEED_2p5G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_10G:
				case SPEED_10G_XAUI:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=1 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=2) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=8) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=16) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_120G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=12) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=48) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_100G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=12 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=40) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				default:
					break;	
			}
		}
		if (port_state_map[i]==2)
		{
			switch (speed[i+1])
			{
				case SPEED_1G:
				case SPEED_2p5G:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_x_1[j]==(i+1)) k++; if (mmu_tdm_ovs_x_2[j]==(i+1)) k++; if (mmu_tdm_ovs_x_3[j]==(i+1)) k++; if (mmu_tdm_ovs_x_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_10G:
				case SPEED_10G_XAUI:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=1 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_x_1[j]==(i+1)) k++; if (mmu_tdm_ovs_x_2[j]==(i+1)) k++; if (mmu_tdm_ovs_x_3[j]==(i+1)) k++; if (mmu_tdm_ovs_x_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=2) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_x_1[j]==(i+1)) k++; if (mmu_tdm_ovs_x_2[j]==(i+1)) k++; if (mmu_tdm_ovs_x_3[j]==(i+1)) k++; if (mmu_tdm_ovs_x_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_x0[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_x_1[j]==(i+1)) k++; if (mmu_tdm_ovs_x_2[j]==(i+1)) k++; if (mmu_tdm_ovs_x_3[j]==(i+1)) k++; if (mmu_tdm_ovs_x_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				default:
					break;
			}
		}
	}
	for (i=32; i<64; i++)
	{
		k=0;
		if (port_state_map[i]==1)
		{
			switch (speed[i+1])
			{
				case SPEED_1G:
				case SPEED_2p5G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x1[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_10G:
				case SPEED_10G_XAUI:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x1[j]==(i+1)) k++;
					if (k!=1 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x1[j]==(i+1)) k++;
					if (k!=2) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=8) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x1[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=16) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_120G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x1[j]==(i+1)) k++;
					if (k!=12) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=48) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_100G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_x1[j]==(i+1)) k++;
					if (k!=12 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_x[j]==(i+1)) k++;
					if (k!=40) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				default:
					break;	
			}
		}
		if (port_state_map[i]==2)
		{
			switch (speed[i+1])
			{
				case SPEED_1G:
				case SPEED_2p5G:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_x1[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_x_1[j]==(i+1)) k++; if (mmu_tdm_ovs_x_2[j]==(i+1)) k++; if (mmu_tdm_ovs_x_3[j]==(i+1)) k++; if (mmu_tdm_ovs_x_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_10G:
				case SPEED_10G_XAUI:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_x1[j]==(i+1)) k++;
					if (k!=1 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_x_1[j]==(i+1)) k++; if (mmu_tdm_ovs_x_2[j]==(i+1)) k++; if (mmu_tdm_ovs_x_3[j]==(i+1)) k++; if (mmu_tdm_ovs_x_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_x1[j]==(i+1)) k++;
					if (k!=2) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_x_1[j]==(i+1)) k++; if (mmu_tdm_ovs_x_2[j]==(i+1)) k++; if (mmu_tdm_ovs_x_3[j]==(i+1)) k++; if (mmu_tdm_ovs_x_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_x1[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_x_1[j]==(i+1)) k++; if (mmu_tdm_ovs_x_2[j]==(i+1)) k++; if (mmu_tdm_ovs_x_3[j]==(i+1)) k++; if (mmu_tdm_ovs_x_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				default:
					break;
			}
		}
	}
	for (i=64; i<96; i++)
	{
		k=0;
		if (port_state_map[i]==1)
		{
			switch (speed[i+1])
			{
				case SPEED_1G:
				case SPEED_2p5G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_y0[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_y[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_10G:
				case SPEED_10G_XAUI:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_y0[j]==(i+1)) k++;
					if (k!=1 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_y[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_y0[j]==(i+1)) k++;
					if (k!=2) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_y[j]==(i+1)) k++;
					if (k!=8) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_y0[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_y[j]==(i+1)) k++;
					if (k!=16) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_120G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_y0[j]==(i+1)) k++;
					if (k!=12) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_y[j]==(i+1)) k++;
					if (k!=48) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_100G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_y0[j]==(i+1)) k++;
					if (k!=12 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_y[j]==(i+1)) k++;
					if (k!=40) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				default:
					break;	
			}
		}
		if (port_state_map[i]==2)
		{
			switch (speed[i+1])
			{
				case SPEED_1G:
				case SPEED_2p5G:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_y0[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_y_1[j]==(i+1)) k++; if (mmu_tdm_ovs_y_2[j]==(i+1)) k++; if (mmu_tdm_ovs_y_3[j]==(i+1)) k++; if (mmu_tdm_ovs_y_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_10G:
				case SPEED_10G_XAUI:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_y0[j]==(i+1)) k++;
					if (k!=1 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_y_1[j]==(i+1)) k++; if (mmu_tdm_ovs_y_2[j]==(i+1)) k++; if (mmu_tdm_ovs_y_3[j]==(i+1)) k++; if (mmu_tdm_ovs_y_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_y0[j]==(i+1)) k++;
					if (k!=2) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_y_1[j]==(i+1)) k++; if (mmu_tdm_ovs_y_2[j]==(i+1)) k++; if (mmu_tdm_ovs_y_3[j]==(i+1)) k++; if (mmu_tdm_ovs_y_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_y0[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_y_1[j]==(i+1)) k++; if (mmu_tdm_ovs_y_2[j]==(i+1)) k++; if (mmu_tdm_ovs_y_3[j]==(i+1)) k++; if (mmu_tdm_ovs_y_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				default:
					break;
			}
		}
	}
	for (i=96; i<128; i++)
	{
		k=0;
		if (port_state_map[i]==1)
		{
			switch (speed[i+1])
			{
				case SPEED_1G:
				case SPEED_2p5G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_y1[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_y[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_10G:
				case SPEED_10G_XAUI:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_y1[j]==(i+1)) k++;
					if (k!=1 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_y[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_y1[j]==(i+1)) k++;
					if (k!=2) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_y[j]==(i+1)) k++;
					if (k!=8) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_y1[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_y[j]==(i+1)) k++;
					if (k!=16) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_120G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_y1[j]==(i+1)) k++;
					if (k!=12) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_y[j]==(i+1)) k++;
					if (k!=48) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_100G:
					for (j=0; j<32; j++) if (pgw_tdm_tbl_y1[j]==(i+1)) k++;
					if (k!=12 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<256; j++) if (mmu_tdm_tbl_y[j]==(i+1)) k++;
					if (k!=40) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU table (k=%0d)\n",(i+1),k);}
					break;
				default:
					break;	
			}
		}
		if (port_state_map[i]==2)
		{
			switch (speed[i+1])
			{
				case SPEED_1G:
				case SPEED_2p5G:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_y1[j]==(i+1)) k++;
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_y_1[j]==(i+1)) k++; if (mmu_tdm_ovs_y_2[j]==(i+1)) k++; if (mmu_tdm_ovs_y_3[j]==(i+1)) k++; if (mmu_tdm_ovs_y_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_10G:
				case SPEED_10G_XAUI:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_y1[j]==(i+1)) k++;
					if (k!=1 && k!=10) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_y_1[j]==(i+1)) k++; if (mmu_tdm_ovs_y_2[j]==(i+1)) k++; if (mmu_tdm_ovs_y_3[j]==(i+1)) k++; if (mmu_tdm_ovs_y_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_21G:
				case SPEED_20G:
				case SPEED_21G_DUAL:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_y1[j]==(i+1)) k++;
					if (k!=2) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_y_1[j]==(i+1)) k++; if (mmu_tdm_ovs_y_2[j]==(i+1)) k++; if (mmu_tdm_ovs_y_3[j]==(i+1)) k++; if (mmu_tdm_ovs_y_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				case SPEED_42G:
				case SPEED_40G:
					for (j=0; j<32; j++) if (ovs_tdm_tbl_y1[j]==(i+1)) k++;
					if (k!=4) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the PGW OVS table (k=%0d)\n",(i+1),k);}
					k=0;
					for (j=0; j<16; j++) {if (mmu_tdm_ovs_y_1[j]==(i+1)) k++; if (mmu_tdm_ovs_y_2[j]==(i+1)) k++; if (mmu_tdm_ovs_y_3[j]==(i+1)) k++; if (mmu_tdm_ovs_y_4[j]==(i+1)) k++;}
					if (k!=1) {fail[3]=1; TDM_ERROR2("TDM: _____ERROR: port %0d subscription error in the MMU OVS buckets (k=%0d)\n",(i+1),k);}
					break;
				default:
					break;
			}
		}
	}
	}
	TDM_FREE(pgw_x0_mtbl);
	TDM_FREE(pgw_x1_mtbl);
	TDM_FREE(pgw_y0_mtbl);
	TDM_FREE(pgw_y1_mtbl);
	TDM_FREE(mmu_x_mtbl);
	TDM_FREE(mmu_y_mtbl);
	TDM_FREE(pgw_x0_tracker);
	TDM_FREE(pgw_x1_tracker);
	TDM_FREE(pgw_y0_tracker);
	TDM_FREE(pgw_y1_tracker);
	TDM_FREE(mmu_x_tracker);
	TDM_FREE(mmu_y_tracker);
}


#ifdef TD2_TDM_ARISTA_96X10G_8X40G
	/**
	@name: set_tdm_tbl
	@param: enum, int, int[32], int[32], int[32], int[32], int[32], int[32], int[32], int[32], int[65], int[65], int[128]
	
	Test case involving 2:1 oversubscription at 760MHz and 960G core bandwidth. Provides hard-coded TDM instead of
	calling scheduler algorithm.
	**/
	int bcm56850_a0_set_tdm_tbl(int speed[NUM_EXT_PORTS], int tdm_bw, 
			int pgw_tdm_tbl_x0[32], int ovs_tdm_tbl_x0[32], int ovs_spacing_x0[32],
			int pgw_tdm_tbl_x1[32], int ovs_tdm_tbl_x1[32], int ovs_spacing_x1[32],
			int pgw_tdm_tbl_y0[32], int ovs_tdm_tbl_y0[32], int ovs_spacing_y0[32],
			int pgw_tdm_tbl_y1[32], int ovs_tdm_tbl_y1[32], int ovs_spacing_y1[32],
			int mmu_tdm_tbl_x[256], int mmu_tdm_ovs_x_1[16], int mmu_tdm_ovs_x_2[16], int mmu_tdm_ovs_x_3[16], int mmu_tdm_ovs_x_4[16],
			int mmu_tdm_tbl_y[256], int mmu_tdm_ovs_y_1[16], int mmu_tdm_ovs_y_2[16], int mmu_tdm_ovs_y_3[16], int mmu_tdm_ovs_y_4[16],
			int port_state_map[128],
			int iarb_tdm_tbl_x[512], int iarb_tdm_tbl_y[512]) 
	{
		int wc_array[NUM_WC][4], i, j;
	
		for (i=0; i< 256; i++) {
			mmu_tdm_tbl_x[i] = NUM_EXT_PORTS;
			mmu_tdm_tbl_y[i] = NUM_EXT_PORTS;
		}
		for (i=0; i<16; i++) {
			mmu_tdm_ovs_x_1[i] = NUM_EXT_PORTS;
			mmu_tdm_ovs_x_2[i] = NUM_EXT_PORTS;
			mmu_tdm_ovs_x_3[i] = NUM_EXT_PORTS;
			mmu_tdm_ovs_x_4[i] = NUM_EXT_PORTS;
			mmu_tdm_ovs_y_1[i] = NUM_EXT_PORTS;
			mmu_tdm_ovs_y_2[i] = NUM_EXT_PORTS;
			mmu_tdm_ovs_y_3[i] = NUM_EXT_PORTS;
			mmu_tdm_ovs_y_4[i] = NUM_EXT_PORTS;
		}
		for (i=0; i< 32; i++) {
			pgw_tdm_tbl_x0[i] = NUM_EXT_PORTS;
			ovs_tdm_tbl_x0[i] = NUM_EXT_PORTS;
			ovs_spacing_x0[i] = NUM_EXT_PORTS;
			pgw_tdm_tbl_x1[i] = NUM_EXT_PORTS;
			ovs_tdm_tbl_x1[i] = NUM_EXT_PORTS;
			ovs_spacing_x1[i] = NUM_EXT_PORTS;
			pgw_tdm_tbl_y0[i] = NUM_EXT_PORTS;
			ovs_tdm_tbl_y0[i] = NUM_EXT_PORTS;
			ovs_spacing_y0[i] = NUM_EXT_PORTS;
			pgw_tdm_tbl_y1[i] = NUM_EXT_PORTS;
			ovs_tdm_tbl_y1[i] = NUM_EXT_PORTS;
			ovs_spacing_y1[i] = NUM_EXT_PORTS;
		}

		TSC_port_transcription(wc_array, speed, port_state_map);
		
		for (i=0; i<24; i+=6) {
			pgw_tdm_tbl_x0[4+i]=131; pgw_tdm_tbl_x0[5+i]=131;
			pgw_tdm_tbl_x1[4+i]=131; pgw_tdm_tbl_x1[5+i]=131;
			pgw_tdm_tbl_y0[4+i]=131; pgw_tdm_tbl_y0[5+i]=131;
			pgw_tdm_tbl_y1[4+i]=131; pgw_tdm_tbl_y1[5+i]=131;
		}
		for (i=0; i<24; i+=6) {
			for (j=0; j<4; j++) {
				pgw_tdm_tbl_x0[i+j]=( (1+(i/6))+(j*4) );
				pgw_tdm_tbl_x1[i+j]=( (33+(i/6))+(j*4) );
				pgw_tdm_tbl_y0[i+j]=( (65+(i/6))+(j*4) );
				pgw_tdm_tbl_y1[i+j]=( (97+(i/6))+(j*4) );
			}
		}
		for (i=0; i<16; i+=4) {
			ovs_tdm_tbl_x0[i+2]=25; ovs_tdm_tbl_x0[i+3]=29;
			ovs_tdm_tbl_x1[i+2]=57; ovs_tdm_tbl_x1[i+3]=61;
			ovs_tdm_tbl_y0[i+2]=89; ovs_tdm_tbl_y0[i+3]=93;
			ovs_tdm_tbl_y1[i+2]=121; ovs_tdm_tbl_y1[i+3]=125;
			for (j=0; j<2; j++) {
				ovs_tdm_tbl_x0[i+j]= ( (17+(i/4))+(j*4) );
				ovs_tdm_tbl_x1[i+j]= ( (49+(i/4))+(j*4) );
				ovs_tdm_tbl_y0[i+j]= ( (81+(i/4))+(j*4) );
				ovs_tdm_tbl_y1[i+j]= ( (113+(i/4))+(j*4) );
			}
		}
		for (i=0; i<32; i++) {
			ovs_spacing_x0[i]=32;
			ovs_spacing_x1[i]=32;
			ovs_spacing_y0[i]=32;
			ovs_spacing_y1[i]=32;
		}
		for (i=2; i<32; i+=8) {
			ovs_spacing_x0[i]=8; ovs_spacing_x0[i+1]=8;
			ovs_spacing_x1[i]=8; ovs_spacing_x1[i+1]=8;
			ovs_spacing_y0[i]=8; ovs_spacing_y0[i+1]=8;
			ovs_spacing_y1[i]=8; ovs_spacing_y1[i+1]=8;
		}
		
		mmu_tdm_ovs_x_1[0] = 56;
		mmu_tdm_ovs_x_1[1] = 52;
		mmu_tdm_ovs_x_1[2] = 24;
		mmu_tdm_ovs_x_1[3] = 20;
		mmu_tdm_ovs_x_1[4] = 53;
		mmu_tdm_ovs_x_1[5] = 49;
		mmu_tdm_ovs_x_1[6] = 21;
		mmu_tdm_ovs_x_1[7] = 17;
		mmu_tdm_ovs_x_1[8] = 54;
		mmu_tdm_ovs_x_1[9] = 50;
		mmu_tdm_ovs_x_1[10] = 22;
		mmu_tdm_ovs_x_1[11] = 18;
		mmu_tdm_ovs_x_1[12] = 55;
		mmu_tdm_ovs_x_1[13] = 51;
		mmu_tdm_ovs_x_1[14] = 23;
		mmu_tdm_ovs_x_1[15] = 19;
		
		mmu_tdm_ovs_x_2[0] = 61;
		mmu_tdm_ovs_x_2[1] = 57;
		mmu_tdm_ovs_x_2[2] = 29;
		mmu_tdm_ovs_x_2[3] = 25;
		
		mmu_tdm_ovs_y_1[0] = 120;
		mmu_tdm_ovs_y_1[1] = 116;
		mmu_tdm_ovs_y_1[2] = 88;
		mmu_tdm_ovs_y_1[3] = 84;
		mmu_tdm_ovs_y_1[4] = 117;
		mmu_tdm_ovs_y_1[5] = 113;
		mmu_tdm_ovs_y_1[6] = 85;
		mmu_tdm_ovs_y_1[7] = 81;
		mmu_tdm_ovs_y_1[8] = 118;
		mmu_tdm_ovs_y_1[9] = 114;
		mmu_tdm_ovs_y_1[10] = 86;
		mmu_tdm_ovs_y_1[11] = 82;
		mmu_tdm_ovs_y_1[12] = 119;
		mmu_tdm_ovs_y_1[13] = 115;
		mmu_tdm_ovs_y_1[14] = 87;
		mmu_tdm_ovs_y_1[15] = 83;

		mmu_tdm_ovs_y_2[0] = 125;
		mmu_tdm_ovs_y_2[1] = 121;
		mmu_tdm_ovs_y_2[2] = 93;
		mmu_tdm_ovs_y_2[3] = 89;
		
		mmu_tdm_tbl_x[0]=48;
		mmu_tdm_tbl_x[1]=16;
		mmu_tdm_tbl_x[3]=44;
		mmu_tdm_tbl_x[4]=12;
		mmu_tdm_tbl_x[6]=40;
		mmu_tdm_tbl_x[7]=8;
		mmu_tdm_tbl_x[9]=36;
		mmu_tdm_tbl_x[10]=4;
		mmu_tdm_tbl_x[12]=45;
		mmu_tdm_tbl_x[13]=13;
		mmu_tdm_tbl_x[15]=41;
		mmu_tdm_tbl_x[16]=9;
		mmu_tdm_tbl_x[18]=37;
		mmu_tdm_tbl_x[19]=5;
		mmu_tdm_tbl_x[21]=33;
		mmu_tdm_tbl_x[22]=1;
		mmu_tdm_tbl_x[24]=46;
		mmu_tdm_tbl_x[25]=14;
		mmu_tdm_tbl_x[27]=42;
		mmu_tdm_tbl_x[28]=10;
		mmu_tdm_tbl_x[30]=38;
		mmu_tdm_tbl_x[31]=6;
		mmu_tdm_tbl_x[33]=34;
		mmu_tdm_tbl_x[34]=2;
		mmu_tdm_tbl_x[36]=47;
		mmu_tdm_tbl_x[37]=15;
		mmu_tdm_tbl_x[39]=43;
		mmu_tdm_tbl_x[40]=11;
		mmu_tdm_tbl_x[42]=39;
		mmu_tdm_tbl_x[43]=7;
		mmu_tdm_tbl_x[45]=35;
		mmu_tdm_tbl_x[46]=3;
		
		for (i=0; i<47; i++) mmu_tdm_tbl_x[i+48]=mmu_tdm_tbl_x[i];
		for (i=0; i<97; i++) mmu_tdm_tbl_x[i+97]=mmu_tdm_tbl_x[i];
		
		for (i=255; i>24; i--) mmu_tdm_tbl_x[i]=mmu_tdm_tbl_x[i-1];
		mmu_tdm_tbl_x[24]=0;
		for (i=255; i>49; i--) mmu_tdm_tbl_x[i]=mmu_tdm_tbl_x[i-1];
		mmu_tdm_tbl_x[49]=132;
		for (i=255; i>74; i--) mmu_tdm_tbl_x[i]=mmu_tdm_tbl_x[i-1];
		mmu_tdm_tbl_x[74]=0;
		for (i=255; i>99; i--) mmu_tdm_tbl_x[i]=mmu_tdm_tbl_x[i-1];
		mmu_tdm_tbl_x[99]=132;
		for (i=255; i>124; i--) mmu_tdm_tbl_x[i]=mmu_tdm_tbl_x[i-1];
		mmu_tdm_tbl_x[124]=132;
		for (i=255; i>149; i--) mmu_tdm_tbl_x[i]=mmu_tdm_tbl_x[i-1];
		mmu_tdm_tbl_x[149]=0;
		for (i=255; i>174; i--) mmu_tdm_tbl_x[i]=mmu_tdm_tbl_x[i-1];
		mmu_tdm_tbl_x[174]=132;
		for (i=255; i>199; i--) mmu_tdm_tbl_x[i]=mmu_tdm_tbl_x[i-1];
		mmu_tdm_tbl_x[199]=132;

		mmu_tdm_tbl_y[0]=112;
		mmu_tdm_tbl_y[1]=80;
		mmu_tdm_tbl_y[3]=108;
		mmu_tdm_tbl_y[4]=76;
		mmu_tdm_tbl_y[6]=104;
		mmu_tdm_tbl_y[7]=72;
		mmu_tdm_tbl_y[9]=100;
		mmu_tdm_tbl_y[10]=68;
		mmu_tdm_tbl_y[12]=109;
		mmu_tdm_tbl_y[13]=77;
		mmu_tdm_tbl_y[15]=105;
		mmu_tdm_tbl_y[16]=73;
		mmu_tdm_tbl_y[18]=101;
		mmu_tdm_tbl_y[19]=69;
		mmu_tdm_tbl_y[21]=97;
		mmu_tdm_tbl_y[22]=65;
		mmu_tdm_tbl_y[24]=110;
		mmu_tdm_tbl_y[25]=78;
		mmu_tdm_tbl_y[27]=106;
		mmu_tdm_tbl_y[28]=74;
		mmu_tdm_tbl_y[30]=102;
		mmu_tdm_tbl_y[31]=70;
		mmu_tdm_tbl_y[33]=98;
		mmu_tdm_tbl_y[34]=66;
		mmu_tdm_tbl_y[36]=111;
		mmu_tdm_tbl_y[37]=79;
		mmu_tdm_tbl_y[39]=107;
		mmu_tdm_tbl_y[40]=75;
		mmu_tdm_tbl_y[42]=103;
		mmu_tdm_tbl_y[43]=71;
		mmu_tdm_tbl_y[45]=99;
		mmu_tdm_tbl_y[46]=67;
		
		for (i=0; i<47; i++) mmu_tdm_tbl_y[i+48]=mmu_tdm_tbl_y[i];
		for (i=0; i<97; i++) mmu_tdm_tbl_y[i+97]=mmu_tdm_tbl_y[i];
		
		for (i=255; i>24; i--) mmu_tdm_tbl_y[i]=mmu_tdm_tbl_y[i-1];
		mmu_tdm_tbl_y[24]=129;
		for (i=255; i>49; i--) mmu_tdm_tbl_y[i]=mmu_tdm_tbl_y[i-1];
		mmu_tdm_tbl_y[49]=132;
		for (i=255; i>74; i--) mmu_tdm_tbl_y[i]=mmu_tdm_tbl_y[i-1];
		mmu_tdm_tbl_y[74]=129;
		for (i=255; i>99; i--) mmu_tdm_tbl_y[i]=mmu_tdm_tbl_y[i-1];
		mmu_tdm_tbl_y[99]=132;
		for (i=255; i>124; i--) mmu_tdm_tbl_y[i]=mmu_tdm_tbl_y[i-1];
		mmu_tdm_tbl_y[124]=132;
		for (i=255; i>149; i--) mmu_tdm_tbl_y[i]=mmu_tdm_tbl_y[i-1];
		mmu_tdm_tbl_y[149]=129;
		for (i=255; i>174; i--) mmu_tdm_tbl_y[i]=mmu_tdm_tbl_y[i-1];
		mmu_tdm_tbl_y[174]=132;
		for (i=255; i>199; i--) mmu_tdm_tbl_y[i]=mmu_tdm_tbl_y[i-1];
		mmu_tdm_tbl_y[199]=132;
		
		for (i=0; i<200; i++) {
			if (mmu_tdm_tbl_x[i]==130) mmu_tdm_tbl_x[i]=131;
			if (mmu_tdm_tbl_y[i]==130) mmu_tdm_tbl_y[i]=131;
		}
		
		print_tbl_summary(pgw_tdm_tbl_x0, pgw_tdm_tbl_x1, pgw_tdm_tbl_y0, pgw_tdm_tbl_y1,
				  ovs_tdm_tbl_x0, ovs_tdm_tbl_x1, ovs_tdm_tbl_y0, ovs_tdm_tbl_y1,
      				  ovs_spacing_x0, ovs_spacing_x1, ovs_spacing_y0, ovs_spacing_y1,
      				  tdm_bw);
		
		return 1;
	}
#else
	/**
	@name: set_tdm_tbl
	@param: enum, int, int[32], int[32], int[32], int[32], int[32], int[32], int[32], int[32], int[65], int[65], int[128]
	
	SV interfaced entry point for the 19 pre-configured TDM configurations
	**/
	int bcm56850_a0_set_tdm_tbl(int speed[NUM_EXT_PORTS], int tdm_bw, 
			int pgw_tdm_tbl_x0[32], int ovs_tdm_tbl_x0[32], int ovs_spacing_x0[32],
			int pgw_tdm_tbl_x1[32], int ovs_tdm_tbl_x1[32], int ovs_spacing_x1[32],
			int pgw_tdm_tbl_y0[32], int ovs_tdm_tbl_y0[32], int ovs_spacing_y0[32],
			int pgw_tdm_tbl_y1[32], int ovs_tdm_tbl_y1[32], int ovs_spacing_y1[32],
			int mmu_tdm_tbl_x[256], int mmu_tdm_ovs_x_1[16], int mmu_tdm_ovs_x_2[16], int mmu_tdm_ovs_x_3[16], int mmu_tdm_ovs_x_4[16],
			int mmu_tdm_tbl_y[256], int mmu_tdm_ovs_y_1[16], int mmu_tdm_ovs_y_2[16], int mmu_tdm_ovs_y_3[16], int mmu_tdm_ovs_y_4[16],
			int port_state_map[128],
			int iarb_tdm_tbl_x[512], int iarb_tdm_tbl_y[512])
	{
		int wc_array[NUM_WC][4], mgmtbw=0;
		int i;
		int checkpoint[6];
	
		if (pgw_tdm_tbl_x0[0]==1234) wc_array[3][0]=MGM_TOKEN;
	
		for (i=0; i< 256; i++)
		{
			mmu_tdm_tbl_x[i] = NUM_EXT_PORTS;
			mmu_tdm_tbl_y[i] = NUM_EXT_PORTS;
		}
		for (i=0; i<16; i++) 
		{
			mmu_tdm_ovs_x_1[i] = NUM_EXT_PORTS;
			mmu_tdm_ovs_x_2[i] = NUM_EXT_PORTS;
			mmu_tdm_ovs_x_3[i] = NUM_EXT_PORTS;
			mmu_tdm_ovs_x_4[i] = NUM_EXT_PORTS;
			mmu_tdm_ovs_y_1[i] = NUM_EXT_PORTS;
			mmu_tdm_ovs_y_2[i] = NUM_EXT_PORTS;
			mmu_tdm_ovs_y_3[i] = NUM_EXT_PORTS;
			mmu_tdm_ovs_y_4[i] = NUM_EXT_PORTS;
		}
		for (i=0; i< 32; i++){
			pgw_tdm_tbl_x0[i] = NUM_EXT_PORTS;
			ovs_tdm_tbl_x0[i] = NUM_EXT_PORTS;
			ovs_spacing_x0[i] = NUM_EXT_PORTS;
			pgw_tdm_tbl_x1[i] = NUM_EXT_PORTS;
			ovs_tdm_tbl_x1[i] = NUM_EXT_PORTS;
			ovs_spacing_x1[i] = NUM_EXT_PORTS;
			pgw_tdm_tbl_y0[i] = NUM_EXT_PORTS;
			ovs_tdm_tbl_y0[i] = NUM_EXT_PORTS;
			ovs_spacing_y0[i] = NUM_EXT_PORTS;
			pgw_tdm_tbl_y1[i] = NUM_EXT_PORTS;
			ovs_tdm_tbl_y1[i] = NUM_EXT_PORTS;
			ovs_spacing_y1[i] = NUM_EXT_PORTS;
		}
			
		for (i=0; i< NUM_EXT_PORTS; i++) TDM_VERBOSE2("TDM: _____VERBOSE: the speed for port %0d is %0d\n",i,speed[i]);
		
		TSC_port_transcription(wc_array, speed, port_state_map);
		print_port(wc_array);
		
		for (i=0; i<4; i++) if (wc_array[3][i]==MGM_TOKEN) mgmtbw++;
	
		TDM_VERBOSE1("TDM: _____VERBOSE: the chip bandwidth is %0d\n", tdm_bw);
	
			checkpoint[0] = TDM_scheduler_wrap(wc_array, speed, pgw_tdm_tbl_x0, ovs_tdm_tbl_x0, 0, tdm_bw, port_state_map, 0, 32);
			print_tdm_tbl(pgw_tdm_tbl_x0, "Pipe_x0_PGW");
			print_tdm_tbl(ovs_tdm_tbl_x0, "Pipe_x0_OVS");
			checkpoint[1] = TDM_scheduler_wrap(wc_array, speed, pgw_tdm_tbl_x1, ovs_tdm_tbl_x1, 1, tdm_bw, port_state_map, 32, 64);
			print_tdm_tbl(pgw_tdm_tbl_x1, "Pipe_x1_PGW");
			print_tdm_tbl(ovs_tdm_tbl_x1, "Pipe_x1_OVS");
			checkpoint[2] = TDM_scheduler_wrap(wc_array, speed, pgw_tdm_tbl_y0, ovs_tdm_tbl_y0, 2, tdm_bw, port_state_map, 64, 96);
			print_tdm_tbl(pgw_tdm_tbl_y0, "Pipe_y0_PGW");
			print_tdm_tbl(ovs_tdm_tbl_y0, "Pipe_y0_OVS");
			checkpoint[3] = TDM_scheduler_wrap(wc_array, speed, pgw_tdm_tbl_y1, ovs_tdm_tbl_y1, 3, tdm_bw, port_state_map, 96, 128);
			print_tdm_tbl(pgw_tdm_tbl_y1, "Pipe_y1_PGW");
			print_tdm_tbl(ovs_tdm_tbl_y1, "Pipe_y1_OVS");
		
			checkpoint[4] = write_mmu_tdm_tbl(pgw_tdm_tbl_x0, pgw_tdm_tbl_x1, ovs_tdm_tbl_x0, ovs_tdm_tbl_x1, mmu_tdm_tbl_x, mmu_tdm_ovs_x_1, mmu_tdm_ovs_x_2, mmu_tdm_ovs_x_3, mmu_tdm_ovs_x_4, TRUE, port_state_map, wc_array, tdm_bw, speed);
			checkpoint[5] = write_mmu_tdm_tbl(pgw_tdm_tbl_y0, pgw_tdm_tbl_y1, ovs_tdm_tbl_y0, ovs_tdm_tbl_y1, mmu_tdm_tbl_y, mmu_tdm_ovs_y_1, mmu_tdm_ovs_y_2, mmu_tdm_ovs_y_3, mmu_tdm_ovs_y_4, FALSE, port_state_map, wc_array, tdm_bw, speed);
		
			if (ovs_tdm_tbl_x0[0] != NUM_EXT_PORTS) TDM_OVS_spacer(wc_array, ovs_tdm_tbl_x0, ovs_spacing_x0);
			if (ovs_tdm_tbl_x1[0] != NUM_EXT_PORTS) TDM_OVS_spacer(wc_array, ovs_tdm_tbl_x1, ovs_spacing_x1);
			if (ovs_tdm_tbl_y0[0] != NUM_EXT_PORTS) TDM_OVS_spacer(wc_array, ovs_tdm_tbl_y0, ovs_spacing_y0);
			if (ovs_tdm_tbl_y1[0] != NUM_EXT_PORTS) TDM_OVS_spacer(wc_array, ovs_tdm_tbl_y1, ovs_spacing_y1);

			print_tbl_summary(pgw_tdm_tbl_x0, pgw_tdm_tbl_x1, pgw_tdm_tbl_y0, pgw_tdm_tbl_y1,
					ovs_tdm_tbl_x0, ovs_tdm_tbl_x1, ovs_tdm_tbl_y0, ovs_tdm_tbl_y1,
					ovs_spacing_x0, ovs_spacing_x1, ovs_spacing_y0, ovs_spacing_y1,
					tdm_bw);
			parse_mmu_tdm_tbl(tdm_bw, mgmtbw, mmu_tdm_tbl_x, mmu_tdm_ovs_x_1, mmu_tdm_ovs_x_2, mmu_tdm_ovs_x_3, mmu_tdm_ovs_x_4, 0);
			parse_mmu_tdm_tbl(tdm_bw, mgmtbw, mmu_tdm_tbl_y, mmu_tdm_ovs_y_1, mmu_tdm_ovs_y_2, mmu_tdm_ovs_y_3, mmu_tdm_ovs_y_4, 1);
	
		if (checkpoint[0]==0||checkpoint[1]==0||checkpoint[2]==0||checkpoint[3]==0||checkpoint[4]==0||checkpoint[5]==0)
		{
			if (checkpoint[0]==0) TDM_ERROR0("TDM: _____ERROR: quadrant x0 failed to schedule\n");
			if (checkpoint[1]==0) TDM_ERROR0("TDM: _____ERROR: quadrant x1 failed to schedule\n");
			if (checkpoint[2]==0) TDM_ERROR0("TDM: _____ERROR: quadrant y0 failed to schedule\n");
			if (checkpoint[3]==0) TDM_ERROR0("TDM: _____ERROR: quadrant y1 failed to schedule\n");
			if (checkpoint[4]==0) TDM_ERROR0("TDM: _____ERROR: mmu x pipe table failed to schedule\n");
			if (checkpoint[5]==0) TDM_ERROR0("TDM: _____ERROR: mmu y pipe table failed to schedule\n");
			return 0;
		}
		else return 1;
		
	}
#endif


/**
@name: init_iarb_tdm_ovs_table
@param: int, int, int, int, int*, int*, int[512], int[512]

IARB TDM Oversubscription Schedule:
  Input  1  => Core bandwidth - 960/720/640/480.
  Input  2  => 1 if there are 4x1G management ports, 0 otherwise.
  Input  3  => 1 if there are 4x2.5G management ports, 0 otherwise.
  Input  4  => 1 if there are 1x10G management port, 0 otherwise.
  Output 5  => The X-pipe TDM oversubscription table wrap pointer value.
  Output 6  => The Y-pipe TDM oversubscription table wrap pointer value.
  Output 7  => The X-pipe TDM oversubscription schedule.
  Output 8  => The Y-pipe TDM oversubscription schedule.
**/
static void init_iarb_tdm_ovs_table (
          int core_bw,
          int mgm4x1,
          int mgm4x2p5,
          int mgm1x10,
          int *iarb_tdm_wrap_ptr_ovs_x,
          int *iarb_tdm_wrap_ptr_ovs_y,
          int iarb_tdm_tbl_ovs_x[512],
          int iarb_tdm_tbl_ovs_y[512]
          ) {
  int i;

  switch (core_bw) {
    case 960 :
      /* First, assume no management ports. */
      *iarb_tdm_wrap_ptr_ovs_x = 199;
      *iarb_tdm_wrap_ptr_ovs_y = 199;
      for (i = 0; i < 24; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[24] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[24] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 25; i < 49; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[49] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[49] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 50; i < 74; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[74] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[74] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 75; i < 99; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[99] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[99] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 100; i < 124; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[124] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[124] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 125; i < 149; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[149] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[149] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 150; i < 174; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[174] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[174] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 175; i < 199; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[199] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[199] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;

      /* Then check for management ports. */
      if (mgm4x1) {
        iarb_tdm_tbl_ovs_x[24] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[49] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[74] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[99] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
      } else if (mgm4x2p5 || mgm1x10) {
        /*
          Nate's comment in spreadsheet: "Not suppoted in Iarb. It's still possible
          to have a 10G management port scheduled with regular ports in PGW".
        */
      }
      break;
    case 720 :
      /* First, assume no management ports. */
      *iarb_tdm_wrap_ptr_ovs_x = 159;
      *iarb_tdm_wrap_ptr_ovs_y = 159;
      for (i = 0; i < 15; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[15] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      iarb_tdm_tbl_ovs_y[15] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      iarb_tdm_tbl_ovs_x[16] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[16] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      for (i = 17; i < 31; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[31] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[31] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 32; i < 47; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[47] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      iarb_tdm_tbl_ovs_y[47] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      iarb_tdm_tbl_ovs_x[48] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[48] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      for (i = 49; i < 63; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[63] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[63] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 64; i < 79; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[79] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      iarb_tdm_tbl_ovs_y[79] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      iarb_tdm_tbl_ovs_x[80] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[80] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      for (i = 81; i < 95; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[95] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[95] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 96; i < 111; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[111] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      iarb_tdm_tbl_ovs_y[111] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      iarb_tdm_tbl_ovs_x[112] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[112] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      for (i = 113; i < 127; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[127] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[127] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 128; i < 143; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[143] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      iarb_tdm_tbl_ovs_y[143] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      iarb_tdm_tbl_ovs_x[144] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[144] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      for (i = 145; i < 159; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[159] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[159] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;

      /* Then check for management ports. */
      if (mgm4x1) {
        iarb_tdm_tbl_ovs_x[16] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[31] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[48] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[63] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
      } else if (mgm4x2p5 || mgm1x10) {
        iarb_tdm_tbl_ovs_x[16] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[31] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[48] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[63] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[80] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[95] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[112] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[127] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
      }
      break;
    case 640 :
      /* First, assume no management ports. */
      *iarb_tdm_wrap_ptr_ovs_x = 135;
      *iarb_tdm_wrap_ptr_ovs_y = 135;
      for (i = 0; i < 16; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[16] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[16] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 17; i < 33; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[33] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[33] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 34; i < 50; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[50] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[50] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 51; i < 67; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[67] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[67] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 68; i < 84; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[84] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[84] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 85; i < 101; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[101] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[101] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 102; i < 118; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[118] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[118] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 119; i < 135; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[135] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[135] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;

      /* Then check for management ports. */
      if (mgm4x1) {
        iarb_tdm_tbl_ovs_x[16] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[50] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[33] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[67] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
      } else if (mgm4x2p5 || mgm1x10) {
        /*
          Nate's comment in spreadsheet: "Not suppoted in Iarb. It's still possible
          to have a 10G management port scheduled with regular ports in PGW".
        */
      }
      break;
    case 480 :
      /* First, assume no management ports. */
      *iarb_tdm_wrap_ptr_ovs_x = 105;
      *iarb_tdm_wrap_ptr_ovs_y = 105;
      for (i = 0; i < 10; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[10] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[10] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 11; i < 20; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[20] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      iarb_tdm_tbl_ovs_y[20] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_x[21] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[21] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      for (i = 22; i < 30; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[30] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[30] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
      iarb_tdm_tbl_ovs_x[31] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
      iarb_tdm_tbl_ovs_y[31] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 32; i < 41; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[41] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[41] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 42; i < 52; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[52] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[52] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 53; i < 63; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[63] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[63] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 64; i < 73; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[73] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      iarb_tdm_tbl_ovs_y[73] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      iarb_tdm_tbl_ovs_x[74] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[74] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      for (i = 75; i < 83; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[83] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[83] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
      iarb_tdm_tbl_ovs_x[84] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
      iarb_tdm_tbl_ovs_y[84] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 85; i < 94; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_ovs_x[94] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_ovs_y[94] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 95; i < 105; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_ovs_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_ovs_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_ovs_x[105] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_ovs_y[105] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;

      /* Then check for management ports. */
      if (mgm4x1) {
        iarb_tdm_tbl_ovs_x[10] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[21] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[30] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[41] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
      } else if (mgm4x2p5 || mgm1x10) {
        iarb_tdm_tbl_ovs_x[10] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[21] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[30] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[41] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[52] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[63] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[74] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_ovs_x[83] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
      }
      break;
  }
}


/**
@name: init_iarb_tdm_lr_table
@param: int, int, int, int, int*, int*, int[512], int[512]

IARB TDM Linerate Schedule:
  Input  1  => Core bandwidth - 960/720/640/480.
  Input  2  => 1 if there are 4x1G management ports, 0 otherwise.
  Input  3  => 1 if there are 4x2.5G management ports, 0 otherwise.
  Input  4  => 1 if there are 1x10G management port, 0 otherwise.
  Output 5  => The X-pipe TDM linerate table wrap pointer value.
  Output 6  => The Y-pipe TDM linerate table wrap pointer value.
  Output 7  => The X-pipe TDM linerate schedule.
  Output 8  => The Y-pipe TDM linerate schedule.
**/
static void init_iarb_tdm_lr_table (
          int core_bw,
          int mgm4x1,
          int mgm4x2p5,
          int mgm1x10,
          int *iarb_tdm_wrap_ptr_lr_x,
          int *iarb_tdm_wrap_ptr_lr_y,
          int iarb_tdm_tbl_lr_x[512],
          int iarb_tdm_tbl_lr_y[512]
          ) {
  int i;

  switch (core_bw) {
    case 960 :
      /* First, assume no management ports. */
      *iarb_tdm_wrap_ptr_lr_x = 199;
      *iarb_tdm_wrap_ptr_lr_y = 199;
      for (i = 0; i < 24; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[24] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[24] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 25; i < 49; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_lr_x[49] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[49] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 50; i < 74; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[74] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[74] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 75; i < 99; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_lr_x[99] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[99] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 100; i < 124; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[124] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[124] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 125; i < 149; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_lr_x[149] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[149] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 150; i < 174; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[174] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[174] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 175; i < 199; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_lr_x[199] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[199] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;

      /* Then check for management ports. */
      if (mgm4x1) {
        iarb_tdm_tbl_lr_x[24] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[74] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[124] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[174] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[199] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      } else if (mgm4x2p5 || mgm1x10) {
        iarb_tdm_tbl_lr_x[24] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[74] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[124] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[174] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[49] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[99] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[149] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[199] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
      }
      break;
    case 720 : 
      /* First, assume no management ports. */
      *iarb_tdm_wrap_ptr_lr_x = 159;
      *iarb_tdm_wrap_ptr_lr_y = 159;
      for (i = 0; i < 15; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[15] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[15] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 16; i < 31; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[31] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[31] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 32; i < 47; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[47] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[47] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 48; i < 63; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[63] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[63] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 64; i < 79; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[79] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[79] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 80; i < 95; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[95] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[95] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 96; i < 111; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[111] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[111] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 112; i < 127; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[127] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[127] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 128; i < 143; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[143] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[143] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 144; i < 159; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[159] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[159] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;

      /* Then check for management ports. */
      if (mgm4x1) {
        iarb_tdm_tbl_lr_x[15] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[31] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[47] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[63] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
      } else if (mgm4x2p5 || mgm1x10) {
        iarb_tdm_tbl_lr_x[15] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[31] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[47] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[63] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[79] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[95] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[111] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[127] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
      }
      break;
    case 640 : 
      /* First, assume no management ports. */
      *iarb_tdm_wrap_ptr_lr_x = 135;
      *iarb_tdm_wrap_ptr_lr_y = 135;
      for (i = 0; i < 16; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[16] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[16] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 17; i < 33; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_lr_x[33] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[33] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 34; i < 50; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[50] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[50] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 51; i < 67; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_lr_x[67] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[67] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 68; i < 84; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[84] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[84] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 85; i < 101; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_lr_x[101] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[101] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 102; i < 118; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[118] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[118] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 119; i < 135; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_lr_x[135] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[135] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;

      /* Then check for management ports. */
      if (mgm4x1) {
        iarb_tdm_tbl_lr_x[16] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[50] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[33] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[67] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
      } else if (mgm4x2p5 || mgm1x10) {
        iarb_tdm_tbl_lr_x[16] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[50] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[33] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[67] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[84] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[101] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[118] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[135] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
      }
      break;
    case 480 :
      /* First, assume no management ports. */
      *iarb_tdm_wrap_ptr_lr_x = 105;
      *iarb_tdm_wrap_ptr_lr_y = 105;
      for (i = 0; i < 10; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[10] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[10] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 11; i < 20; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_lr_x[20] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      iarb_tdm_tbl_lr_y[20] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_x[21] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[21] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      for (i = 22; i < 30; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[30] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[30] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
      iarb_tdm_tbl_lr_x[31] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
      iarb_tdm_tbl_lr_y[31] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 32; i < 41; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_lr_x[41] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[41] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 42; i < 52; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[52] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[52] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 53; i < 63; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_lr_x[63] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[63] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 64; i < 73; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[73] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      iarb_tdm_tbl_lr_y[73] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      iarb_tdm_tbl_lr_x[74] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[74] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
      for (i = 75; i < 83; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_lr_x[83] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[83] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
      iarb_tdm_tbl_lr_x[84] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
      iarb_tdm_tbl_lr_y[84] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      for (i = 85; i < 94; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        }
      }
      iarb_tdm_tbl_lr_x[94] = IARB_MAIN_TDM__TDM_SLOT_CMIC_PORT;
      iarb_tdm_tbl_lr_y[94] = IARB_MAIN_TDM__TDM_SLOT_EP_LOOPBACK;
      for (i = 95; i < 105; i++) {
        if (i%2 == 0) {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_1;
        } else {
          iarb_tdm_tbl_lr_x[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
          iarb_tdm_tbl_lr_y[i] = IARB_MAIN_TDM__TDM_SLOT_PGW_0;
        }
      }
      iarb_tdm_tbl_lr_x[105] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;
      iarb_tdm_tbl_lr_y[105] = IARB_MAIN_TDM__TDM_SLOT_AUX_OPS_SLOT;

      /* Then check for management ports. */
      if (mgm4x1) {
        iarb_tdm_tbl_lr_x[10] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[21] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[30] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[41] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
      } else if (mgm4x2p5 || mgm1x10) {
        iarb_tdm_tbl_lr_x[10] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[21] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[30] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[41] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[52] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[63] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[74] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
        iarb_tdm_tbl_lr_x[83] = IARB_MAIN_TDM__TDM_SLOT_QGP_PORT;
      }
      break;
  }
}


/**
@name: set_iarb_tdm_table
@param: int, int, int, int, int, int, int*, int*, int[512], int[512]

IARB TDM Schedule Generator:
  Return    => 1 if error, 0 otherwise.
  Input  1  => Core bandwidth - 960/720/640/480.
  Input  2  => 1 if X-pipe is oversub, 0 otherwise.
  Input  3  => 1 if Y-pipe is oversub, 0 otherwise.
  Input  4  => 1 if there are 4x1G management ports, 0 otherwise.
  Input  5  => 1 if there are 4x2.5G management ports, 0 otherwise.
  Input  6  => 1 if there are 1x10G management port, 0 otherwise.
  Output 7  => The X-pipe TDM table wrap pointer value.
  Output 8  => The Y-pipe TDM table wrap pointer value.
  Output 9  => The X-pipe TDM schedule.
  Output 10 => The Y-pipe TDM schedule.
**/
int bcm56850_a0_set_iarb_tdm_table (
          int core_bw,
          int is_x_ovs,
          int is_y_ovs,
          int mgm4x1,
          int mgm4x2p5,
          int mgm1x10,
          int *iarb_tdm_wrap_ptr_x,
          int *iarb_tdm_wrap_ptr_y,
          int iarb_tdm_tbl_x[512],
          int iarb_tdm_tbl_y[512]
          ) {
  int i;
  int is_succ;
  int iarb_tdm_wrap_ptr_ovs_x, iarb_tdm_wrap_ptr_ovs_y;
  int iarb_tdm_wrap_ptr_lr_x, iarb_tdm_wrap_ptr_lr_y;
  TDM_ALLOC(iarb_tdm_tbl_ovs_x, int, 512, "iarb_tdm_tbl_ovs_x");
  TDM_ALLOC(iarb_tdm_tbl_ovs_y, int, 512, "iarb_tdm_tbl_ovs_y");
  TDM_ALLOC(iarb_tdm_tbl_lr_x, int, 512, "iarb_tdm_tbl_lr_x");
  TDM_ALLOC(iarb_tdm_tbl_lr_y, int, 512, "iarb_tdm_tbl_lr_y");

  /*
    Initial IARB TDM table containers - to be copied into final container based
    on the TDM selected.
  */
  if (!(!mgm4x1 && !mgm4x2p5 && !mgm1x10) && !(mgm4x1 ^ mgm4x2p5 ^ mgm1x10)) {
      TDM_ERROR0("IARB TDM: _____ERROR: Multiple management port settings specified!\n");
  }

	init_iarb_tdm_ovs_table(core_bw, mgm4x1, mgm4x2p5, mgm1x10, 
                          &iarb_tdm_wrap_ptr_ovs_x, &iarb_tdm_wrap_ptr_ovs_y,
                          iarb_tdm_tbl_ovs_x, iarb_tdm_tbl_ovs_y);
	init_iarb_tdm_lr_table(core_bw, mgm4x1, mgm4x2p5, mgm1x10,
                         &iarb_tdm_wrap_ptr_lr_x, &iarb_tdm_wrap_ptr_lr_y,
                         iarb_tdm_tbl_lr_x, iarb_tdm_tbl_lr_y);

  if ((is_x_ovs == 0) && (is_y_ovs == 0)) {
    /* The following TDMs have linerate X-pipe and linerate Y-pipe. */
    *iarb_tdm_wrap_ptr_x = iarb_tdm_wrap_ptr_lr_x;
    *iarb_tdm_wrap_ptr_y = iarb_tdm_wrap_ptr_lr_y;
    TDM_MEMCPY(iarb_tdm_tbl_x, iarb_tdm_tbl_lr_x, sizeof(int) * 512);
    TDM_MEMCPY(iarb_tdm_tbl_y, iarb_tdm_tbl_lr_y, sizeof(int) * 512);
  }
  if ((is_x_ovs == 0) && (is_y_ovs == 1)) {
    /* The following TDMs have linerate X-pipe and oversubscribed Y-pipe. */
    *iarb_tdm_wrap_ptr_x = iarb_tdm_wrap_ptr_lr_x;
    *iarb_tdm_wrap_ptr_y = iarb_tdm_wrap_ptr_ovs_y;
    TDM_MEMCPY(iarb_tdm_tbl_x, iarb_tdm_tbl_lr_x, sizeof(int) * 512);
    TDM_MEMCPY(iarb_tdm_tbl_y, iarb_tdm_tbl_ovs_y, sizeof(int) * 512);
  }
  if ((is_x_ovs == 1) && (is_y_ovs == 0)) {
    /* The following TDMs have oversubscribed X-pipe and linerate Y-pipe. */
    *iarb_tdm_wrap_ptr_x = iarb_tdm_wrap_ptr_ovs_x;
    *iarb_tdm_wrap_ptr_y = iarb_tdm_wrap_ptr_lr_y;
    TDM_MEMCPY(iarb_tdm_tbl_x, iarb_tdm_tbl_ovs_x, sizeof(int) * 512);
    TDM_MEMCPY(iarb_tdm_tbl_y, iarb_tdm_tbl_lr_y, sizeof(int) * 512);
  }
  if ((is_x_ovs == 1) && (is_y_ovs == 1)) {
    /* The following TDMs have oversubscribed X-pipe and oversubscribed Y-pipe. */
    *iarb_tdm_wrap_ptr_x = iarb_tdm_wrap_ptr_ovs_x;
    *iarb_tdm_wrap_ptr_y = iarb_tdm_wrap_ptr_ovs_y;
    TDM_MEMCPY(iarb_tdm_tbl_x, iarb_tdm_tbl_ovs_x, sizeof(int) * 512);
    TDM_MEMCPY(iarb_tdm_tbl_y, iarb_tdm_tbl_ovs_y, sizeof(int) * 512);
  }

  TDM_VERBOSE1("IARB TDM: _____DEBUG: iarb_tdm_wrap_ptr_x = %d\n",*iarb_tdm_wrap_ptr_x);
  for (i = 0; i <= *iarb_tdm_wrap_ptr_x; i++) {
    TDM_VERBOSE2("IARB TDM: _____DEBUG: iarb_tdm_tbl_x[%d] = %d\n",i,iarb_tdm_tbl_x[i]);
  }
  TDM_VERBOSE1("IARB TDM: _____DEBUG: iarb_tdm_wrap_ptr_y = %d\n",*iarb_tdm_wrap_ptr_y);
  for (i = 0; i <= *iarb_tdm_wrap_ptr_y; i++) {
    TDM_VERBOSE2("IARB TDM: _____DEBUG: iarb_tdm_tbl_y[%d] = %d\n",i,iarb_tdm_tbl_y[i]);
  }

  /* Always succeeds by definition. */
  is_succ = 1;
  TDM_FREE(iarb_tdm_tbl_ovs_x);
  TDM_FREE(iarb_tdm_tbl_ovs_y);
  TDM_FREE(iarb_tdm_tbl_lr_x);
  TDM_FREE(iarb_tdm_tbl_lr_y);
  return is_succ;
}
#endif /* CDK_CONFIG_INCLUDE_BCM56850_A0 */
