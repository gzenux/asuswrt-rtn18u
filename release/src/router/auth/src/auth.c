
//--------------------------------------------------
// IEEE 802.1x Implementation
//
// File		: auth.c
// Programmer	: Arunesh Mishra
//
//
// Copyright (c) Arunesh Mishra 2002
// All rights reserved.
// Maryland Information and Systems Security Lab
// University of Maryland, College Park.
//
//--------------------------------------------------


#include <stdio.h>
#include <getopt.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <signal.h>

#include "1x_common.h"
#include "1x_auth_pae.h"
#include "1x_nal.h"
#include "1x_radius.h"
#include "1x_fifo.h"
#include "1x_ioctl.h"


#define  SVR_ETH_ADDR       { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00} // we do not need this currently
#define  UDP_OURPORT	    1116
#define  IP_ADDRSIZE        50
// mark following define by referring the definition in 1x_common.h, david+2006-02-06
//#define  MAX_SUPPLICANT     32
//#define  MAX_SUPPLICANT  1


int lib1x_load_config(Dot1x_Authenticator * auth, char *confFileName);

#ifdef START_AUTH_IN_LIB
int lib1x_load_config_param(Dot1x_Authenticator *auth, auth_param_t *pParam);
extern int sockets_open(void);
#endif

//2003-06-27
#define PID_NAME_FMT  "/var/run/auth-%s.pid"

/*
	Debugging message dump
*/
#ifdef DEBUG_DISABLE
#define _AUTH_DBGMSG(fmt, args...)
#else
#define _AUTH_DBGMSG(fmt, args...)	\
	do {printf("[%s-%d]-DEBUG-: " fmt "\n", __FUNCTION__, __LINE__, ## args);} while (0)
#endif
#define _AUTH_ERRMSG(fmt, args...)	\
	do {printf("[%s-%d]-ERROR-: " fmt "\n", __FUNCTION__, __LINE__, ## args);} while (0)

Dot1x_Authenticator	RTLAuthenticator;

#ifdef RTL_WPA_CLIENT
#include "1x_supp_pae.h"
Dot1x_Client		RTLClient;
#endif

#ifdef CLIENT_TLS
#include "xsup_src/profile.h"
#include "xsup_src/xsup_err.h"
#include "xsup_src/xsup_debug.h"
#include "xsup_src/statemachine.h"
#include "xsup_src/eapol.h"
extern struct interface_data *int_list;
#endif

/*
* The following four options are taken from the config file
*/
u_char svrip[IP_ADDRSIZE+1];
u_char dev_svr[LIB1X_MAXDEVLEN];
u_char dev_supp[LIB1X_MAXDEVLEN];
u_short udp_svrport;
#ifdef RTL_RADIUS_2SET
u_char svrip2[IP_ADDRSIZE+1];
u_short udp_svrport2;
#endif




u_char oursvr_addr[ ETHER_ADDRLEN];
u_char oursupp_addr[ ETHER_ADDRLEN];
u_char svraddr[ ETHER_ADDRLEN];
u_char ourip[IP_ADDRSIZE+1];

#ifdef RTL_WPA_CLIENT
#if defined(CONFIG_RTL_802_1X_CLIENT_SUPPORT) || defined(CLIENT_TLS)
	char xsup_conf[50];				
#endif
#endif

#if defined(CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT)
	char ethsup_conf[50];				
#endif

/*
* Determine IP and ETH addresses
* Currently we are using libnet for this.
*/
// david
//void lib1x_resolve()
int lib1x_resolve()
{
	u_char errbuf[LIBNET_ERRBUF_SIZE];
	struct ether_addr * eth;
	struct libnet_link_int * l;

#ifndef PSK_ONLY
	struct in_addr tmpip;
	l = libnet_open_link_interface( dev_svr, errbuf );
	if ( l == NULL ) {
		lib1x_message(MESS_ERROR_FATAL,"open1x: Could not open interface %s", dev_svr );
		return -1;	// david
	}
	tmpip.s_addr = ntohl(libnet_get_ipaddr(l, dev_svr, errbuf));
	if ( tmpip.s_addr == -1 ) {
		lib1x_message(MESS_ERROR_FATAL,"open1x: Could not obtain IP for interface %s", dev_svr );
		return -1;	// david
	}
	strcpy( ourip, inet_ntoa(tmpip));
	eth = libnet_get_hwaddr( l, dev_svr, errbuf);
	if (eth == NULL ) {
		lib1x_message(MESS_ERROR_FATAL,"open1x: Could not obtain ethernet address for interface %s", dev_svr );
		return -1;	// david
	}
	memcpy( oursvr_addr, eth, ETHER_ADDRLEN);

	libnet_close_link_interface(l); // david
#endif

	l = libnet_open_link_interface( dev_supp, errbuf );
	if ( l == NULL ) {
		lib1x_message(MESS_ERROR_FATAL,"open1x: Could not open interface %s", dev_supp );
		return -1;	// david
	}
	eth = libnet_get_hwaddr( l, dev_supp, errbuf);
	if (eth == NULL ) {
		lib1x_message(MESS_ERROR_FATAL,"open1x: Could not obtain ethernet address for interface %s", dev_supp );
		return -2;	// david
	}
	memcpy( oursupp_addr, eth, ETHER_ADDRLEN);

	libnet_close_link_interface(l); // david

	return 0;	// david
}

int lib1x_init_fifo(Dot1x_Authenticator *auth, char *wlan_name)
{


	int 	flags, retVal = 0;
	struct stat status;
	char 	fifo_name[80];

                /* create server's well-known FIFO; OK if already exists */
	/*
        if((mkfifo(DAEMON_FIFO, FILE_MODE) < 0) )
	{
         	//lib1x_message(MESS_DBG_DAEMON, "can't create %s", DAEMON_FIFO);
	}
	*/
                /* open server's well-known for reading and writing */
	sprintf(fifo_name, DAEMON_FIFO, wlan_name);
	if(stat(fifo_name, &status) == 0)
		unlink(fifo_name);

	if((mkfifo(fifo_name, FILE_MODE) < 0)){
		printf("mkfifo %s fifo error: %s!\n", fifo_name, strerror(errno));
		return -1;
	}

	auth->GlobalTxRx->readfifo = open(fifo_name, O_RDONLY, 0);

	if( (flags = fcntl(auth->GlobalTxRx->readfifo, F_GETFL, 0)) < 0)

	{
		printf("F_GETF: error\n");
		retVal = -1;
	}else
	{
		flags |= O_NONBLOCK;
		if( (flags = fcntl(auth->GlobalTxRx->readfifo, F_SETFL, flags)) < 0)
		{
        	printf("F_GETF: error\n");
			retVal = -1;
		}
	}
        auth->GlobalTxRx->dummyfd = open(fifo_name, O_WRONLY, 0);

	auth->GlobalTxRx->RListenFIFO.Octet = (u_char*)malloc(100);

	return retVal;
}

#ifndef START_AUTH_IN_LIB
static int pidfile_acquire(char *pidfile)
{
	int pid_fd;

	if(pidfile == NULL)
		return -1;

	pid_fd = open(pidfile, O_CREAT | O_WRONLY, 0644);
	if (pid_fd < 0)
		printf("Unable to open pidfile %s\n", pidfile);
	else
		lockf(pid_fd, F_LOCK, 0);

	return pid_fd;
}

static void pidfile_write_release(int pid_fd)
{
	FILE *out;

	if(pid_fd < 0)
		return;

	if((out = fdopen(pid_fd, "w")) != NULL) {
		fprintf(out, "%d\n", getpid());
		fclose(out);
	}
	lockf(pid_fd, F_UNLCK, 0);
	close(pid_fd);
}
#endif // !START_AUTH_IN_LIB


void _tmain_hmac();
void TestPassPhrases();
void TestPRF();
void TestRC4();

#if defined(CONFIG_RTL_802_1X_CLIENT_SUPPORT) || defined(CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT)
#define FAILED -1
#define SUCCESS 0

int isFileExist(char *file_name)
{
	struct stat status;

	if ( stat(file_name, &status) < 0)
		return 0;

	return 1;
}

/* To parse wlan client mode related to 802.1x 
*   from /var/wpa-wlan0.conf to /var/1x/1x.conf
*   Pars:
*   outFile: output file name, such as: /var/1x/1x.conf
*/
int prepareClientMode1xConf(Dot1x_Authenticator * auth, const char *outFile)
{
	FILE *inFp, *outFp;
	struct stat status;
	char *p1,*p2,*ptr;
	char buffer[200], tmpBuf[200];
	int len;
	int ret;

	inFp=NULL;
	outFp=NULL;

	outFp = fopen(outFile, "w");
	if (!outFp) {
		printf("open %s error.\n", outFile);//Added for test
		ret=FAILED;
		goto err;
	}

	if(auth->eapType == EAP_MD5){		
		inFp = fopen(XSUP_MD5_CONF_MODULE_FILE, "r");
		if (!inFp) {
			printf("%s(%d): fopen %s failed.\n",__FUNCTION__,__LINE__, XSUP_MD5_CONF_MODULE_FILE);//Added for test
			ret=FAILED;
			goto err;
		}

		while(fgets(buffer, sizeof(buffer), inFp) != NULL){
			ptr=strstr(buffer, "@eap_user_id@");
			if(ptr != NULL){
				//To replace "@eap_user_id@"
				memset(tmpBuf, 0, sizeof(tmpBuf));
				p1=buffer;
				p2=ptr;
				
				len=0;
				strncpy(tmpBuf, p1, p2-p1);
				len=p2-p1;
				strncpy(tmpBuf+len, auth->eapUserId, strlen(auth->eapUserId));
				len+=strlen(auth->eapUserId);
				ptr+=strlen("@eap_user_id@");
				strcpy(tmpBuf+len, ptr);

				fputs(tmpBuf, outFp);
				continue;
			}

			ptr=strstr(buffer, "@eap_md5_username@");
			if(ptr != NULL){
				//To replace "@eap_md5_username@"
				memset(tmpBuf, 0, sizeof(tmpBuf));
				p1=buffer;
				p2=ptr;
				
				len=0;
				strncpy(tmpBuf, p1, p2-p1);
				len=p2-p1;
				strncpy(tmpBuf+len, auth->rsUserName, strlen(auth->rsUserName));
				len+=strlen(auth->rsUserName);
				ptr+=strlen("@eap_md5_username@");
				strcpy(tmpBuf+len, ptr);

				fputs(tmpBuf, outFp);
				continue;
			}

			ptr=strstr(buffer, "@eap_md5_passwd@");
			if(ptr != NULL){
				//To replace "@eap_md5_passwd@"
				memset(tmpBuf, 0, sizeof(tmpBuf));
				p1=buffer;
				p2=ptr;
				
				len=0;
				strncpy(tmpBuf, p1, p2-p1);
				len=p2-p1;
				strncpy(tmpBuf+len, auth->rsUserPasswd, strlen(auth->rsUserPasswd));
				len+=strlen(auth->rsUserPasswd);
				ptr+=strlen("@eap_md5_passwd@");
				strcpy(tmpBuf+len, ptr);

				fputs(tmpBuf, outFp);
				continue;
			}
			
			fputs(buffer, outFp);
		}
	}
	else if(auth->eapType == EAP_TLS){
		inFp = fopen(XSUP_TLS_CONF_MODULE_FILE, "r");
		if (!inFp) {
			printf("%s(%d): fopen %s failed.\n",__FUNCTION__,__LINE__, XSUP_TLS_CONF_MODULE_FILE);//Added for test
			ret=FAILED;
			goto err;
		}

		while(fgets(buffer, sizeof(buffer), inFp) != NULL){
			ptr=strstr(buffer, "@eap_user_id@");
			if(ptr != NULL){
				//To replace "@eap_user_id@"
				memset(tmpBuf, 0, sizeof(tmpBuf));
				p1=buffer;
				p2=ptr;
				
				len=0;
				strncpy(tmpBuf, p1, p2-p1);
				len=p2-p1;
				strncpy(tmpBuf+len, auth->eapUserId, strlen(auth->eapUserId));
				len+=strlen(auth->eapUserId);
				ptr+=strlen("@eap_user_id@");
				strcpy(tmpBuf+len, ptr);

				fputs(tmpBuf, outFp);
				continue;
			}

#if 1
			// To configure eap_tls related certs
			if(auth->rsBandSel==PHYBAND_5G){
				ptr=strstr(buffer, "#eap_tls_user_cert_5g#");
				if(ptr != NULL){
					//To rm "#eap_tls_user_cert_5g#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_tls_user_cert_5g#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}

				ptr=strstr(buffer, "#eap_tls_user_key_5g#");
				if(ptr != NULL){
					//To rm "#eap_tls_user_key_5g#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_tls_user_key_5g#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}

				ptr=strstr(buffer, "#eap_tls_root_cert_5g#");
				if(ptr != NULL){
					//To rm "#eap_tls_root_cert_5g#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_tls_root_cert_5g#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}
			}
			else if(auth->rsBandSel==PHYBAND_2G){
				ptr=strstr(buffer, "#eap_tls_user_cert_2g#");
				if(ptr != NULL){
					//To rm "#eap_tls_user_cert_2g#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_tls_user_cert_2g#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}

				ptr=strstr(buffer, "#eap_tls_user_key_2g#");
				if(ptr != NULL){
					//To rm "#eap_tls_user_key_2g#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_tls_user_key_2g#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}

				ptr=strstr(buffer, "#eap_tls_root_cert_2g#");
				if(ptr != NULL){
					//To rm "#eap_tls_root_cert_2g#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_tls_root_cert_2g#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}
			}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
			else if(auth->ethDot1xMode & ETH_DOT1X_CLIENT_MODE){
				ptr=strstr(buffer, "#eap_tls_user_cert_eth#");
				if(ptr != NULL){
					//To rm "#eap_tls_user_cert_eth#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_tls_user_cert_eth#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}

				ptr=strstr(buffer, "#eap_tls_user_key_eth#");
				if(ptr != NULL){
					//To rm "#eap_tls_user_key_eth#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_tls_user_key_eth#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}

				ptr=strstr(buffer, "#eap_tls_root_cert_eth#");
				if(ptr != NULL){
					//To rm "#eap_tls_root_cert_eth#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_tls_root_cert_eth#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}
			}
#endif
			else{
				printf("%s(%d): [Warning] wrong auth->rsBandSel=%d.\n",__FUNCTION__,__LINE__,auth->rsBandSel);//Added for test
				ret=FAILED;
				goto err;
			}
#endif

			if((auth->rsUserCertPasswd != NULL) && (strlen(auth->rsUserCertPasswd)!=0)){
				ptr=strstr(buffer, "#eap_tls_user_key_pass#");
				if(ptr != NULL){
					//To rm "#eap_tls_user_key_pass#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_tls_user_key_pass#");

					//To replace "@eap_tls_user_cert_passwd@"
					p1=ptr;
					ptr=strstr(p1, "@eap_tls_user_cert_passwd@");
					if(ptr != NULL){
						p2=ptr;
						
						len=0;
						strncpy(tmpBuf, p1, p2-p1);
						len=p2-p1;
						strncpy(tmpBuf+len, auth->rsUserCertPasswd, strlen(auth->rsUserCertPasswd));
						len+=strlen(auth->rsUserCertPasswd);
						ptr+=strlen("@eap_tls_user_cert_passwd@");
						strcpy(tmpBuf+len, ptr);

						fputs(tmpBuf, outFp);
						continue;
						
					}
					else{
						printf("%s(%d): [Warning] \"@eap_tls_user_cert_passwd@\" not found.\n",__FUNCTION__,__LINE__);//Added for test
						ret=FAILED;
						goto err;
					}					
				}
			}
			
			fputs(buffer, outFp);
		}
	}
	else if(auth->eapType == EAP_PEAP){
		inFp = fopen(XSUP_PEAP_CONF_MODULE_FILE, "r");
		if (!inFp) {
			printf("%s(%d): fopen %s failed.\n",__FUNCTION__,__LINE__, XSUP_PEAP_CONF_MODULE_FILE);//Added for test
			ret=FAILED;
			goto err;
		}

		while(fgets(buffer, sizeof(buffer), inFp) != NULL){
			ptr=strstr(buffer, "@eap_user_id@");
			if(ptr != NULL){
				//To replace "@eap_user_id@"
				memset(tmpBuf, 0, sizeof(tmpBuf));
				p1=buffer;
				p2=ptr;
				
				len=0;
				strncpy(tmpBuf, p1, p2-p1);
				len=p2-p1;
				strncpy(tmpBuf+len, auth->eapUserId, strlen(auth->eapUserId));
				len+=strlen(auth->eapUserId);
				ptr+=strlen("@eap_user_id@");
				strcpy(tmpBuf+len, ptr);

				fputs(tmpBuf, outFp);
				continue;
			}

			ptr=strstr(buffer, "@eap_peap_inside_type@");
			if(ptr != NULL){
				//To replace "@eap_peap_inside_type@"
				memset(tmpBuf, 0, sizeof(tmpBuf));
				p1=buffer;
				p2=ptr;
				
				len=0;
				strncpy(tmpBuf, p1, p2-p1);
				len=p2-p1;

				if(auth->eapInsideType == INSIDE_MSCHAPV2){
					strncpy(tmpBuf+len, "eap_mschapv2", strlen("eap_mschapv2"));
					len+=strlen("eap_mschapv2");
				}
				else{
					printf("%s(%d): [err] auth->eapInsideType(%d) not supported here.\n",__FUNCTION__,__LINE__,auth->eapInsideType);//Added for test
					ret=FAILED;
					goto err;
				}
				
				ptr+=strlen("@eap_peap_inside_type@");
				strcpy(tmpBuf+len, ptr);

				fputs(tmpBuf, outFp);
				continue;
			}

			if(auth->eapInsideType == INSIDE_MSCHAPV2){
				ptr=strstr(buffer, "#eap_peap_mschapv2_comment#");
				if(ptr != NULL){
					//To rm "#eap_peap_mschapv2_comment#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_peap_mschapv2_comment#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}

				ptr=strstr(buffer, "#eap_peap_mschapv2_username#");
				if(ptr != NULL){
					//To rm "#eap_peap_mschapv2_username#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_peap_mschapv2_username#");

					//To replace "@eap_peap_mschapv2_username@"
					p1=ptr;
					ptr=strstr(p1, "@eap_peap_mschapv2_username@");
					if(ptr != NULL){
						p2=ptr;
						
						len=0;
						strncpy(tmpBuf, p1, p2-p1);
						len=p2-p1;
						strncpy(tmpBuf+len, auth->rsUserName, strlen(auth->rsUserName));
						len+=strlen(auth->rsUserName);
						ptr+=strlen("@eap_peap_mschapv2_username@");
						strcpy(tmpBuf+len, ptr);

						fputs(tmpBuf, outFp);
						continue;
						
					}
					else{
						printf("%s(%d): [Warning] \"@eap_peap_mschapv2_username@\" not found.\n",__FUNCTION__,__LINE__);//Added for test
						ret=FAILED;
						goto err;
					}					
				}

				ptr=strstr(buffer, "#eap_peap_mschapv2_password#");
				if(ptr != NULL){
					//To rm "#eap_peap_mschapv2_password#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_peap_mschapv2_password#");

					//To replace "@eap_peap_mschapv2_passwd@"
					p1=ptr;
					ptr=strstr(p1, "@eap_peap_mschapv2_passwd@");
					if(ptr != NULL){
						p2=ptr;
						
						len=0;
						strncpy(tmpBuf, p1, p2-p1);
						len=p2-p1;
						strncpy(tmpBuf+len, auth->rsUserPasswd, strlen(auth->rsUserPasswd));
						len+=strlen(auth->rsUserPasswd);
						ptr+=strlen("@eap_peap_mschapv2_passwd@");
						strcpy(tmpBuf+len, ptr);

						fputs(tmpBuf, outFp);
						continue;
						
					}
					else{
						printf("%s(%d): [Warning] \"@eap_peap_mschapv2_passwd@\" not found.\n",__FUNCTION__,__LINE__);//Added for test
						ret=FAILED;
						goto err;
					}					
				}
			}
			else{	//To add more eap_peap inside type
				printf("%s(%d): [err] peap inside type (%d) not supported!\n",__FUNCTION__,__LINE__,auth->eapInsideType);//Added for test
			}

			// To configure eap_peap related certs
			if((auth->rsBandSel==PHYBAND_5G)&&(isFileExist(RS_USER_CERT_5G) == 1)){
				ptr=strstr(buffer, "#eap_peap_user_cert_5g#");
				if(ptr != NULL){
					//To rm "#eap_peap_user_cert_5g#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_peap_user_cert_5g#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}

				ptr=strstr(buffer, "#eap_peap_user_key_5g#");
				if(ptr != NULL){
					//To rm "#eap_peap_user_key_5g#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_peap_user_key_5g#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}

				if((auth->rsUserCertPasswd != NULL) && (strlen(auth->rsUserCertPasswd)!=0)){
					ptr=strstr(buffer, "#eap_peap_user_key_pass#");
					if(ptr != NULL){
						//To rm "#eap_peap_user_key_pass#"
						memset(tmpBuf, 0, sizeof(tmpBuf));
						ptr += strlen("#eap_peap_user_key_pass#");

						//To replace "@eap_peap_user_cert_passwd@"
						p1=ptr;
						ptr=strstr(p1, "@eap_peap_user_cert_passwd@");
						if(ptr != NULL){
							p2=ptr;
							
							len=0;
							strncpy(tmpBuf, p1, p2-p1);
							len=p2-p1;
							strncpy(tmpBuf+len, auth->rsUserCertPasswd, strlen(auth->rsUserCertPasswd));
							len+=strlen(auth->rsUserCertPasswd);
							ptr+=strlen("@eap_peap_user_cert_passwd@");
							strcpy(tmpBuf+len, ptr);

							fputs(tmpBuf, outFp);
							continue;
							
						}
						else{
							printf("%s(%d): [Warning] \"@eap_peap_user_cert_passwd@\" not found.\n",__FUNCTION__,__LINE__);//Added for test
							ret=FAILED;
							goto err;
						}					
					}
				}
			}
			else if((auth->rsBandSel==PHYBAND_2G)&&(isFileExist(RS_USER_CERT_2G) == 1)){
				ptr=strstr(buffer, "#eap_peap_user_cert_2g#");
				if(ptr != NULL){
					//To rm "#eap_peap_user_cert_2g#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_peap_user_cert_2g#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}

				ptr=strstr(buffer, "#eap_peap_user_key_2g#");
				if(ptr != NULL){
					//To rm "#eap_peap_user_key_2g#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_peap_user_key_2g#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}

				if((auth->rsUserCertPasswd != NULL) && (strlen(auth->rsUserCertPasswd)!=0)){
					ptr=strstr(buffer, "#eap_peap_user_key_pass#");
					if(ptr != NULL){
						//To rm "#eap_peap_user_key_pass#"
						memset(tmpBuf, 0, sizeof(tmpBuf));
						ptr += strlen("#eap_peap_user_key_pass#");

						//To replace "@eap_peap_user_cert_passwd@"
						p1=ptr;
						ptr=strstr(p1, "@eap_peap_user_cert_passwd@");
						if(ptr != NULL){
							p2=ptr;
							
							len=0;
							strncpy(tmpBuf, p1, p2-p1);
							len=p2-p1;
							strncpy(tmpBuf+len, auth->rsUserCertPasswd, strlen(auth->rsUserCertPasswd));
							len+=strlen(auth->rsUserCertPasswd);
							ptr+=strlen("@eap_peap_user_cert_passwd@");
							strcpy(tmpBuf+len, ptr);

							fputs(tmpBuf, outFp);
							continue;
							
						}
						else{
							printf("%s(%d): [Warning] \"@eap_peap_user_cert_passwd@\" not found.\n",__FUNCTION__,__LINE__);//Added for test
							ret=FAILED;
							goto err;
						}					
					}
				}
			}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
			else if((auth->ethDot1xMode & ETH_DOT1X_CLIENT_MODE) && (isFileExist(RS_USER_CERT_ETH) == 1)){
				ptr=strstr(buffer, "#eap_peap_user_cert_eth#");
				if(ptr != NULL){
					//To rm "#eap_peap_user_cert_eth#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_peap_user_cert_eth#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}

				ptr=strstr(buffer, "#eap_peap_user_key_eth#");
				if(ptr != NULL){
					//To rm "#eap_peap_user_key_2g#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_peap_user_key_eth#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}
				if((auth->rsUserCertPasswd != NULL) && (strlen(auth->rsUserCertPasswd)!=0)){
					ptr=strstr(buffer, "#eap_peap_user_key_pass#");
					if(ptr != NULL){
						//To rm "#eap_peap_user_key_pass#"
						memset(tmpBuf, 0, sizeof(tmpBuf));
						ptr += strlen("#eap_peap_user_key_pass#");

						//To replace "@eap_peap_user_cert_passwd@"
						p1=ptr;
						ptr=strstr(p1, "@eap_peap_user_cert_passwd@");
						if(ptr != NULL){
							p2=ptr;
							
							len=0;
							strncpy(tmpBuf, p1, p2-p1);
							len=p2-p1;
							strncpy(tmpBuf+len, auth->rsUserCertPasswd, strlen(auth->rsUserCertPasswd));
							len+=strlen(auth->rsUserCertPasswd);
							ptr+=strlen("@eap_peap_user_cert_passwd@");
							strcpy(tmpBuf+len, ptr);

							fputs(tmpBuf, outFp);
							continue;
							
						}
						else{
							printf("%s(%d): [Warning] \"@eap_peap_user_cert_passwd@\" not found.\n",__FUNCTION__,__LINE__);//Added for test
							ret=FAILED;
							goto err;
						}					
					}
				}
			}
#endif

			if((auth->rsBandSel==PHYBAND_5G)&&(isFileExist(RS_ROOT_CERT_5G) == 1)){
				ptr=strstr(buffer, "#eap_peap_root_cert_5g#");
				if(ptr != NULL){
					//To rm "#eap_peap_root_cert_5g#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_peap_root_cert_5g#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}
			}
			else if((auth->rsBandSel==PHYBAND_2G)&&(isFileExist(RS_ROOT_CERT_2G) == 1)){
				ptr=strstr(buffer, "#eap_peap_root_cert_2g#");
				if(ptr != NULL){
					//To rm "#eap_peap_root_cert_2g#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_peap_root_cert_2g#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}
			}
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
			else if((auth->ethDot1xMode & ETH_DOT1X_CLIENT_MODE) && (isFileExist(RS_ROOT_CERT_ETH) == 1)){
				ptr=strstr(buffer, "#eap_peap_root_cert_eth#");
				if(ptr != NULL){
					//To rm "#eap_peap_root_cert_2g#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_peap_root_cert_eth#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}
			}
#endif
			else{
				ptr=strstr(buffer, "#eap_peap_root_cert_none#");
				if(ptr != NULL){
					//To rm "#eap_peap_root_cert_none#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_peap_root_cert_none#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}
			}
						
			fputs(buffer, outFp);
		}
	}
#ifdef RTL_TTLS_CLIENT
	else if(auth->eapType == EAP_TTLS)
	{
		inFp = fopen(XSUP_TTLS_CONF_MODULE_FILE, "r");
		if (!inFp) {
			printf("%s(%d): fopen %s failed.\n",__FUNCTION__,__LINE__, XSUP_PEAP_CONF_MODULE_FILE);//Added for test
			ret=FAILED;
			goto err;
		}

		while(fgets(buffer, sizeof(buffer), inFp) != NULL){
			ptr=strstr(buffer, "@eap_user_id@");
			if(ptr != NULL){
				//To replace "@eap_user_id@"
				memset(tmpBuf, 0, sizeof(tmpBuf));
				p1=buffer;
				p2=ptr;
				
				len=0;
				strncpy(tmpBuf, p1, p2-p1);
				len=p2-p1;
				strncpy(tmpBuf+len, auth->eapUserId, strlen(auth->eapUserId));
				len+=strlen(auth->eapUserId);
				ptr+=strlen("@eap_user_id@");
				strcpy(tmpBuf+len, ptr);

				fputs(tmpBuf, outFp);
				continue;
			}

			ptr=strstr(buffer, "@eap_ttls_phase2_type@");
			if(ptr != NULL){
				//To replace "@eap_peap_inside_type@"
				memset(tmpBuf, 0, sizeof(tmpBuf));
				p1=buffer;
				p2=ptr;
				
				len=0;
				strncpy(tmpBuf, p1, p2-p1);
				len=p2-p1;

				if(auth->ttlsPhase2Type == TTLS_PHASE2_EAP){
					if(auth->ttlsPhase2EapMethod == TTLS_PHASE2_EAP_MD5){
					strncpy(tmpBuf+len, "eap_md5", strlen("eap_md5"));
					len+=strlen("eap_md5");
					}
					else{
						printf("%s(%d): [err] auth->ttlsPhase2EapMethod(%d) not supported here.\n",__FUNCTION__,__LINE__,auth->ttlsPhase2EapMethod);
						ret=FAILED;
						goto err;
					}
				}
				else{
					printf("%s(%d): [err] auth->ttlsPhase2Type(%d) not supported here.\n",__FUNCTION__,__LINE__,auth->ttlsPhase2Type);
					ret=FAILED;
					goto err;
				}
				
				ptr+=strlen("@eap_ttls_phase2_type@");
				strcpy(tmpBuf+len, ptr);

				fputs(tmpBuf, outFp);
				continue;
			}

			if(auth->ttlsPhase2Type == TTLS_PHASE2_EAP && auth->ttlsPhase2EapMethod == TTLS_PHASE2_EAP_MD5){
				ptr=strstr(buffer, "#eap_ttls_eap_md5_comment#");
				if(ptr != NULL){
					//To rm "#eap_peap_mschapv2_comment#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_ttls_eap_md5_comment#");
					strcpy(tmpBuf, ptr);
					
					fputs(tmpBuf, outFp);
					continue;
				}

				ptr=strstr(buffer, "#eap_ttls_eap_md5_username#");
				if(ptr != NULL){
					//To rm "#eap_peap_mschapv2_username#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_ttls_eap_md5_username#");

					//To replace "@eap_peap_mschapv2_username@"
					p1=ptr;
					ptr=strstr(p1, "@eap_ttls_eap_md5_username@");
					if(ptr != NULL){
						p2=ptr;
						
						len=0;
						strncpy(tmpBuf, p1, p2-p1);
						len=p2-p1;
						strncpy(tmpBuf+len, auth->rsUserName, strlen(auth->rsUserName));
						len+=strlen(auth->rsUserName);
						ptr+=strlen("@eap_ttls_eap_md5_username@");
						strcpy(tmpBuf+len, ptr);

						fputs(tmpBuf, outFp);
						continue;
						
					}
					else{
						printf("%s(%d): [Warning] \"@eap_ttls_eap_md5_username@\" not found.\n",__FUNCTION__,__LINE__);//Added for test
						ret=FAILED;
						goto err;
					}					
				}

				ptr=strstr(buffer, "#eap_ttls_eap_md5_password#");
				if(ptr != NULL){
					//To rm "#eap_peap_mschapv2_password#"
					memset(tmpBuf, 0, sizeof(tmpBuf));
					ptr += strlen("#eap_ttls_eap_md5_password#");

					//To replace "@eap_peap_mschapv2_passwd@"
					p1=ptr;
					ptr=strstr(p1, "@eap_ttls_eap_md5_password@");
					if(ptr != NULL){
						p2=ptr;
						
						len=0;
						strncpy(tmpBuf, p1, p2-p1);
						len=p2-p1;
						strncpy(tmpBuf+len, auth->rsUserPasswd, strlen(auth->rsUserPasswd));
						len+=strlen(auth->rsUserPasswd);
						ptr+=strlen("@eap_ttls_eap_md5_password@");
						strcpy(tmpBuf+len, ptr);

						fputs(tmpBuf, outFp);
						continue;
						
					}
					else{
						printf("%s(%d): [Warning] \"@eap_ttls_eap_md5_password@\" not found.\n",__FUNCTION__,__LINE__);//Added for test
						ret=FAILED;
						goto err;
					}					
				}
			}
			
						
			fputs(buffer, outFp);
		}
	}
#endif
	else{
		printf("%s(%d): [err] auth->eapType(%d) not supported here.\n",__FUNCTION__,__LINE__,auth->eapType);//Added for test
		ret=FAILED;
		goto err;
	}

	ret=SUCCESS;

err:
	if(inFp)
		fclose(inFp);
	
	if(outFp)
		fclose(outFp);
	
	return ret;
}
#endif

#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
void ProcEthSignalEvent(int sig)
{
	Dot1x_Authenticator     * auth = &RTLAuthenticator;
	int isMore =0;
	do{
		isMore = lib1x_control_Eth_Poll(auth);
	}while(isMore);
}
int lib1x_process_eth_eap_event(Dot1x_Authenticator *auth)
{
	struct lib1x_nal_intfdesc * descSupp = auth->GlobalTxRx->network_supp;
	rtl802Dot1xEapPkt *eth_eap;
	int isMore,port_num;
	int suppid;
	
	eth_eap = (rtl802Dot1xEapPkt *)auth->GlobalTxRx->RecvBuf;	
	auth->GlobalTxRx->network_supp->packet.data = eth_eap->item;
	auth->GlobalTxRx->network_supp->packet.caplen = eth_eap->item_size;
	isMore = eth_eap->flag;
	port_num = eth_eap->rx_port_num;
	descSupp->packet.caplen = eth_eap->item_size;
	
	memcpy(descSupp->packet_buffer,eth_eap->item, descSupp->packet.caplen);
	descSupp->packet.data = descSupp->packet_buffer;
	if(auth->currentRole == role_eth && (auth->ethDot1xMode & ETH_DOT1X_CLIENT_MODE) && ((1 << eth_eap->rx_port_num) & auth->ethDot1xClientModePortMask))
	{
		lib1x_suppsm_capture_auth( auth->client->global, descSupp, & descSupp->packet );
	}else if (auth->currentRole == role_eth && (auth->ethDot1xMode & ETH_DOT1X_PROXY_MODE) && ((1 << eth_eap->rx_port_num) & auth->ethDot1xProxyModePortMask))
	{

		suppid = lib1x_eth_search_supp(auth, &descSupp->packet, port_num);
		if(suppid != -1 &&( !memcmp(descSupp->packet.data, auth->GlobalTxRx->oursupp_addr, ETHER_ADDRLEN )|| auth->currentRole == role_eth))
		{
		
			lib1x_authsm_capture_supp(auth->Supp[suppid]->global, descSupp, & descSupp->packet);
			lib1x_auth_process(auth);
		}
	}
	return isMore;	
}


#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
int ethdot1x_client_mode_init(Dot1x_Authenticator *auth)
{
	void global_deinit(int);
	static const int xsup_argc = 7;

	struct sigaction action;

	sprintf(ethsup_conf, XSUP_CONF_FILE_NAME_FMT, "eth1");
	if(prepareClientMode1xConf(&RTLAuthenticator, ethsup_conf) == -1){
		printf("%s(%d): prepareClientMode1xConf() failed.\n",__FUNCTION__,__LINE__);//Added for test
	}
	lib1x_init_supp(&RTLAuthenticator, &RTLClient);
	static char *xsup_argv[]= { "xsuplicant", "-i", "eth1", "-c", ethsup_conf, "-d", "-1" };	//Modified for test
	lib1x_reset_supp(RTLClient.global);
	lib1x_message(MESS_DBG_SUPP, "Wait for packet Timeout, Resent");
	{
	xsup_main(xsup_argc, xsup_argv);

	// When we quit, cleanup.
	action.sa_handler = (void (*)())global_deinit;
	action.sa_flags = 0;

	if (sigaction(SIGTERM,&action,0)==-1)
	{
		perror( "sigaction");
		printf("sigaction %d\n", __LINE__);
		return 1;
	}
	if (sigaction(SIGINT,&action,0)==-1)
	{
		perror( "sigaction");
		printf("sigaction %d\n", __LINE__);
		return 1;
	}
	if (sigaction(SIGQUIT,&action,0)==-1)
	{
		perror( "sigaction");
		printf("sigaction %d\n", __LINE__);
		return 1;
	}
	eapol_init(int_list);
	}
}
void ethdot1x_client_port_down()
{
	struct interface_data *incur;
	incur = int_list;
	if(incur != NULL)
		eapol_cleanup(int_list);	
}
void ethdot1x_client_port_up()
{
	struct interface_data *incur;
	incur = int_list;
	if(incur != NULL){
		eapol_init(int_list);
		lib1x_reset_supp(RTLClient.global);
	}
}

#endif

	
//extern u_char	EMPTY_ADDR;
static u_char	EMPTY_ADDR[] = {0xEE, 0xEE, 0xEE, 0xEE, 0xEE, 0xEE};
int lib1x_process_eth_port_down_event(Dot1x_Authenticator *auth)
{
	rtl802Dot1xPortStateInfo *portinfo;
	Global_Params *global;
	Auth_Pae * auth_pae;
	int isMore;
	int i, j;
	unsigned int portmask;
	
	portinfo = (rtl802Dot1xPortStateInfo *)auth->GlobalTxRx->RecvBuf;
	portmask = portinfo->port_mask;
	isMore = portinfo->flag;
	
	lib1x_message(MESS_DBG_CONTROL, "Receive port down event portmask=0x%x\n", portmask);
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
	if(auth->currentRole == role_eth && (auth->ethDot1xMode & ETH_DOT1X_CLIENT_MODE) && (portmask & auth->ethDot1xClientModePortMask))
	{
		ethdot1x_client_port_down();
	}
#endif
	for (j = 0; j < sizeof(unsigned int); j++)
	{
		if ((1<<j) & portmask)
		{
			for( i = 0; i < auth->MaxSupplicant ; i++)
			{
				// reduce pre-alloc memory size, david+2006-02-06			
				//				if( auth->Supp[i]->isEnable )
				
				if(auth->Supp[i] && auth->Supp[i]->isEnable)
				{
					global = auth->Supp[i]->global;
					auth_pae = auth->Supp[i]->global->theAuthenticator;
					if(auth->Supp[i]->global->port_num == j)
					{
						
						lib1x_control_eth_SetPORT(auth->Supp[i]->global, DOT11_PortStatus_Unauthorized);
						
						global->auth->Supp[global->index]->isEnable = FALSE;
						
						memcpy(auth_pae->supp_addr, EMPTY_ADDR, ETHER_ADDRLEN);
						
						//global->akm_sm->CurrentReplayCounter.field.HighPart = 0;
						//global->akm_sm->CurrentReplayCounter.field.LowPart = 0;
						
						auth->Supp[i]->isEnable = FALSE;
						global->auth->NumOfSupplicant--;
						lib1x_message(MESS_DBG_CONTROL, "disable supplicant client portnum=%d NumOfSupplicant=%d\n", j, global->auth->NumOfSupplicant);
						
					}
				}
			}
		}
	}
	
	return isMore;	
}
int lib1x_process_eth_port_up_event(Dot1x_Authenticator *auth)
{
	rtl802Dot1xPortStateInfo *portinfo;
	int isMore;
	int i, j;
	unsigned int portmask;
	
	portinfo = (rtl802Dot1xPortStateInfo *)auth->GlobalTxRx->RecvBuf;
	portmask = portinfo->port_mask;
	isMore = portinfo->flag;
	
	lib1x_message(MESS_DBG_CONTROL, "Receive port up event portmask=0x%x\n", portmask);
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
	if(auth->currentRole == role_eth && (auth->ethDot1xMode & ETH_DOT1X_CLIENT_MODE) && (portmask & auth->ethDot1xClientModePortMask))
	{
		ethdot1x_client_port_up();
	}
#endif
	return isMore; 
}

#endif

#ifdef START_AUTH_IN_LIB
int auth_main(auth_param_t *pParam)
#else
int  main( int numArgs, char ** theArgs )
#endif
{


	u_char eth[50];
	char pid_name[100];
	int i;

	Dot1x_Authenticator     * auth = &RTLAuthenticator;

#ifndef START_AUTH_IN_LIB
	if ( numArgs < 5 ) {
		printf("Usage: auth wlan-interface eth-interface mode conf-file\n");
		return -1;
	}

#ifdef RTL_WPA_CLIENT
// david -------------------------------
//	if (numArgs == 4) {
		if(!strcmp(theArgs[3], "client-infra"))
			RTLAuthenticator.currentRole = role_Supplicant_infra;
		else if(!strcmp(theArgs[3], "client-adhoc"))
			RTLAuthenticator.currentRole = role_Supplicant_adhoc;
		else if(!strcmp(theArgs[3], "auth"))
			RTLAuthenticator.currentRole = role_Authenticator;
		else if(!strcmp(theArgs[3], "wds"))
			RTLAuthenticator.currentRole = role_wds;
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
		else if(!strcmp(theArgs[3],"eth"))
			RTLAuthenticator.currentRole = role_eth;
#endif
		else {
			printf("\nArgument 4 is invalid. Valid value are: auth, client-infra or client-adhoc\n");
			exit(1);
		}
//	}
//	else
#endif
//		RTLAuthenticator.currentRole = role_Authenticator;

	RTLAuthenticator.NumOfSupplicant = 0;
//-------------------------------------


#ifdef _ON_RTL8181_TARGET
// 2003-06-27, destroy old process and create a PID file -------
{	FILE *fp;
	char line[40];
	pid_t pid;
	int pid_fd;
	sprintf(pid_name, PID_NAME_FMT, theArgs[1]);
	if ((fp = fopen(pid_name, "r")) != NULL) {
		fgets(line, sizeof(line), fp);
		if ( sscanf(line, "%d", &pid) ) {
			if (pid > 1)
				kill(pid, SIGTERM);
		}
		fclose(fp);
	}
	pid_fd = pidfile_acquire(pid_name);
	if (pid_fd < 0)
		return 0;

	if (daemon(0,1) == -1) {
		printf("fork auth error!\n");
		exit(1);
	}
	pidfile_write_release(pid_fd);

}
	setsid(); // david, requested from abocom
//-----------------------------------------------------------
#endif


#ifdef _ON_RTL8181_TARGET
/*
	Application Note:
		Usage of 802.1x AUTH daemon:

			" auth wlan_interface lan_interface auth wpa_conf & "

				- wlan_interface:	WLAN interface, e.g. wlan0
				- lan_interface	:	LAN interface which connects to Radius server, e.g. br0 or eth1
				- "auth"	:	denote to act as authenticator
				- wpa_conf	:	path of wpa config file, e.g., /var/wpa-wlan0.conf
*/
	/* wlan_interface */
	if (strlen(theArgs[1]) >= sizeof(dev_supp))
	{
		_AUTH_ERRMSG("String Length of parameter [wlan_interface] exceeds (MAX: %d)", sizeof(dev_supp));
		return -1;
	}
	_AUTH_DBGMSG("WLAN interface : %s", theArgs[1]);
	strcpy(dev_supp, theArgs[1]);

	/* lan_interface */
	if (strlen(theArgs[2]) >= sizeof(dev_svr))
	{
		_AUTH_ERRMSG("String Length of parameter [lan_interface] exceeds (MAX: %d)", sizeof(dev_svr));
		return -1;
	}
	_AUTH_DBGMSG("Radius interface : %s", theArgs[2]);
	strcpy(dev_svr, theArgs[2]);

	/* wpa_conf */
	if (lib1x_load_config(&RTLAuthenticator, theArgs[4]) != 0)
	{
		_AUTH_ERRMSG("Configuration file [%s] loading FAILED!", theArgs[4]);
		return -1;
	}
	_AUTH_DBGMSG("Configuration file [%s] loading OK!", theArgs[4]);

#else
	lib1x_load_config(&RTLAuthenticator, "/etc/wpa.conf");
        memcpy(dev_svr, "eth0", sizeof("eth0"));
        memcpy(dev_supp, "wlan0", sizeof("wlan0"));
#endif

#else

	lib1x_load_config_param(&RTLAuthenticator, pParam);

	strcpy(dev_supp, "wlan0");
	RTLAuthenticator.currentRole = pParam->role;

#endif // START_AUTH_IN_LIB

	memcpy(svrip, RTLAuthenticator.svrip, sizeof(svrip));
	udp_svrport = auth->udp_svrport;
#ifdef RTL_RADIUS_2SET
	memcpy(svrip2, RTLAuthenticator.svrip2, sizeof(svrip2));
	udp_svrport2 = auth->udp_svrport2;
#endif

// david ------------------------
//	lib1x_resolve();
#ifdef RTL_WPA_CLIENT
	while ((RTLAuthenticator.currentRole != role_Supplicant_adhoc) &&
			(RTLAuthenticator.currentRole != role_wds))
#else
	while (1)
#endif
	{
		i = lib1x_resolve();
		if ( i == 0 ) // success
			break;
		if ( i == -1 ) {
			sleep(1);
			continue;
		}
		printf("802.1x daemon: open interface failed!\n");
		exit(1);
	}
//-------------------------------

	lib1x_print_etheraddr( eth, oursvr_addr );
	lib1x_print_etheraddr( eth, oursupp_addr );

#ifdef CONFIG_RTL865X
	printf("Initiate IEEE 802.1X (WPA) daemon, version %d.%d (%d-%d-%d)\n",
					AUTH_865XPLATFORM_VERH,
					AUTH_865XPLATFORM_VERL,
					AUTH_865XPLATFORM_Y,
					AUTH_865XPLATFORM_M,
					AUTH_865XPLATFORM_D);
#else
	printf("IEEE 802.1x (WPA) daemon, version 1.8f \n");
#endif	/* CONFIG_RTL865X */


	RTLAuthenticator.GlobalTxRx = (TxRx_Params *)lib1x_init_txrx(
			&RTLAuthenticator,  oursvr_addr, svraddr, oursupp_addr, ourip,
			svrip, UDP_OURPORT, udp_svrport,
			auth->acctip, auth->udp_acctport,
#ifdef RTL_RADIUS_2SET
			svrip2, udp_svrport2,
			auth->acctip2, auth->udp_acctport2,
#endif
			dev_svr, dev_supp);

	lib1x_init_auth(&RTLAuthenticator);

	RTLAuthenticator.Dot1xKeyReplayCounter.field.HighPart = 0xfffffff0;
	RTLAuthenticator.Dot1xKeyReplayCounter.field.LowPart = 0;


#ifdef _RTL_WPA_UNIX
	lib1x_init_authRSNConfig(&RTLAuthenticator);
	lib1x_init_authGlobal(&RTLAuthenticator);
#endif

	RTLAuthenticator.MaxSupplicant = MAX_SUPPLICANT;

	if ((RTLAuthenticator.currentRole != role_Supplicant_adhoc) &&
					(RTLAuthenticator.currentRole != role_wds)) {

#if 0 //ndef START_AUTH_IN_LIB
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
		if(RTLAuthenticator.currentRole != role_eth)
#endif
		if(lib1x_init_fifo(&RTLAuthenticator, dev_supp)) {
			printf("auth-%s:create fifo error \n", dev_supp);
			return -1;
		}
#endif
		for(i = 0; i < MAX_SUPPLICANT; i++) {
// Allocate strcuture when inserting a supplicant dynamically to reduce pre-alloc memory size
#if 0			
			RTLAuthenticator.Supp[i] = (Dot1x_Supplicant * ) malloc ( sizeof (Dot1x_Supplicant) );
			RTLAuthenticator.Supp[i]->index = i;
			RTLAuthenticator.Supp[i]->isEnable = FALSE;
			RTLAuthenticator.Supp[i]->global = lib1x_init_authenticator( &RTLAuthenticator, RTLAuthenticator.GlobalTxRx );
			RTLAuthenticator.Supp[i]->global->index = i;
			RTLAuthenticator.Supp[i]->global->theAuthenticator->rinfo->global_identifier = &RTLAuthenticator.GlobalTxRx->GlobalRadId;
#endif		
			RTLAuthenticator.Supp[i] = NULL;
//---------------------------------------------- david+2006-02-06

		}
	}
	
#ifdef RTL_WPA_CLIENT
#if defined(CONFIG_RTL_802_1X_CLIENT_SUPPORT) 
	sprintf(xsup_conf, XSUP_CONF_FILE_NAME_FMT, theArgs[1]);
#endif
#endif

/*HS2 SUPPORT*/
#ifdef CONFIG_IEEE80211W
	lib1x_control_InitPMF(auth);
#endif
/*HS2 SUPPORT*/
#ifdef RTL_WPA_CLIENT
	if ( auth->currentRole !=  role_Authenticator
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
		||(RTLAuthenticator.currentRole != role_eth)
#endif
		){
		lib1x_init_supp(&RTLAuthenticator, &RTLClient);
	}
    // david ----------------------
	if ( (auth->currentRole == role_Supplicant_adhoc) || (auth->currentRole == role_wds)) {
        lib1x_control_STA_SetGTK(auth->client->global, auth->RSNVariable.PassPhraseKey, 0);
		if (auth->currentRole == role_Supplicant_adhoc) {
			lib1x_control_RSNIE(auth, DOT11_Ioctl_Set);
			lib1x_control_InitQueue(auth);
		}
	}
	
#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
				if((RTLAuthenticator.currentRole == role_eth)){
					
					lib1x_control_eth_register_pid(auth);
					
					signal(SIGIO, ProcEthSignalEvent);
#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
					if(RTLAuthenticator.currentRole == role_eth && (RTLAuthenticator.ethDot1xMode & ETH_DOT1X_CLIENT_MODE)){
						
						ethdot1x_client_mode_init(&RTLAuthenticator);
					}
				
#endif
				}
#endif
#ifdef CONFIG_RTL_802_1X_CLIENT_SUPPORT
	if(auth->currentRole ==  role_Supplicant_infra){
		// To parse wlan client mode related to 802.1x 
		// from /var/wpa-wlan0.conf to /var/1x/1x.conf
		// "/var/1x/1x_module.conf" for test only!
		if(prepareClientMode1xConf(&RTLAuthenticator, xsup_conf) == FAILED){
			AUTHDEBUG("prepare ClientMode1xConf fail!\n");//Added for test
		}
	}
#endif
    //----------------------------
#endif

    // david
    // kenny
	lib1x_init_authTimer( &RTLAuthenticator);

    //	printf("%s(%d): auth->currentRole(%d), RTLClient.global->AuthKeyMethod(%d)=============== \n",__FUNCTION__,__LINE__,
    //				auth->currentRole,RTLClient.global->AuthKeyMethod);//Added for test
    //	printf("%s(%d): auth->RSNVariable.Dot1xEnabled(%d), auth->RSNVariable.RSNEnabled(%d), auth->RSNVariable.MacAuthEnabled(%d)=============== \n",__FUNCTION__,__LINE__,
    //				auth->RSNVariable.Dot1xEnabled,auth->RSNVariable.RSNEnabled,auth->RSNVariable.MacAuthEnabled);//Added for test
    
	while(1)
	{
		//----if 0802
		if(auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.RSNEnabled || auth->RSNVariable.MacAuthEnabled)
		//----else
		//if(auth->RSNVariable.Dot1xEnabled || auth->RSNVariable.RSNEnabled)
		//----endif
		{
			// kenny
#ifdef START_AUTH_IN_LIB
			usleep(10000);
			if (pParam->terminate){
				pParam->terminate = 0;

				// free buffer
				for(i = 0; i < MAX_SUPPLICANT; i++) {
					free(RTLAuthenticator.Supp[i]);
					free(RTLAuthenticator.Supp[i]->global);
				}

				free(RTLClient.auth);
				free(RTLClient.global);
				free(RTLClient.supp_pae);
				return;
			}
#endif

#ifdef RTL_WPA_CLIENT

#ifdef CLIENT_TLS

			if(auth->currentRole == role_Supplicant_infra
			    &&( RTLClient.global->AuthKeyMethod == DOT11_AuthKeyType_RSN 			    
			    	|| RTLClient.global->AuthKeyMethod == DOT11_AuthKeyType_802_1X_SHA256)
			   )	
			{
				static int xsup_inited = 0;
				static int not_associated = 1;
				static int reset_xsup = 0;
				not_associated = lib1x_control_STA_QUERY_BSSID(RTLClient.global);

				if ( not_associated != 0) {

					if ((xsup_inited == 1) && (reset_xsup==0)) {
						eapol_cleanup(int_list);
						reset_xsup = 1;
					}

					continue;
				}


				if (xsup_inited == 1) {
					if (reset_xsup == 1) {
						eapol_init(int_list);
						reset_xsup = 0;
						lib1x_reset_supp(RTLClient.global);
					}
				}
				else
				{
					void global_deinit(int);
					static char *xsup_argv[]= { "xsuplicant", "-i", dev_supp, "-c", xsup_conf, "-d", "0" };	//Modified for test
					static const int xsup_argc = 7;

					struct sigaction  action;

					lib1x_reset_supp(RTLClient.global);
					lib1x_message(MESS_DBG_SUPP, "Wait for packet Timeout, Resent");
					lib1x_message(MESS_DBG_SUPP, "reset_xsup == %d, lib1x_control_STA_QUERY_BSSID(RTLClient.global) = %d\n", xsup_inited, not_associated);
					xsup_main(xsup_argc, xsup_argv);
					xsup_inited = 1;

					// When we quit, cleanup.
					action.sa_handler = (void (*)())global_deinit;
					action.sa_flags = 0;

					if (sigaction(SIGTERM,&action,0)==-1)
					{
						perror( "sigaction");
						printf("sigaction %d\n", __LINE__);
						return 1;
					}
					if (sigaction(SIGINT,&action,0)==-1)
					{
						perror( "sigaction");
						printf("sigaction %d\n", __LINE__);
						return 1;
					}
					if (sigaction(SIGQUIT,&action,0)==-1)
					{
						perror( "sigaction");
						printf("sigaction %d\n", __LINE__);
						return 1;
					}

					//signal(SIGTERM, global_deinit);
					//signal(SIGINT, global_deinit);
					//signal(SIGQUIT, global_deinit);
					//signal(SIGKILL, global_deinit);

					lib1x_message(MESS_DBG_SUPP, "xsup_inited == %d, lib1x_control_STA_QUERY_BSSID(RTLClient.global) = %d\n", xsup_inited, not_associated);
				}
			}
#endif /* CLIENT_TLS */



			if(auth->currentRole == role_Supplicant_infra)
				lib1x_do_supplicant(&RTLAuthenticator, RTLClient.global);

			else if ( (auth->currentRole == role_Supplicant_adhoc) ||
						(auth->currentRole == role_wds))
				break;
			#ifdef CONFIG_RTL_ETH_802DOT1X_SUPPORT
			else if( auth ->currentRole == role_eth && (auth ->ethDot1xMode & ETH_DOT1X_PROXY_MODE)){
				lib1x_do_authenticator( &RTLAuthenticator );
			}
			#endif
			#ifdef CONFIG_RTL_ETH_802DOT1X_CLIENT_MODE_SUPPORT
			else if(auth ->currentRole == role_eth && (auth ->ethDot1xMode & ETH_DOT1X_CLIENT_MODE)){
				sleep(2);
			}
			#endif
			else

#endif
            {
    			lib1x_do_authenticator( &RTLAuthenticator );
            }

            // david ---------
            // kenny
            /*
            			if (!(cnt++%10))
            				lib1x_timer_authenticator(SIGALRM);

            			usleep(10000);
                    */
            //----------------

		}
		else

			sleep(1000);

	}
    sleep(1);//for wds & adhoc role
	unlink(pid_name);

	return 0;


}


#ifdef START_AUTH_IN_LIB
#if 0
int main()
{
	auth_param_t param;
	param.encryption = 2; // 2:WPA, 4:WPA2 
	strcpy(param.psk, "1234567890");
	strcpy(param.ssid, "draytek-ap");
	param.role = 1; // 0:AP, 1:infra-client, 2:ad-hoc

	param.wpaCipher = 1; // 1:TKIP, 2:AES
	param.wpa2Cipher = 0; // 1:TKIP, 2:AES
	auth_main(&param);
}
#endif
#endif
