#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <syslog.h>
#include "common.h"
#include "defs.h"
#include "wps_parser.h"
#include "wsplcd.h"
#include "wps_config.h"
#include <shared.h>
int qca_role;
int qca_cfg_changed;
int get_2g=0;
int get_5g=0;

struct wl_translate_option{
    char *wsplcd;
    char *nvram;
    int (*translate_val)(char *val);   
};


int translate_authmode(char *val)
{
	if(!strcmp(val,"None"))
		strcpy(val,"open");
	else if(!strcmp(val,"Basic"))
		strcpy(val,"shared");
	else if(!strcmp(val,"WPA"))
		strcpy(val,"psk");
	else if(!strcmp(val,"11i"))
 		strcpy(val,"psk2");
	else if(!strcmp(val,"WPAand11i"))
		strcpy(val,"pskpsk2");
	else
		strcpy(val,"");

	dprintf(MSG_DEBUG, "=translate auth %s=\n",val);
	return 1;
}


int translate_crypto(char *val)
{
	if(!strcmp(val,"AESEncryption"))
		strcpy(val,"aes");
	else if(!strcmp(val,"TKIPandAESEncryption"))
		strcpy(val,"aes+tkip");
	else if(!strcmp(val,"TKIPEncryption"))
		strcpy(val,"tkip");
	dprintf(MSG_DEBUG, "=translate crypto %s=\n",val);

	return 1;
}

struct wl_translate_option wsp_info[] =
{
	{".ClonedChannel",		"channel",      NULL},  //only for wifiX
	{".Channel",	     		"channel",     	NULL},  //only for athX
	{".PeerBSSID",       		"sta_bssid",    NULL},	//only for staX
	{".SSID",   	     		"ssid",     	NULL},
	{".BeaconType",      		"auth_mode_x",  translate_authmode},
	{".IEEE11iAuthenticationMode",  NULL,  		NULL},
	{".IEEE11iEncryptionModes",	NULL,     	NULL},
	{".BasicAuthenticationMode",    NULL, 		NULL},
	{".BasicEncryptionModes",	NULL,     	NULL},
	{".KeyPassphrase",		"wpa_psk",     	NULL},
	{".AuthenticationServiceMode",  NULL,     	NULL},
	{".X_ATH-COM_HT40Coexist",   	NULL,     	NULL},
	{".Standard",   		NULL,     	NULL},
	{".GROUPKEY",   		"groupkey",     NULL},
	{".ASUSCMD",   			"dummy",     	NULL},
	{".SECURITY_TYPE",   		"dummy2",       NULL},
	{".SECURITY_EXT",   		"dummy3",       NULL},
	{".CH5G2",   			"channel_5g2",   NULL},
#ifndef RTCONFIG_DUAL_BACKHAUL
	{".CH2G",   			"channel_2g",   NULL},
#endif
	{".INFORE",   			"re_syncing",   NULL},
	{NULL}
};

void uci2nvram(char* nvram, char* val)
{
	char tmp[100];
	memset(tmp,0,sizeof(tmp));
	nvram_set(nvram,val);
}


//keep 200 parameters
#define num 200
char sname[num][150];
char sval[num][150];

void *storage_getHandle()
{
        return (void *)sname;
}


int storage_setParam(void *handle, const char *name, const char *value)
{
        int i;
        //dprintf(MSG_DEBUG,"%s\n", __func__);
        if(!strlen(name) || ! strlen(value))
		return -1;
	
        for(i=0;i<num;i++)
        {
		if(strlen(sname[i]))
		{
	                if(!strcmp(sname[i],name))
				strcpy(sval[i],value);
		}
		else
		{
			strcpy(sname[i],name);
			strcpy(sval[i],value);
			goto fin;
		}

        }
fin:
	dprintf(MSG_DEBUG,"==> storage_setParam set %s = %s\n",name,value);
	return 1;
}

int  storage_apply(void *handle)
{
   	int o;
	FILE *fp;
	dprintf(MSG_DEBUG,"==> storage apply, save the config!!!\n");
    	if (!(fp = fopen("/tmp/wsplcd.apply", "w+")))
       	         return 0;
    	for(o=0;o<num;o++)
		if(strlen(sname[o]))
			 fprintf(fp, "%s=%s\n",sname[o],sval[o]);

	fclose(fp);
	transfer_to_nvram();
    	return 0; 
}

int  storage_addVAP()    
{
	return 0;
}

int  storage_delVAP(int index)   
{
	return 0;
}



void transfer_to_nvram(void)
{
	FILE *fp;
	char buf[1024];
	char cmp[50],temp[40]="wlxxxxxxxx";	
	char *pt1;
	char data[64];
	struct wl_translate_option *iopt;
	int old_sync,old_ch5g2;
	char *now_scy,*scy_ext;
#ifndef RTCONFIG_DUAL_BACKHAUL
	int old_ch2g;
#endif
	char *old_group;
        memset(buf, 0, sizeof(buf));
	
	dprintf(MSG_DEBUG,"translate nvram ....\n");
        if ((fp = fopen("/tmp/wsplcd.apply", "r")) == NULL)
                return;

        while(fgets(buf,1024,fp)!=NULL)
        {
		dprintf(MSG_DEBUG,"===> get data is %s\n",buf);		
		memset(data,0,sizeof(data));
		memset(cmp,0,sizeof(cmp));

		if(strstr(buf,".1") || strstr(buf,".3")) //2G
			sprintf(temp,"wl%d",0);
		else //5G
			sprintf(temp,"wl%d",1);
		
		iopt=wsp_info;
		while(iopt->wsplcd != NULL)
    		{
                	sprintf(cmp,"%s=",iopt->wsplcd);
			dprintf(MSG_DEBUG,"cmp=%s\n",cmp);
			if((pt1=strstr(buf,cmp)))
			{
                               	strcpy(data,pt1+strlen(cmp));
                                data[strlen(data)-1] = '\0';
				dprintf(MSG_DEBUG,"data=%s\n",data);
				if(iopt->nvram != NULL)
				{
						sprintf(temp,"%s_%s",temp,iopt->nvram);
						if(iopt->translate_val)
							iopt->translate_val(data);
						if(strstr(buf,".GROUPKEY"))
						{
							dprintf(MSG_DEBUG,"===> v1.0 set group key as %s\n",data);		
							old_group=nvram_get("cfg_group");
							uci2nvram("cfg_group",data);
							if(strcmp(old_group,data)!=0)
							{
								dprintf(MSG_DEBUG,"===> cfg_group=%s, %s.notify cfg_sync!!\n",old_group,data);
								notify_rc("restart_cfgsync");			
							}	
						}
						else if(strstr(buf,".INFORE"))
						{
							dprintf(MSG_DEBUG,"===> v1.0 set re_syncing as %s\n",data);		
							old_sync=nvram_get_int("re_syncing");
							uci2nvram("re_syncing",data);
							if(!old_sync && nvram_get_int("re_syncing"))
							{
                        					dprintf(MSG_DEBUG,"!!!!!!!!!RE: config change start!!!!!!!!\n");
                        					lp55xx_leds_proc(LP55XX_GREENERY_LEDS, LP55XX_WIFI_PARAM_SYNC);
							}

							if(nvram_get_int("re_syncing"))
							{
								if(strstr(temp,"wl0"))
									get_2g=1;
								if(strstr(temp,"wl1"))
									get_5g=1;
								if(get_2g && get_5g)
								{
									if(nvram_get_int("re_syncing")==2)
									{
										if(!strcmp(nvram_get("re_asuscmd"),"0"))
                        								dprintf(MSG_DEBUG,"RE: wait asus command\n");
										else
											system("hive_re waitimeout");
									}
									else
										system("hive_re waitimeout");
								}
							}
							
							

						}
#if defined(MAPAC2200)
						else if(strstr(buf,".CH5G2"))
						{
							dprintf(MSG_DEBUG,"===> v1.0 set wl2_channel as %s\n",data);		
							old_ch5g2=nvram_get_int("wl2_channel");
							uci2nvram("wl2_channel",data);
							if(old_ch5g2!=nvram_get_int("wl2_channel"))
							{
                        					  dprintf(MSG_DEBUG,"!!!!!!!!!RE: 5G-2 %s change channel to %d!!!!!!!!\n",nvram_get("wl2_ifname"),nvram_get_int("wl2_channel"));
								 if(nvram_get_int("wl2_channel")>=36)
								  	doSystem("iwconfig %s channel %d",nvram_get("wl2_ifname"),nvram_get_int("wl2_channel"));
								 else
								  	doSystem("iwconfig %s channel auto",nvram_get("wl2_ifname"));
							}

						}
#endif

#ifndef RTCONFIG_DUAL_BACKHAUL
						else if(strstr(buf,".CH2G"))
						{
							dprintf(MSG_DEBUG,"===> v1.0 set wl0_channel as %s\n",data);		
							old_ch2g=nvram_get_int("wl0_channel");
							uci2nvram("wl0_channel",data);
							if(old_ch2g!=nvram_get_int("wl0_channel"))
							{
                        					  dprintf(MSG_DEBUG,"!!!!!!!!!RE: 2G %s change channel to %d!!!!!!!!\n",nvram_get("wl0_ifname"),nvram_get_int("wl0_channel"));
								 if(nvram_get_int("wl0_channel")<=14)
								  	doSystem("iwconfig %s channel %d",nvram_get("wl0_ifname"),nvram_get_int("wl0_channel"));
								 else
								  	doSystem("iwconfig %s channel auto",nvram_get("wl0_ifname"));
							}

						}
#endif
						else if(strstr(buf,".ASUSCMD"))
						{
							dprintf(MSG_DEBUG,"===> v1.0 set asus command as %s\n",data);		
							uci2nvram("re_asuscmd",data);
							if(nvram_get_int("re_syncing")==2)
								system("hive_re waitimeout");
						}
						else if(strstr(buf,".SECURITY_TYPE"))
						{
							dprintf(MSG_DEBUG,"===> v1.0 set re_security as %s\n",data);	
							now_scy=nvram_get("now_security");
							if(strcmp(now_scy, data)) //different
								uci2nvram("re_security_new",data);
						}
						else if(strstr(buf,".SECURITY_EXT"))
						{
							dprintf(MSG_DEBUG,"===> v1.0 set re_security_ext as %s\n",data);	
							scy_ext=nvram_get("re_security_ext");
							if(strcmp(scy_ext, data)) //different
								uci2nvram("re_security_ext",data);
						}
						else
						{
				 			uci2nvram(temp,data);
							dprintf(MSG_DEBUG,"===> v1.0 transfer nvram set %s=%s\n",temp,data);		
						}
				}
				break;
			}
        		iopt ++;
    		}

        	memset(buf, 0, sizeof(buf));
        }
	nvram_commit();
        fclose(fp);

}


void storage_restartWireless(void)   
{

	dprintf(MSG_DEBUG,"====>role:%s ,restart wireless\n",qca_role?"ENROLLEE":"REGISTER");
	if(qca_role)
	{
		dprintf(MSG_DEBUG,"wsplcd: restart RE!\n");
		transfer_to_nvram();
		//system("nvram unset hive_re_autocnf");
		system("hive_re restart");
	}
	else //REGISTER
	{
		dprintf(MSG_DEBUG,"wsplcd: restart CAP!\n");
		dprintf(MSG_DEBUG,"qca_cfg_changed=%d\n",qca_cfg_changed);
		system("hive_cap restart");
	}
}

#if 0
void main(void)
{
	int k;
	void *newHandle = NULL;
	newHandle = storage_getHandle();
	storage_setParam(newHandle,"SSID", "WIFI-SON");

	storage_setParam(newHandle,"ENABLE.2", "1");
	storage_setParam(newHandle,"ENABLE", "1");
	storage_setParam(newHandle,"ENCRYPTION.2", "PSK");
	storage_setParam(newHandle,"KEY", "1234567890");
	storage_setParam(newHandle,"BSSID", "00:11:22:33:44:55");


	for(k=0;k<200;k++)
		printf("[k=%d, %s=%s]\n",k,sname[k],sval[k]);

}
#endif
