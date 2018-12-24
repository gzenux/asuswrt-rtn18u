#include <rc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void adjust_url_urlelist(void)
{
	char *nv, *nvp, *b, *chk, *chkp = NULL;
	char *url;
	char  replacebox[2048], rerule[256];
	int   cnt = 0;
	int   RESAVE = OFF;
	
	nv = nvp = strdup(nvram_safe_get("url_rulelist"));
	
	/* Change setting format 
	From:[<str1<str2<str3]
	To:  [<1>ALL>str1<1>ALL>str2<1>ALL>str3] 
	*/
	memset(replacebox, 0, sizeof(replacebox));
	while (nvp && (b = strsep(&nvp, "<")) != NULL) {
		chkp = chk = strdup(b);
		//dbg("[%s(%d)] %s\n", __FUNCTION__, __LINE__, chk);
		while( *chk != '\0') {
			if(*chk == '>') cnt++;
			chk++;
		}
		if (cnt != 2) {
			if (vstrsep(b, ">", &url) != 1) continue;
			if (*url) {
				memset(rerule, 0, sizeof(rerule));
				snprintf(rerule, sizeof(rerule), "<1>ALL>%s", url);
				//dbg("[%s(%d)] %s\n", __FUNCTION__, __LINE__, rerule);
				strcat(replacebox, rerule);
				RESAVE = ON;
			}
		}
		cnt = 0;
	}
	if (RESAVE) 
		nvram_set("url_rulelist", replacebox);
	if(nv) free(nv);
	if(chkp) free(chkp);
}

void adjust_ddns_config(void)
{
	char *server;

	server = nvram_safe_get("ddns_server_x");
	if(!strcmp(server, "WWW.GOOGLE-DDNS.COM") || 
	   !strcmp(server, "WWW.GOOGLE-DOMAINS.COM")) {
		nvram_set("ddns_server_x", "DOMAINS.GOOGLE.COM");
	}
	
}

void adjust_access_restrict_config(void)
{
	char *nv, *nvp, *b, *chk, *chkp = NULL;
	char *ipAddr;
	char *http_list;
	char *restrict_list;
	char  replacebox[2048], rerule[256];
	int   cnt = 0;
	int   RESAVE = OFF;
	int   nCount = 0;
	
	http_list = nvram_safe_get("http_clientlist");
	restrict_list = nvram_safe_get("restrict_rulelist");
	
	if ( (restrict_list[0] == '\0' && nvram_get_int("enable_acc_restriction") == 0) && 
	     (http_list[0] != '\0') ) {
		
		nvram_set_int("enable_acc_restriction", nvram_get_int("http_client"));
		
		nv = nvp = strdup(nvram_safe_get("http_clientlist"));
		
		/* Change setting format 
		From:[<ipAddr1<ipAddr2<ipAddr3]
		To:  [<1>ipAddr1>7<1>ipAddr2>7<1>ipAddr3>7]
		*/
		memset(replacebox, 0, sizeof(replacebox));
		while (nvp && (b = strsep(&nvp, "<")) != NULL) {
			chkp = chk = strdup(b);
			//dbg("[%s(%d)] %s\n", __FUNCTION__, __LINE__, chk);
			while( *chk != '\0') {
				if(*chk == '>') cnt++;
				chk++;
			}
			if (cnt != 2) {
				if (vstrsep(b, ">", &ipAddr) != 1) continue;
				if (*ipAddr) {
					memset(rerule, 0, sizeof(rerule));
					snprintf(rerule, sizeof(rerule), "<1>%s>7", ipAddr);
					//dbg("[%s(%d)] %s\n", __FUNCTION__, __LINE__, rerule);
					nCount = sizeof(replacebox) - strlen(replacebox);
					strncat(replacebox, rerule, nCount-1);
					RESAVE = ON;
				}
			}
			cnt = 0;
		}
		if (RESAVE) 
			nvram_set("restrict_rulelist", replacebox);
		if(nv) free(nv);
		if(chkp) free(chkp);
	}
}

