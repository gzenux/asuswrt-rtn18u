#include "media.h"

#define TYPE_AUDIO	0x01
#define TYPE_VIDEO	0x02
#define TYPE_IMAGES	0x04
#define ALL_MEDIA	0x07

int decode_url(char *url)
{

    //printf("start decode url \n");

    int len ;
    int i,k;
    char temp_url[512];

    memset( temp_url,0,sizeof(temp_url) );

    len = strlen(url);

    for( i = 0 , k= 0 ; i < len ; i++ ,k++)
    {
        if( url[i] == '/')
        {
            temp_url[k] = '\\';
            temp_url[k+1] = '/';
            k++;
        }
        if( url[i] == ' ')
        {
            temp_url[k] = '\\';
            temp_url[k+1] = ' ';
            k++;
        }
        temp_url[k] = url[i];
    }

    //int size = strlen(temp_url);
    temp_url[k+1] = '\0';

    //fprintf(stderr,"temp url is %s \n",temp_url);


    strcpy(url,temp_url);

}
void replace(char *input,char *oldwd, const char *newwd)
{
        //fprintf(stderr,"input=%s\n",input);
        //fprintf(stderr,"psrc=%s\n",oldwd);
        //fprintf(stderr,"pdst=%s\n",newwd);

        char *ptr;
        while(ptr = strstr(input,oldwd))
        {
                memmove(ptr+strlen(newwd),ptr+strlen(oldwd),strlen(ptr)-strlen(oldwd)+1);
                memcpy(ptr,&newwd[0],strlen(newwd));
        }
}


int main(void){
    printf("ContentType:text/html\r\n");
    printf("Cache-Control:private,max-age=0;\r\n");
    printf("\r\n");

    char *data;

    data = getenv("QUERY_STRING");
    init_cgi(data);	// there wasn't '?' in the head.
    char *value;
    char *url;
    char *type;
    char *current_url;
    char *next_url;
    char *next_host;
    char *script;
    char *dms_enable;
    char *daapd_enable;
    char *mediasever_path;
    char *friendly_name;
    char *itunes_name;
    char *path_type;
    char *dms_dir_manual;
    char diskname_tmp[50];
    FILE *fp;
    memset(diskname_tmp,'\0',strlen(diskname_tmp));
    char diskname[50];
    memset(diskname,'\0',strlen(diskname));

    value = websGetVar(wp, "action_mode", "");
    dms_enable = websGetVar(wp, "dms_enable", "");
    daapd_enable = websGetVar(wp, "daapd_enable", "");
    mediasever_path = websGetVar(wp, "mediasever_path", "");
    friendly_name = websGetVar(wp, "friendly_name", "");
    path_type = websGetVar(wp, "path_type", "");
    itunes_name = websGetVar(wp, "itunes_name", "");
    dms_dir_manual = websGetVar(wp, "dms_dir_manual", "");

    replace(mediasever_path, "&nbsp;", " ");
    replace(mediasever_path, "&amp;", "&");

    int mipsb_type;
    char command[128];
    if(!strcmp(value, "DLNA_SETTING")){
	if(access("/userfs/bin/tcapi",0) == 0){
		mipsb_type=1;
	}
	else
	{
		mipsb_type=0;
	}
	if(mipsb_type == 0){//nvram
		if(!strncmp(daapd_enable,"1",1))
		{
		    //nvram recover eric added 2012.12.31
		    //fprintf(stderr,"\ndaapd_enable==1\n");
		   
		    memset(command,0,sizeof(command));
		    sprintf(command,"nvram set ms_daapd=1");
		    system(command);
		    memset(command,0,sizeof(command));
		    sprintf(command,"nvram set ms_itunes=\"%s\"",itunes_name);
		    system(command);
		    system("nvram commit");

		    fp=popen("/opt/etc/init.d/S50mediaserver daapd-restart","r");
		    if(NULL == fp)
		    {
		        printf("MS_APPLY_FAIL");
		        fflush(stdout);
		        return 0;
		    }
		    int ms_rc = pclose(fp);
		    if(-1 == ms_rc)
		    {
		        printf("MS_APPLY_FAIL");
		        fflush(stdout);
		        exit(1);
		    }
		}
		else
		{
		    //nvram recover eric added 2012.12.31
		    //fprintf(stderr,"\ndaapd_enable==0\n");
		    memset(command,0,sizeof(command));
		    sprintf(command,"nvram set ms_daapd=0");
		    system(command);
		    /*memset(command,0,sizeof(command));
		    sprintf(command,"nvram set ms_itunes=\"%s\"",itunes_name);
		    system(command);*/
		    system("nvram commit");
		    system("/opt/etc/init.d/S50mediaserver daapd-stop");
		}
		//fprintf(stderr,"dlna_enable=%s daapd_enable=%s path=%s friendly_name=%s path_type=%s\n",dms_enable, daapd_enable, mediasever_path, friendly_name, path_type);


		if(!strncmp(dms_enable,"0",1))
		{
		    //nvram recover eric added 2012.12.31
		    //fprintf(stderr,"\ndms_enable==0\n");
		    memset(command,0,sizeof(command));
		    sprintf(command,"sed -i \"1s/^.*$/dms_enable=0/\" /opt/etc/Mediaserver.conf");
		    system(command);
		    memset(command,0,sizeof(command));
		    sprintf(command,"nvram set ms_dlna=0");
		    system(command);
		    /*memset(command,0,sizeof(command));
		    sprintf(command,"nvram set ms_path_type=\"%s\"",path_type);
		    system(command);
		    memset(command,0,sizeof(command));
		    sprintf(command,"nvram set ms_name=\"%s\"",friendly_name);
		    system(command);

		    char command1[strlen(mediasever_path)+20];
		    memset(command1,0,sizeof(command1));
		    sprintf(command1,"nvram set ms_path=\"%s\"",mediasever_path);
		    //fprintf(stderr,"\ncommand1=%s\n",command1);
		    system(command1);*/
		    system("nvram commit");
		    system("/opt/etc/init.d/S50mediaserver dlna-stop");
		}
		else
		{
		    fp = fopen("/opt/etc/Mediaserver.conf","w");
		    if(fp) {
		        fprintf(fp,"dms_enable=%s\ndaapd_enable=%s\nmediasever_path=%s"
		                "\nms_type=%s\nfriendly_name=%s\nitunes_name=%s\ndms_dir_manual=%s",
		                dms_enable,daapd_enable,mediasever_path,
		                path_type,friendly_name,itunes_name,dms_dir_manual);
		        fclose(fp);
		    }
		    //fprintf(stderr,"\ndms_enable==1\n");
		    memset(command,0,sizeof(command));
		    sprintf(command,"nvram set ms_dlna=1");
		    system(command);

		    memset(command,0,sizeof(command));
		    sprintf(command,"nvram set ms_dir_manual=%s",dms_dir_manual);
		    system(command);

		    /*if(strncmp(dms_dir_manual,"1",1))
		    {
		        memset(command,0,sizeof(command));
		        sprintf(command,"nvram set ms_path_type=\"<APV\"");
		        system(command);

		        char command1[strlen(mediasever_path)+50];
		        memset(command1,0,sizeof(command1));
		        sprintf(command1,"nvram set ms_path=\"</tmp/mnt\"");
		        replace(command1, "spechar3spechar", "\\`");
		        system(command1);
		    }
		    else
		    {*/
		        memset(command,0,sizeof(command));
		        sprintf(command,"nvram set ms_path_type=\"%s\"",path_type);
		        system(command);

		        char command1[strlen(mediasever_path)+50];
		        memset(command1,0,sizeof(command1));
		        sprintf(command1,"nvram set ms_path=\"%s\"",mediasever_path);
		        replace(command1, "spechar3spechar", "\\`");
		        system(command1);
		    //}



		    memset(command,0,sizeof(command));
		    sprintf(command,"nvram set ms_name=\"%s\"",friendly_name);
		    system(command);

		    system("nvram commit");

		    replace(mediasever_path, "spechar3spechar", "`");

		    int dircount = 0;
		    fp = fopen("/opt/etc/minidlna.conf","w");
		    if(fp) {
		    #ifndef MS_I686 
		        fprintf(fp,"port=8200\nfriendly_name=%s\ndb_dir=/opt/var/minidlna\nalbum_art_names=Cover.jpg/cover.jpg/Thumb.jpg/thumb.jpg\n"
		                "network_interface=br0\nenable_tivo=no\nstrict_dlna=no\ninotify=yes\npresentation_url=http://192.168.1.1:8200\n"
		                "notify_interval=600\nserial=12345678\n",friendly_name);
			#else
				fprintf(fp,"port=8200\nfriendly_name=%s\ndb_dir=/opt/var/minidlna\nalbum_art_names=Cover.jpg/cover.jpg/Thumb.jpg/thumb.jpg\n"
		                "network_interface=br2\nenable_tivo=no\nstrict_dlna=no\ninotify=yes\npresentation_url=http://192.168.1.1:8200\n"
		                "notify_interval=600\nserial=12345678\n",friendly_name);
			#endif

		        if(strncmp(dms_dir_manual,"1",1))
		        {
		            fprintf(fp,"media_dir=/tmp/mnt\n");
		        }
		        else
		        {
		            char dirlist[32][1024];
		            char typelist[32];
		            int type;
		            char *nv, *nvp, *b, *c;
		            char *nv2, *nvp2;
		            char types[5];
		            int i, j;

		            nv = nvp = strdup(mediasever_path);
		            nv2 = nvp2 = strdup(path_type);
		            if(nv) {
		                while((b = strsep(&nvp, "<")) != NULL) {
		                    if(!strlen(b)) continue;
		                    if(access(b,F_OK)==0)
		                        strncpy(dirlist[dircount++], b, 1024);
		                }
		            }
		            dircount = 0;
		            if(nv2) {
		                while((c = strsep(&nvp2, "<")) != NULL) {
		                    if(!strlen(c))  continue;

		                    type = 0;
		                    while(*c)
		                    {
		                        if(*c == ',')
		                            break;

		                        if(*c == 'A' || *c == 'a')
		                            type |= TYPE_AUDIO;
		                        else if(*c == 'V' || *c == 'v')
		                            type |= TYPE_VIDEO;
		                        else if(*c == 'P' || *c == 'p')
		                            type |= TYPE_IMAGES;
		                        else
		                            type = ALL_MEDIA;

		                        c++;
		                    }
		                    typelist[dircount++] = type;
		                }
		            }
		            if(nv) free(nv);
		            if(nv2) free(nv2);
		            for(i=0;i<dircount;i++)
		            {
		                type = typelist[i];

		                if(type == ALL_MEDIA)
		                    types[0] = 0;
		                else
		                {
		                    j = 0;
		                    if(type & TYPE_AUDIO)
		                        types[j++] = 'A';
		                    if(type & TYPE_VIDEO)
		                        types[j++] = 'V';
		                    if(type & TYPE_IMAGES)
		                        types[j++] = 'P';

		                    types[j++] = ',';
		                    types[j] = 0;
		                }
		                fprintf(fp,"media_dir=%s%s\n",types,dirlist[i]);
		            }
		        }
		        fclose(fp);
		    }
		    if(dircount || strncmp(dms_dir_manual,"1",1))
		        system("/opt/etc/init.d/S50mediaserver dlna-restart");
		    else
		        system("/opt/etc/init.d/S50mediaserver dlna-stop");
		}
	}
	else{//tcapi
		
		if(!strncmp(daapd_enable,"1",1))
		{
		    //nvram recover eric added 2012.12.31
		    //fprintf(stderr,"\ndaapd_enable==1\n");
		    memset(command,0,sizeof(command));
		    sprintf(command,"/userfs/bin/tcapi set Apps_Entry ms_daapd 1");
		    system(command);
		    memset(command,0,sizeof(command));
		    sprintf(command,"/userfs/bin/tcapi set Apps_Entry ms_itunes \"%s\"",itunes_name);
		    system(command);
		    system("/userfs/bin/tcapi commit Apps");
		    system("/userfs/bin/tcapi save");
		    fp=popen("/opt/etc/init.d/S50mediaserver daapd-restart","r");
		    if(NULL == fp)
		    {
		        printf("MS_APPLY_FAIL");
		        fflush(stdout);
		        return 0;
		    }
		    int ms_rc = pclose(fp);
		    if(-1 == ms_rc)
		    {
		        printf("MS_APPLY_FAIL");
		        fflush(stdout);
		        exit(1);
		    }
		}
		else
		{
		    //nvram recover eric added 2012.12.31
		    //fprintf(stderr,"\ndaapd_enable==0\n");
		    memset(command,0,sizeof(command));
		    sprintf(command,"/userfs/bin/tcapi set Apps_Entry ms_daapd 0");
		    system(command);
		    /*memset(command,0,sizeof(command));
		    sprintf(command,"nvram set ms_itunes=\"%s\"",itunes_name);
		    system(command);*/
		    system("/userfs/bin/tcapi commit Apps");
		    system("/userfs/bin/tcapi save");
		    system("/opt/etc/init.d/S50mediaserver daapd-stop");
		}
		//fprintf(stderr,"dlna_enable=%s daapd_enable=%s path=%s friendly_name=%s path_type=%s\n",dms_enable, daapd_enable, mediasever_path, friendly_name, path_type);

		if(!strncmp(dms_enable,"0",1))
		{
		    //nvram recover eric added 2012.12.31
		    //fprintf(stderr,"\ndms_enable==0\n");
		    memset(command,0,sizeof(command));
		    sprintf(command,"sed -i \"1s/^.*$/dms_enable=0/\" /opt/etc/Mediaserver.conf");
		    system(command);
		    memset(command,0,sizeof(command));
		    sprintf(command,"/userfs/bin/tcapi set Apps_Entry ms_dlna 0");
		    system(command);
		    /*memset(command,0,sizeof(command));
		    sprintf(command,"nvram set ms_path_type=\"%s\"",path_type);
		    system(command);
		    memset(command,0,sizeof(command));
		    sprintf(command,"nvram set ms_name=\"%s\"",friendly_name);
		    system(command);

		    char command1[strlen(mediasever_path)+20];
		    memset(command1,0,sizeof(command1));
		    sprintf(command1,"nvram set ms_path=\"%s\"",mediasever_path);
		    //fprintf(stderr,"\ncommand1=%s\n",command1);
		    system(command1);*/
		    system("/userfs/bin/tcapi commit Apps");
		    system("/userfs/bin/tcapi save");
		    system("/opt/etc/init.d/S50mediaserver dlna-stop");
		}
		else
		{
		    fp = fopen("/opt/etc/Mediaserver.conf","w");
		    if(fp) {
		        fprintf(fp,"dms_enable=%s\ndaapd_enable=%s\nmediasever_path=%s"
		                "\nms_type=%s\nfriendly_name=%s\nitunes_name=%s\ndms_dir_manual=%s",
		                dms_enable,daapd_enable,mediasever_path,
		                path_type,friendly_name,itunes_name,dms_dir_manual);
		        fclose(fp);
		    }
		    //fprintf(stderr,"\ndms_enable==1\n");
		    memset(command,0,sizeof(command));
		    sprintf(command,"/userfs/bin/tcapi set Apps_Entry ms_dlna 1");
		    system(command);

		    memset(command,0,sizeof(command));
		    sprintf(command,"/userfs/bin/tcapi set Apps_Entry ms_dir_manual \"%s\"",dms_dir_manual);
		    system(command);

		    /*if(strncmp(dms_dir_manual,"1",1))
		    {
		        memset(command,0,sizeof(command));
		        sprintf(command,"nvram set ms_path_type=\"<APV\"");
		        system(command);

		        char command1[strlen(mediasever_path)+50];
		        memset(command1,0,sizeof(command1));
		        sprintf(command1,"nvram set ms_path=\"</tmp/mnt\"");
		        replace(command1, "spechar3spechar", "\\`");
		        system(command1);
		    }
		    else
		    {*/
		        memset(command,0,sizeof(command));
		        sprintf(command,"/userfs/bin/tcapi set Apps_Entry ms_path_type \"%s\"",path_type);
		        system(command);

		        char command1[strlen(mediasever_path)+50];
		        memset(command1,0,sizeof(command1));
		        sprintf(command1,"/userfs/bin/tcapi set Apps_Entry ms_path \"%s\"",mediasever_path);
		        replace(command1, "spechar3spechar", "\\`");
		        system(command1);
		    //}



		    memset(command,0,sizeof(command));
		    sprintf(command,"/userfs/bin/tcapi set Apps_Entry ms_name \"%s\"",friendly_name);
		    system(command);

		    system("/userfs/bin/tcapi commit Apps");
		    system("/userfs/bin/tcapi save");

		    replace(mediasever_path, "spechar3spechar", "`");

		    int dircount = 0;
		    fp = fopen("/opt/etc/minidlna.conf","w");
		    if(fp) {
		    #ifndef MS_I686
		        fprintf(fp,"port=8200\nfriendly_name=%s\ndb_dir=/opt/var/minidlna\nalbum_art_names=Cover.jpg/cover.jpg/Thumb.jpg/thumb.jpg\n"
		                "network_interface=br0\nenable_tivo=no\nstrict_dlna=no\ninotify=yes\npresentation_url=http://192.168.1.1:8200\n"
		                "notify_interval=600\nserial=12345678\n",friendly_name);
			#else
				fprintf(fp,"port=8200\nfriendly_name=%s\ndb_dir=/opt/var/minidlna\nalbum_art_names=Cover.jpg/cover.jpg/Thumb.jpg/thumb.jpg\n"
		                "network_interface=br2\nenable_tivo=no\nstrict_dlna=no\ninotify=yes\npresentation_url=http://192.168.1.1:8200\n"
		                "notify_interval=600\nserial=12345678\n",friendly_name);
			#endif

		        if(strncmp(dms_dir_manual,"1",1))
		        {
		            fprintf(fp,"media_dir=/tmp/mnt\n");
		        }
		        else
		        {
		            char dirlist[32][1024];
		            char typelist[32];
		            int type;
		            char *nv, *nvp, *b, *c;
		            char *nv2, *nvp2;
		            char types[5];
		            int i, j;

		            nv = nvp = strdup(mediasever_path);
		            nv2 = nvp2 = strdup(path_type);
		            if(nv) {
		                while((b = strsep(&nvp, "<")) != NULL) {
		                    if(!strlen(b)) continue;
		                    if(access(b,F_OK)==0)
		                        strncpy(dirlist[dircount++], b, 1024);
		                }
		            }
		            dircount = 0;
		            if(nv2) {
		                while((c = strsep(&nvp2, "<")) != NULL) {
		                    if(!strlen(c))  continue;

		                    type = 0;
		                    while(*c)
		                    {
		                        if(*c == ',')
		                            break;

		                        if(*c == 'A' || *c == 'a')
		                            type |= TYPE_AUDIO;
		                        else if(*c == 'V' || *c == 'v')
		                            type |= TYPE_VIDEO;
		                        else if(*c == 'P' || *c == 'p')
		                            type |= TYPE_IMAGES;
		                        else
		                            type = ALL_MEDIA;

		                        c++;
		                    }
		                    typelist[dircount++] = type;
		                }
		            }
		            if(nv) free(nv);
		            if(nv2) free(nv2);
		            for(i=0;i<dircount;i++)
		            {
		                type = typelist[i];

		                if(type == ALL_MEDIA)
		                    types[0] = 0;
		                else
		                {
		                    j = 0;
		                    if(type & TYPE_AUDIO)
		                        types[j++] = 'A';
		                    if(type & TYPE_VIDEO)
		                        types[j++] = 'V';
		                    if(type & TYPE_IMAGES)
		                        types[j++] = 'P';

		                    types[j++] = ',';
		                    types[j] = 0;
		                }
		                fprintf(fp,"media_dir=%s%s\n",types,dirlist[i]);
		            }
		        }
		        fclose(fp);
		    }
		   if(dircount || strncmp(dms_dir_manual,"1",1))
		        fp=popen("/opt/etc/init.d/S50mediaserver dlna-restart","r");
		    else
		        fp=popen("/opt/etc/init.d/S50mediaserver dlna-stop","r");
		    if(NULL == fp)
		    {
		        printf("MS_APPLY_FAIL");
		        fflush(stdout);
		        return 0;
		    }
		    int ms_rc = pclose(fp);
		    if(-1 == ms_rc)
		    {
		        printf("MS_APPLY_FAIL");
		        fflush(stdout);
		        exit(1);
		    }
		}
	}
    }
    printf("ACK_SUCESS");
    fflush(stdout);
    return 0;
}

