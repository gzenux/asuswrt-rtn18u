#include "ms_apply_cgi.h"
#include "ms_func.h"
#include "ms_hook.h"

void print_apply(char* d_type)
{
    char ch;
    int i = 0,j = 0;
    FILE *fp;

    if(!strcmp(d_type, "General"))
    {
        system("/opt/etc/apps_asus_script/mes_check_general router-general-renew&");
        sleep(1);
        //2016.8.17 tina modify{
        //getrouterconfig();
        char *routerconfig = getrouterconfig();
        if(routerconfig != NULL)
            free(routerconfig);
        //}end tina
        if (access("/opt/etc/mes_general.conf",0) == 0)
        {

            int fd, len, i=0;
            char ch, tmp[256], name[256], content[256];
            memset(tmp, 0, sizeof(tmp));
            memset(name, 0, sizeof(name));
            memset(content, 0, sizeof(content));

            if((fd = open("/opt/etc/mes_general.conf", O_RDONLY | O_NONBLOCK)) < 0)
            {
                //printf("\nread log error!\n");
            }
            else
            {
                while((len = read(fd, &ch, 1)) > 0)
                {
                    if(ch == '=')
                    {
                        strcpy(name, tmp);
                        //printf("name is %s\n",name);
                        memset(tmp, 0, sizeof(tmp));
                        i = 0;
                        continue;
                    }
                    else if(ch == '\n')
                    {
                        strcpy(content, tmp);
                        //printf("content is [%s] \n",content);
                        memset(tmp, 0, sizeof(tmp));
                        i = 0;

                        if(strcmp(name, "Enable_time") == 0)//0
                        {
                            printf("[\"%s\"",content);
                        }
                        else if(strcmp(name, "Start_hour") == 0)//1
                        {
                            printf(",\"%s\"",content);

                        }
                        else if(strcmp(name, "Start_minute") == 0)//2
                        {
                            printf(",\"%s\"",content);

                        }
                        else if(strcmp(name, "End_hour") == 0)//3
                        {
                            printf(",\"%s\"",content);

                        }
                        else if(strcmp(name, "End_minute") == 0)//4
                        {
                            printf(",\"%s\"",content);

                        }
                        else if(strcmp(name, "Day") == 0)//5
                        {
                            printf(",\"%s\"",content);

                        }
                        else if(strcmp(name, "Download_dir") == 0)//6
                        {
                            printf(",\"%s\"",content);

                        }
                        else if(strcmp(name, "Refresh_rate") == 0)//7
                        {
                            printf(",\"%s\"",content);

                        }
                        else if(strcmp(name, "BASE_PATH") == 0)//8
                        {
                            printf(",\"%s\"",Base_dir);

                        }
                        else if(strcmp(name, "MISC_HTTP_X") == 0)//9
                        {
                            printf(",\"%s\"",content);

                        }
                        else if(strcmp(name, "LAN_IP") == 0)//10
                        {
                            printf(",\"%s\"",lan_ip_addr);

                        }
                        else if(strcmp(name, "MISCR_HTTPPORT_X") == 0)//11
                        {

                            printf(",\"%s\"",miscr_httpport_x_check);

                        }
                        else if(strcmp(name, "MISCR_HTTP_X") == 0)//12
                        {
                            printf(",\"%s\"",miscr_http_x_check);

                        }
                        else if(strcmp(name, "DM_PORT") == 0)//13
                        {
                            printf(",\"%s\"",content);

                        }
                        else if(strcmp(name, "LANGUAGE") == 0)//14
                        {
                            printf(",\"%s\"",content);

                        }
                        else if(strcmp(name, "PRODUCTID") == 0)//15
                        {
                            printf(",\"%s\"",productid_check);

                        }
                        else if(strcmp(name, "APPS_DEV") == 0)//16
                        {
                            printf(",\"%s\"",apps_dev_path);

                        }
                        else if(strcmp(name, "WAN_IP") == 0)//17
                        {
                            printf(",\"%s\"",wan_ip_check);

                        }
                        else if(strcmp(name, "DDNS_ENABLE_X") == 0)//18
                        {
                            printf(",\"%s\"",ddns_enable_x_check);

                        }
                        else if(strcmp(name, "DDNS_HOSTNAME_X") == 0)//19
                        {
                            printf(",\"%s\"",ddns_hostname_x_check);

                        }
                        else if(strcmp(name, "MAX_ON_HEAVY") == 0)//20
                        {
                            printf(",\"%s\"",content);

                        }
                        else if(strcmp(name, "MAX_QUEUES") == 0)//21
                        {
                            printf(",\"%s\"",content);

                        }
                        else if(strcmp(name, "MAX_ON_ED2K") == 0)//22
                        {
                            printf(",\"%s\"",content);

                        }
                        else if(strcmp(name, "RFW_ENABLE_X") == 0)//23
                        {
                            printf(",\"%s\"",rfw_enable_x_check);

                        }
                        else if(strcmp(name, "DEVICE_TYPE") == 0)//24
                        {
                            printf(",\"%s\"",device_type_check);

                        }
                        else if(strcmp(name, "dm_radio_time_x") == 0)//25
                        {
                            printf(",\"%s\"",content);

                        }
                        else if(strcmp(name, "dm_radio_time2_x") == 0)//26
                        {
                            printf(",\"%s\"",content);

                        }

                        continue;
                    }


                    memcpy(tmp+i, &ch, 1);
                    i++;
                }
                printf(",\"%s\"",utility_ver_check);//27
                printf(",\"%s\"",local_domain_check);//28
                printf(",\"%s\"]",http_autologout_check);//29
                close(fd);
            }
        }

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
    //char *current_url;
    //char *next_url;
    //char *next_host;
    //char *script;
    //char *again; //yes or no;
    //char *fid;
    char *path;
    //char *new_floder_name;
    char *dm_lang;


    url = websGetVar(wp, "usb_dm_url", "");
    type = websGetVar(wp, "download_type", "");
    value = websGetVar(data,"action_mode", "");
    //next_host = websGetVar(wp, "next_host", "");
    //current_url = websGetVar(wp, "current_page", "");
    //next_url = websGetVar(wp, "next_page", "");
    //script = websGetVar(wp, "action_script","");
    //again = websGetVar(wp, "again","");
    //fid = websGetVar(wp, "fid","");

    path = websGetVar(wp, "path", "");
    //new_floder_name = websGetVar(wp, "new_floder_name", "");

    if(*(url+strlen(url)-1) == 10)
    {
        //fprintf(stderr, "test\n");
        *(url+strlen(url)-1) = '\0';
    }//2012.06.13 eric added for url content \0

    char chk_tmp[MAX_NAMELEN];
    memset(chk_tmp, 0x00, sizeof(chk_tmp));

    struct Lognote *p;
    head = (struct Lognote *)malloc(sizeof(struct Lognote));
    memset(head, 0, sizeof(struct Lognote));

    init_path();
    //2016.8.17 tina modify{
    //getdmconfig();
    char *dmconfig = getdmconfig();
    if(dmconfig != NULL)
        free(dmconfig);
    //}end tina
    check_alive();
    if(!strcmp(value,"initial"))
    {

        print_apply(type);
        return 0;
    }
    else if(!strcmp(value,"DM_LANG")){
        dm_lang = websGetVar(wp, "DM_language", "");
        char changlang[256];
        memset(changlang,'\0',sizeof(changlang));
        sprintf(changlang,"sed -i '19s/^.*$/LANGUAGE=%s/' /opt/etc/mes_general.conf",dm_lang);
        system(changlang);
        memset(changlang,'\0',sizeof(changlang));
        sprintf(changlang,"sed -i '19s/^.*$/LANGUAGE=%s/' /opt/etc/mes_general_bak.conf",dm_lang);
        system(changlang);
        printf("ACK_SUCESS");
        return 0;
    }

    else if(!strcmp(value,"Lang_Hdr"))
    {
        FILE *fp;
        fp = fopen("/www/Lang_Hdr","r");
        if(fp == NULL)
        {
            printf("LANG_EN,LANG_TW,LANG_CN,LANG_CZ,LANG_PL,LANG_RU,LANG_DE,LANG_FR,LANG_TR,LANG_TH,LANG_MS,LANG_NO,LANG_FI,LANG_DA,LANG_SV,LANG_BR,LANG_JP,LANG_ES,LANG_IT,LANG_UK,LANG_HU,LANG_RO");
        }
        else
        {
            char buf[64];
            char tmp[20];
            char bufLAN[512];
            char *p;
            memset(bufLAN,0,512);
            while (fgets(buf, sizeof(buf), fp)!= NULL)
            {
                if((p = strstr(buf, "LANG_")) != NULL)
                {
                    memset(tmp, 0, sizeof(tmp));
                    strncpy(tmp,p,7);
                    strcat(bufLAN, tmp);
                    strcat(bufLAN, ",");
                }
            }
            fclose(fp);
            bufLAN[strlen(bufLAN) - 1] = '\0';
            printf("%s",bufLAN);
        }
    }
    //printf("</BODY>\n");

    //printf("</HTML>\n");

    fflush(stdout);

    return 0;

}

