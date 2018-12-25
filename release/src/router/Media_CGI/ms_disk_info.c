#include <stdio.h>
#include <sys/statfs.h>
#include <dirent.h>
#include "ms_hook.h"
#include "ms_disk_info.h"

int main(void)
{

    printf("ContentType:text/html\r\n");
    printf("Cache-Control:private,max-age=0;\r\n");
    printf("\r\n");

    char *data;

    data = getenv("QUERY_STRING");
    init_cgi(data);	// there wasn't '?' in the head.

    char *path;
    char *url;
    char *type;
    char *current_url;
    char *next_url;
    char *next_host;
    char *script;

    url = websGetVar(wp, "usb_dm_url", "");
    type = websGetVar(wp, "download_type", "");
    path = websGetVar(data,"action_mode", "");
    next_host = websGetVar(wp, "next_host", "");
    current_url = websGetVar(wp, "current_page", "");
    next_url = websGetVar(wp, "next_page", "");
    script = websGetVar(wp, "action_script","");

    {
        char **folder_list = NULL;
        int i, folder_num, result;
        //fprintf(stderr,"path = %s\n",path);
        result = get_all_folder_in_mount_path(path, &folder_num, &folder_list);
        //result = get_all_folder_in_mount_path("/tmp/mnt/TOSHIBA/opt", &folder_num, &folder_list); //yan test

        if(result < 0)
            return 0;

        first_log = 1;
        for(i = 0; i < folder_num; i++)
        {
            if(first_log == 1)
            {
                printf("[\"%s\"]", folder_list[i]);
                first_log = 0;
            }
            else
            {
                printf(",[\"%s\"]", folder_list[i]);
            }
        }

    }

    fflush(stdout);
    return 0;

}


int get_all_folder_in_mount_path(const char *const mount_path, int *sh_num, char ***folder_list){
    DIR *pool_to_open;
    struct dirent *dp;
    char *testdir;
    char **tmp_folder_list, **tmp_folder;
    int len, i;

    pool_to_open = opendir(mount_path);
    if(pool_to_open == NULL){
        //csprintf("Can't opendir \"%s\".\n", mount_path);
        return -1;
    }

    *sh_num = 0;
    while((dp = readdir(pool_to_open)) != NULL){
        //if(!strcmp(dp->d_name, ".") || !strcmp(dp->d_name, ".."))
        if(dp->d_name[0] == '.')
            continue;

        if(test_if_System_folder(dp->d_name) == 1)
            continue;

        len = strlen(mount_path)+strlen("/")+strlen(dp->d_name);
        testdir = (char *)malloc(sizeof(char)*(len+1));
        if(testdir == NULL){
            closedir(pool_to_open);
            return -1;
        }
        sprintf(testdir, "%s/%s", mount_path, dp->d_name);
        testdir[len] = 0;
        if(!test_if_dir(testdir)){
            free(testdir);
            continue;
        }
        free(testdir);

        tmp_folder = (char **)malloc(sizeof(char *)*(*sh_num+1));
        if(tmp_folder == NULL){
            //csprintf("Can't malloc \"tmp_folder\".\n");

            return -1;
        }

        len = strlen(dp->d_name);
        tmp_folder[*sh_num] = (char *)malloc(sizeof(char)*(len+1));
        if(tmp_folder[*sh_num] == NULL){
            //csprintf("Can't malloc \"tmp_folder[%d]\".\n", *sh_num);
            free(tmp_folder);

            return -1;
        }
        strcpy(tmp_folder[*sh_num], dp->d_name);
        if(*sh_num != 0){
            for(i = 0; i < *sh_num; ++i)
                tmp_folder[i] = tmp_folder_list[i];

            free(tmp_folder_list);
            tmp_folder_list = tmp_folder;
        }
        else
            tmp_folder_list = tmp_folder;

        ++(*sh_num);
    }
    closedir(pool_to_open);

    *folder_list = tmp_folder_list;

    return 0;
}

int test_if_System_folder(const char *const dirname){
    char *MS_System_folder[] = {"SYSTEM VOLUME INFORMATION", "RECYCLER", "RECYCLED", NULL};
    char *Linux_System_folder[] = {"lost+found", NULL};
    int i;

    for(i = 0; MS_System_folder[i] != NULL; ++i){
        if(!upper_strcmp(dirname, MS_System_folder[i]))
            return 1;
    }

    for(i = 0; Linux_System_folder[i] != NULL; ++i){
        if(!upper_strcmp(dirname, Linux_System_folder[i]))
            return 1;
    }

    return 0;
}

int test_if_dir(const char *dir){
    DIR *dp = opendir(dir);

    if(dp == NULL)
        return 0;

    closedir(dp);
    return 1;
}

int upper_strcmp(const char *const str1, const char *const str2){
    int len1, len2, i;

    len1 = strlen(str1);
    len2 = strlen(str2);
    if(len1 != len2)
        return len1-len2;

    for(i = 0; i < len1; ++i){
        if(toupper(str1[i]) != toupper(str2[i]))
            return i+1;
    }

    return 0;
}
