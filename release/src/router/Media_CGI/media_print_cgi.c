#include "media.h"

char *read_whole_file(const char *target) {
    FILE *fp = fopen(target, "r");
    char *buffer, *new_str;
    int i;
    unsigned int read_bytes = 0;
    unsigned int each_size = 1024;

    if (fp == NULL)
        return NULL;

    buffer = (char *)malloc(sizeof(char)*each_size+read_bytes);
    if (buffer == NULL) {
        fprintf(stderr,"No memory \"buffer\".\n");
        fclose(fp);
        return NULL;
    }
    memset(buffer, 0, sizeof(char)*each_size+read_bytes);

    while ((i = fread(buffer+read_bytes, each_size * sizeof(char), 1, fp)) == 1){
        read_bytes += each_size;
        new_str = (char *)malloc(sizeof(char)*each_size+read_bytes);
        if (new_str == NULL) {
            fprintf(stderr,"No memory \"new_str\".\n");
            free(buffer);
            fclose(fp);
            return NULL;
        }
        memset(new_str, 0, sizeof(char)*each_size+read_bytes);
        memcpy(new_str, buffer, read_bytes);

        free(buffer);
        buffer = new_str;
    }

    fclose(fp);
    return buffer;
}

char *get_line_from_buffer(const char *buf, char *line, const int line_size){
    int buf_len, len;
    char *ptr;

    if(buf == NULL || (buf_len = strlen(buf)) <= 0)
        return NULL;

    if((ptr = strchr(buf, '\n')) == NULL)
        ptr = (char *)(buf+buf_len);

    if((len = ptr-buf) < 0)
        len = buf-ptr;
    ++len; // include '\n'.

    memset(line, 0, line_size);
    strncpy(line, buf, len);

    return line;
}

int get_device_type_by_device(const char *device_name){
    if(device_name == NULL || strlen(device_name) <= 0){
        fprintf(stderr,"(%s): The device name is not correct.\n", device_name);
        return 0;
    }

    if(!strncmp(device_name, "sd", 2) || !strncmp(device_name, "hd", 2))
    {
        return 1;
    }

    return 0;
}

int is_disk_name(const char *device_name){
    if(get_device_type_by_device(device_name) != 1)
        return 0;

    if(isdigit(device_name[strlen(device_name)-1]))
        return 0;

    return 1;
}

disk_info_t *initial_disk_data(disk_info_t **disk_info_list){
    disk_info_t *follow_disk;

    if(disk_info_list == NULL)
        return NULL;

    *disk_info_list = (disk_info_t *)malloc(sizeof(disk_info_t));
    if(*disk_info_list == NULL)
        return NULL;

    follow_disk = *disk_info_list;

    follow_disk->tag = NULL;
    follow_disk->vendor = NULL;
    follow_disk->model = NULL;
    follow_disk->device = NULL;
    follow_disk->major = (unsigned int)0;
    follow_disk->minor = (unsigned int)0;
    follow_disk->port = NULL;
    follow_disk->partition_number = (unsigned int)0;
    follow_disk->mounted_number = (unsigned int)0;
    follow_disk->size_in_kilobytes = (unsigned long long)0;
    follow_disk->partitions = NULL;
    follow_disk->next = NULL;

    return follow_disk;
}

void free_partition_data(partition_info_t **partition_info_list){
    partition_info_t *follow_partition, *old_partition;

    if(partition_info_list == NULL)
        return;

    follow_partition = *partition_info_list;
    while(follow_partition != NULL){
        if(follow_partition->device != NULL)
            free(follow_partition->device);
        if(follow_partition->mount_point != NULL)
            free(follow_partition->mount_point);
        if(follow_partition->file_system != NULL)
            free(follow_partition->file_system);
        if(follow_partition->permission != NULL)
            free(follow_partition->permission);

        follow_partition->disk = NULL;

        old_partition = follow_partition;
        follow_partition = follow_partition->next;
        free(old_partition);
    }
}

void free_disk_data(disk_info_t **disk_info_list){
    disk_info_t *follow_disk, *old_disk;

    if(disk_info_list == NULL)
        return;

    follow_disk = *disk_info_list;
    while(follow_disk != NULL){
        if(follow_disk->tag != NULL)
            free(follow_disk->tag);
        if(follow_disk->vendor != NULL)
            free(follow_disk->vendor);
        if(follow_disk->model != NULL)
            free(follow_disk->model);
        if(follow_disk->device != NULL)
            free(follow_disk->device);
        if(follow_disk->port != NULL)
            free(follow_disk->port);

        free_partition_data(&(follow_disk->partitions));

        old_disk = follow_disk;
        follow_disk = follow_disk->next;
        free(old_disk);
    }
}

int get_disk_major_minor(const char *disk_name, unsigned int *major, unsigned int *minor){
    FILE *fp;
    char target_file[128], buf[8], *ptr;

    if(major == NULL || minor == NULL)
        return 0;

    *major = 0; // initial value.
    *minor = 0; // initial value.

    if(disk_name == NULL || !is_disk_name(disk_name))
        return 0;

    memset(target_file, 0, 128);
    sprintf(target_file, "%s/%s/dev", "/sys/block", disk_name);
    if((fp = fopen(target_file, "r")) == NULL)
        return 0;

    memset(buf, 0, 8);
    ptr = fgets(buf, 8, fp);
    fclose(fp);
    if(ptr == NULL)
        return 0;

    if((ptr = strchr(buf, ':')) == NULL)
        return 0;

    ptr[0] = '\0';
    *major = (unsigned int)strtol(buf, NULL, 10);
    *minor = (unsigned int)strtol(ptr+1, NULL, 10);

    return 1;
}

get_disk_size(const char *disk_name, unsigned long long *size_in_kilobytes){
    FILE *fp;
    char target_file[128], buf[16], *ptr;

    if(size_in_kilobytes == NULL)
        return 0;

    *size_in_kilobytes = 0; // initial value.

    if(disk_name == NULL || !is_disk_name(disk_name))
        return 0;

    memset(target_file, 0, 128);
    sprintf(target_file, "%s/%s/size", "/sys/block", disk_name);
    if((fp = fopen(target_file, "r")) == NULL)
        return 0;

    memset(buf, 0, 16);
    ptr = fgets(buf, 16, fp);
    fclose(fp);
    if(ptr == NULL)
        return 0;

    *size_in_kilobytes = ((unsigned long long)strtoll(buf, NULL, 10))/2;

    return 1;
}

#define USB_EHCI_PORT_1 get_usb_ehci_port(0)
#define USB_EHCI_PORT_2 get_usb_ehci_port(1)
#define USB_OHCI_PORT_1 get_usb_ohci_port(0)
#define USB_OHCI_PORT_2 get_usb_ohci_port(1)
#define USB_EHCI_PORT_3 get_usb_ehci_port(2)
#define USB_OHCI_PORT_3 get_usb_ohci_port(2)

char *safe_get(char *ports)
{
    FILE *fp;
    int flag = 0;
    fp = fopen("/tmp/Mediaserver/ports.conf","r");
    if(fp != NULL)
    {
        char *buf= NULL;
        buf = (char *)malloc(50);
        while(!feof(fp))
        {	memset(buf,'\0',50);
            fscanf(fp,"%[^\n]%*c",buf);
            if(!strncmp(buf,ports,strlen(ports)))
            {
                buf = buf + 11;
                flag = 1;
                break;
            }
        }
        if(flag == 0)
            fprintf(stderr,"in file (/tmp/Mediaserver/ports.conf), have no %s\n",ports);

        return buf;
    }
    else
        fprintf(stderr,"have no file (/tmp/Mediaserver/ports.conf) exists\n");

    return NULL;
}


char *get_usb_ehci_port(int port)
{
    char word[100], *next;
    int i=0;
    char *a;
    a = safe_get("ehci_ports");

    strcpy(ehci_string, "xxxxxxxx");

    foreac(word, a, next) {
        if(i==port) {
            strcpy(ehci_string, word);
            break;
        }
        i++;
    }
    a = a - 11;
    free(a);
    return ehci_string;
}

char *get_usb_ohci_port(int port)
{
    char word[100], *next;
    int i=0;
    char *a;
    a = safe_get("ohci_ports");

    strcpy(ohci_string, "xxxxxxxx");

    foreac(word, a, next) {
        if(i==port) {
            strcpy(ohci_string, word);
            break;
        }
        i++;
    }
    a = a - 11;
    free(a);
    return ohci_string;
}

char *get_usb_port_by_string(const char *target_string, char *buf, const int buf_size){
    memset(buf, 0, buf_size);

    if(strstr(target_string, USB_EHCI_PORT_1))
        strcpy(buf, USB_EHCI_PORT_1);
    else if(strstr(target_string, USB_EHCI_PORT_2))
        strcpy(buf, USB_EHCI_PORT_2);
    else if(strstr(target_string, USB_OHCI_PORT_1))
        strcpy(buf, USB_OHCI_PORT_1);
    else if(strstr(target_string, USB_OHCI_PORT_2))
        strcpy(buf, USB_OHCI_PORT_2);
    else if(strstr(target_string, USB_EHCI_PORT_3))
        strcpy(buf, USB_EHCI_PORT_3);
    else if(strstr(target_string, USB_OHCI_PORT_3))
        strcpy(buf, USB_OHCI_PORT_3);
    else
        return NULL;

    return buf;
}

char *get_usb_port_by_device(const char *device_name, char *buf, const int buf_size){
    int device_type = get_device_type_by_device(device_name);
    char device_path[128], usb_path[PATH_MAX];
    char disk_name[4];
    if(device_type == 0)
        return NULL;

    memset(device_path, 0, 128);
    memset(usb_path, 0, PATH_MAX);

    if(device_type == 1){
        memset(disk_name, 0, 4);
        strncpy(disk_name, device_name, 3);
        sprintf(device_path, "%s/%s/device", "/sys/block", disk_name);
        if(realpath(device_path, usb_path) == NULL){
            fprintf(stderr,"(%s): Fail to get link: %s.\n", device_name, device_path);
            return NULL;
        }
    }
    else
        return NULL;

    if(get_usb_port_by_string(usb_path, buf, buf_size) == NULL){
        fprintf(stderr,"(%s): Fail to get usb port: %s.\n", device_name, usb_path);
        return NULL;
    }

    return buf;
}

int get_usb_port_number(const char *usb_port){
    char word[100], *next;
    int port_num, i;
    char *a;
    a = safe_get("ehci_ports");

    port_num = 0;
    i = 0;
    foreac(word, a, next){
        ++i;
        if(!strcmp(usb_port, word)){
            port_num = i;
            break;
        }
    }
	a = a - 11;
	free(a);
    a = NULL;
    a = safe_get("ohci_ports");

    i = 0;
    if(port_num == 0){
        foreac(word, a, next){
            ++i;
            if(!strcmp(usb_port, word)){
                port_num = i;
                break;
            }
        }
    }
	a = a - 11;
	free(a);
	a = NULL;

    return port_num;
}

char *get_disk_vendor(const char *disk_name, char *buf, const int buf_size){
    FILE *fp;
    char target_file[128], *ptr;
    int len;

    if(buf_size <= 0)
        return NULL;

    if(disk_name == NULL || !is_disk_name(disk_name))
        return NULL;

    memset(target_file, 0, 128);
    sprintf(target_file, "%s/%s/device/vendor", "/sys/block", disk_name);
    if((fp = fopen(target_file, "r")) == NULL)
        return NULL;

    memset(buf, 0, buf_size);
    ptr = fgets(buf, buf_size, fp);
    fclose(fp);
    if(ptr == NULL)
        return NULL;

    len = strlen(buf);
    buf[len-1] = 0;

    return buf;
}

void strntrim(char *str){
    register char *start, *end;
    int len;

    if(str == NULL)
        return;

    len = strlen(str);
    start = str;
    end = start+len-1;

    while(start < end && isspace(*start))
        ++start;
    while(start <= end && isspace(*end))
        --end;

    end++;

    if((int)(end-start) < len){
        memcpy(str, start, (end-start));
        str[end-start] = 0;
    }

    return;
}

char *get_disk_model(const char *disk_name, char *buf, const int buf_size){
    FILE *fp;
    char target_file[128], *ptr;
    int len;

    if(buf_size <= 0)
        return NULL;

    if(disk_name == NULL || !is_disk_name(disk_name))
        return NULL;

    memset(target_file, 0, 128);
    sprintf(target_file, "%s/%s/device/model", "/sys/block", disk_name);
    if((fp = fopen(target_file, "r")) == NULL)
        return NULL;

    memset(buf, 0, buf_size);
    ptr = fgets(buf, buf_size, fp);
    fclose(fp);
    if(ptr == NULL)
        return NULL;

    len = strlen(buf);
    buf[len-1] = 0;

    return buf;
}


extern int get_disk_partitionnumber(const char *string, unsigned int *partition_number, unsigned int *mounted_number){
    char disk_name[8];
    char target_path[128];
    DIR *dp;
    struct dirent *file;
    int len;
    char *mount_info = NULL, target[8];

    if(partition_number == NULL)
        return 0;

    *partition_number = 0; // initial value.
    if(mounted_number != NULL)
        *mounted_number = 0; // initial value.

    if(string == NULL)
        return 0;

    len = strlen(string);
    if(!is_disk_name(string)){
        while(isdigit(string[len-1]))
            --len;
    }
    memset(disk_name, 0, 8);
    strncpy(disk_name, string, len);

    memset(target_path, 0, 128);
    sprintf(target_path, "%s/%s", "/sys/block", disk_name);
    if((dp = opendir(target_path)) == NULL)
        return 0;

    len = strlen(disk_name);
    if(mounted_number != NULL)
        mount_info = read_whole_file("/proc/mounts");
    while((file = readdir(dp)) != NULL){
        if(file->d_name[0] == '.')
            continue;

        if(!strncmp(file->d_name, disk_name, len)){
            ++(*partition_number);

            if(mounted_number == NULL || mount_info == NULL)
                continue;

            memset(target, 0, 8);
            sprintf(target, "%s ", file->d_name);
            if(strstr(mount_info, target) != NULL)
                ++(*mounted_number);
        }
    }
    closedir(dp);
    if(mount_info != NULL)
        free(mount_info);

    return 1;
}

int is_partition_name(const char *device_name, unsigned int *partition_order){
    int order;
    unsigned int partition_number;

    if(partition_order != NULL)
        *partition_order = 0;

    if(get_device_type_by_device(device_name) != 1)
        return 0;

    // get the partition number in the device_name
    order = (unsigned int)strtol(device_name+3, NULL, 10);
    if(order <= 0 || order == LONG_MIN || order == LONG_MAX)
        return 0;

    if(!get_disk_partitionnumber(device_name, &partition_number, NULL))
        return 0;

    if(partition_order != NULL)
        *partition_order = order;

    return 1;
}

partition_info_t *initial_part_data(partition_info_t **part_info_list){
    partition_info_t *follow_part;

    if(part_info_list == NULL)
        return NULL;

    *part_info_list = (partition_info_t *)malloc(sizeof(partition_info_t));
    if(*part_info_list == NULL)
        return NULL;

    follow_part = *part_info_list;

    follow_part->device = NULL;
    follow_part->partition_order = (unsigned int)0;
    follow_part->mount_point = NULL;
    follow_part->file_system = NULL;
    follow_part->permission = NULL;
    follow_part->size_in_kilobytes = (unsigned long long)0;
    follow_part->used_kilobytes = (unsigned long long)0;
    follow_part->disk = NULL;
    follow_part->next = NULL;

    return follow_part;
}

int read_mount_data(const char *device_name
                    , char *mount_point, int mount_len
                    , char *type, int type_len
                    , char *right, int right_len
                    ){
    char *mount_info = read_whole_file("/proc/mounts");
    char *start, line[256];
    char target[8];

    if(mount_point == NULL || mount_len <= 0
       || type == NULL || type_len <= 0
       || right == NULL || right_len <= 0
       ){
        fprintf(stderr,"Bad input!!\n");
        return 0;
    }

    if(mount_info == NULL){
        fprintf(stderr,"Failed to open \"%s\"!!\n", "/proc/mounts");
        return 0;
    }

    memset(target, 0, 8);
    sprintf(target, "%s", device_name);

    if((start = strstr(mount_info, target)) == NULL){
        //fprintf(stderr,"test_disk2:: %s: Failed to execute strstr()!\n", device_name);
        free(mount_info);
        return 0;
    }

    start += strlen(target);

    if(get_line_from_buffer(start, line, 256) == NULL){
        fprintf(stderr,"%s: Failed to execute get_line_from_buffer()!\n", device_name);
        free(mount_info);
        return 0;
    }

    memset(mount_point, 0, mount_len);
    memset(type, 0, type_len);
    memset(right, 0, right_len);

    if(sscanf(line, "%s %s %[^\n ]", mount_point, type, right) != 3){
        fprintf(stderr,"%s: Failed to execute sscanf()!\n", device_name);
        free(mount_info);
        return 0;
    }
/*
    you had better konw sscanf is not a function and mount_point would be 1 or 2
 */

    right[2] = 0;

    free(mount_info);
    return 1;
}

int get_mount_size(const char *mount_point, unsigned long long *total_kilobytes, unsigned long long *used_kilobytes){
    unsigned long long total_size, free_size, used_size;
    struct statfs fsbuf;

    if(total_kilobytes == NULL || used_kilobytes == NULL)
        return 0;

    *total_kilobytes = 0;
    *used_kilobytes = 0;

    if(statfs(mount_point, &fsbuf))
        return 0;

    total_size = (unsigned long long)((unsigned long long)fsbuf.f_blocks*(unsigned long long)fsbuf.f_bsize);
    free_size = (unsigned long long)((unsigned long long)fsbuf.f_bfree*(unsigned long long)fsbuf.f_bsize);
    used_size = total_size-free_size;

    *total_kilobytes = total_size/1024;
    *used_kilobytes = used_size/1024;

    return 1;
}

int get_partition_size(const char *partition_name, unsigned long long *size_in_kilobytes){
    FILE *fp;
    char disk_name[4];
    char target_file[128], buf[16], *ptr;

    if(size_in_kilobytes == NULL)
        return 0;

    *size_in_kilobytes = 0; // initial value.

    if(!is_partition_name(partition_name, NULL))
        return 0;

    strncpy(disk_name, partition_name, 3);
    disk_name[3] = 0;

    memset(target_file, 0, 128);
    sprintf(target_file, "%s/%s/%s/size", "/sys/block", disk_name, partition_name);
    if((fp = fopen(target_file, "r")) == NULL)
        return 0;

    memset(buf, 0, 16);
    ptr = fgets(buf, 16, fp);
    fclose(fp);
    if(ptr == NULL)
        return 0;

    *size_in_kilobytes = ((unsigned long long)strtoll(buf, NULL, 10))/2;

    return 1;
}

partition_info_t *create_partition(const char *device_name, partition_info_t **new_part_info){
    partition_info_t *follow_part_info;
    unsigned int partition_order;
    unsigned long long size_in_kilobytes = 0, total_kilobytes = 0, used_kilobytes = 0;
    char buf1[PATH_MAX], buf2[64], buf3[PATH_MAX]; // options of mount info needs more buffer size.
    int len;

    if(new_part_info == NULL){
        fprintf(stderr,"Bad input!!\n");
        return NULL;
    }

    *new_part_info = NULL; // initial value.

    if(device_name == NULL || get_device_type_by_device(device_name) != 1)
        return NULL;

    if(!is_disk_name(device_name) && !is_partition_name(device_name, &partition_order))
        return NULL;

    if(initial_part_data(&follow_part_info) == NULL){
        fprintf(stderr,"No memory!!(follow_part_info)\n");
        return NULL;
    }

    len = strlen(device_name);
    follow_part_info->device = (char *)malloc(len+1);
    if(follow_part_info->device == NULL){
        fprintf(stderr,"No memory!!(follow_part_info->device)\n");
        free_partition_data(&follow_part_info);
        return NULL;
    }
    strncpy(follow_part_info->device, device_name, len);
    follow_part_info->device[len] = 0;

    follow_part_info->partition_order = partition_order;

    if(read_mount_data(device_name, buf1, PATH_MAX, buf2, 64, buf3, PATH_MAX)){
        len = strlen(buf1);
        follow_part_info->mount_point = (char *)malloc(len+1);
        if(follow_part_info->mount_point == NULL){
            fprintf(stderr,"No memory!!(follow_part_info->mount_point)\n");
            free_partition_data(&follow_part_info);
            return NULL;
        }
        strncpy(follow_part_info->mount_point, buf1, len);
        follow_part_info->mount_point[len] = 0;

        len = strlen(buf2);
        follow_part_info->file_system = (char *)malloc(len+1);
        if(follow_part_info->file_system == NULL){
            fprintf(stderr,"No memory!!(follow_part_info->file_system)\n");
            free_partition_data(&follow_part_info);
            return NULL;
        }
        strncpy(follow_part_info->file_system, buf2, len);
        follow_part_info->file_system[len] = 0;

        len = strlen(buf3);
        follow_part_info->permission = (char *)malloc(len+1);
        if(follow_part_info->permission == NULL){
            fprintf(stderr,"No memory!!(follow_part_info->permission)\n");
            free_partition_data(&follow_part_info);
            return NULL;
        }
        strncpy(follow_part_info->permission, buf3, len);
        follow_part_info->permission[len] = 0;

        if(get_mount_size(follow_part_info->mount_point, &total_kilobytes, &used_kilobytes)){
            follow_part_info->size_in_kilobytes = total_kilobytes;
            follow_part_info->used_kilobytes = used_kilobytes;
        }
    }
    else{
        /*if(is_disk_name(device_name)){	// Disk
            free_partition_data(&follow_part_info);
            return NULL;
        }
        else{*/
            len = strlen("unknown");
            follow_part_info->file_system = (char *)malloc(len+1);
            if(follow_part_info->file_system == NULL){
                fprintf(stderr,"No memory!!(follow_part_info->file_system)\n");
                free_partition_data(&follow_part_info);
                return NULL;
            }
            strncpy(follow_part_info->file_system, "unknown", len);
            follow_part_info->file_system[len] = 0;

            get_partition_size(device_name, &size_in_kilobytes);
            follow_part_info->size_in_kilobytes = size_in_kilobytes;
        //}
    }

    *new_part_info = follow_part_info;

    return *new_part_info;
}

disk_info_t *create_disk(const char *device_name, disk_info_t **new_disk_info){
    disk_info_t *follow_disk_info;
    unsigned int major, minor;
    unsigned long long size_in_kilobytes = 0;
    int len;
    char buf[64], *port, *vendor, *model, *ptr;
    partition_info_t *new_partition_info, **follow_partition_list;

    if(new_disk_info == NULL){
        fprintf(stderr,"Bad input!!\n");
        return NULL;
    }

    *new_disk_info = NULL; // initial value.

    if(device_name == NULL || !is_disk_name(device_name))
        return NULL;

    if(initial_disk_data(&follow_disk_info) == NULL){
        fprintf(stderr,"No memory!!(follow_disk_info)\n");
        return NULL;
    }

    len = strlen(device_name);
    follow_disk_info->device = (char *)malloc(len+1);
    if(follow_disk_info->device == NULL){
        fprintf(stderr,"No memory!!(follow_disk_info->device)\n");
        free_disk_data(&follow_disk_info);
        return NULL;
    }
    strcpy(follow_disk_info->device, device_name);
    follow_disk_info->device[len] = 0;

    if(!get_disk_major_minor(device_name, &major, &minor)){
        fprintf(stderr,"Fail to get disk's major and minor: %s.\n", device_name);
        free_disk_data(&follow_disk_info);
        return NULL;
    }
    follow_disk_info->major = major;
    follow_disk_info->minor = minor;

    if(!get_disk_size(device_name, &size_in_kilobytes)){
        fprintf(stderr,"Fail to get disk's size_in_kilobytes: %s.\n", device_name);
        free_disk_data(&follow_disk_info);
        return NULL;
    }
    follow_disk_info->size_in_kilobytes = size_in_kilobytes;

    if(!strncmp(device_name, "sd", 2)){
        // Get USB port.
        if(get_usb_port_by_device(device_name, buf, 64) == NULL){
            fprintf(stderr,"Fail to get usb port: %s.\n", device_name);
            free_disk_data(&follow_disk_info);
            return NULL;
        }

        len = strlen(buf);
        if(len > 0){
            port = (char *)malloc(2);
            if(port == NULL){
                fprintf(stderr,"No memory!!(port)\n");
                free_disk_data(&follow_disk_info);
                return NULL;
            }
            memset(port, 0, 2);

            int port_num = get_usb_port_number(buf);
            if(port_num != -1)
                sprintf(port, "%d", port_num);
            else
                strcpy(port, "0");

            follow_disk_info->port = port;
        }

        // start get vendor.
        if(get_disk_vendor(device_name, buf, 64) == NULL){
            fprintf(stderr,"Fail to get disk's vendor: %s.\n", device_name);
            free_disk_data(&follow_disk_info);
            return NULL;
        }

        len = strlen(buf);
        if(len > 0){
            vendor = (char *)malloc(len+1);
            if(vendor == NULL){
                fprintf(stderr,"No memory!!(vendor)\n");
                free_disk_data(&follow_disk_info);
                return NULL;
            }
            strncpy(vendor, buf, len);
            vendor[len] = 0;
            strntrim(vendor);

            follow_disk_info->vendor = vendor;
        }

        // start get model.
        if(get_disk_model(device_name, buf, 64) == NULL){
            fprintf(stderr,"Fail to get disk's model: %s.\n", device_name);
            free_disk_data(&follow_disk_info);
            return NULL;
        }

        len = strlen(buf);
        if(len > 0){
            model = (char *)malloc(len+1);
            if(model == NULL){
                fprintf(stderr,"No memory!!(model)\n");
                free_disk_data(&follow_disk_info);
                return NULL;
            }
            strncpy(model, buf, len);
            model[len] = 0;
            strntrim(model);

            follow_disk_info->model = model;
        }

        // get USB's tag
        memset(buf, 0, 64);
        len = 0;
        ptr = buf;
        if(vendor != NULL){
            len += strlen(vendor);
            strcpy(ptr, vendor);
            ptr += len;
        }
        if(model != NULL){
            if(len > 0){
                ++len; // Add a space between vendor and model.
                strcpy(ptr, " ");
                ++ptr;
            }
            len += strlen(model);
            strcpy(ptr, model);
            ptr += len;
        }

        if(len > 0){
            follow_disk_info->tag = (char *)malloc(len+1);
            if(follow_disk_info->tag == NULL){
                fprintf(stderr,"No memory!!(follow_disk_info->tag)\n");
                free_disk_data(&follow_disk_info);
                return NULL;
            }
            strcpy(follow_disk_info->tag, buf);
            follow_disk_info->tag[len] = 0;
        }
        else{
            len = strlen("USB disk");

            follow_disk_info->tag = (char *)malloc(len+1);
            if(follow_disk_info->tag == NULL){
                fprintf(stderr,"No memory!!(follow_disk_info->tag)\n");
                free_disk_data(&follow_disk_info);
                return NULL;
            }
            strcpy(follow_disk_info->tag, "USB disk");
            follow_disk_info->tag[len] = 0;
        }

        follow_partition_list = &(follow_disk_info->partitions);
        while(*follow_partition_list != NULL)
            follow_partition_list = &((*follow_partition_list)->next);

        new_partition_info = create_partition(device_name, follow_partition_list);
        if(new_partition_info != NULL){
            new_partition_info->disk = follow_disk_info;

            ++(follow_disk_info->partition_number);
            ++(follow_disk_info->mounted_number);
        }
    }

    if(follow_disk_info->partition_number == 0)
        get_disk_partitionnumber(device_name, &(follow_disk_info->partition_number), &(follow_disk_info->mounted_number));

    *new_disk_info = follow_disk_info;

    return *new_disk_info;
}

disk_info_t *read_disk_data()
{
    disk_info_t *disk_info_list = NULL, *new_disk_info, **follow_disk_info_list;
    char *partition_info = read_whole_file("/proc/partitions");
    char *follow_info;
    char line[64], device_name[16];
    unsigned int major;
    disk_info_t *parent_disk_info;
    partition_info_t *new_partition_info, **follow_partition_list;
    unsigned long long device_size;

    if(partition_info == NULL){
        fprintf(stderr,"Failed to open \"%s\"!!\n", "/proc/partitions");
        return disk_info_list;
    }
    follow_info = partition_info;

    memset(device_name, 0, 16);
    while(get_line_from_buffer(follow_info, line, 64) != NULL){
        follow_info += strlen(line);

        if(sscanf(line, "%u %*u %llu %[^\n ]", &major, &device_size, device_name) != 3)
            continue;
        if(major != 8)
            continue;
        if(device_size == 1) // extend partition.
            continue;

        if(is_disk_name(device_name)){ // Disk
            follow_disk_info_list = &disk_info_list;
            while(*follow_disk_info_list != NULL)
                follow_disk_info_list = &((*follow_disk_info_list)->next);
            new_disk_info = create_disk(device_name, follow_disk_info_list);
        }
        else if(is_partition_name(device_name, NULL)){ // Partition
            // Find the parent disk.
            parent_disk_info = disk_info_list;
            while(1){
                if(parent_disk_info == NULL){
                    fprintf(stderr,"Error while parsing %s: found "
                            "partition '%s' but haven't seen the disk device "
                            "of which it is a part.\n", "/proc/partitions", device_name);
                    free(partition_info);
                    return disk_info_list;
                }

                if(!strncmp(device_name, parent_disk_info->device, 3))
                    break;

                parent_disk_info = parent_disk_info->next;
            }

            follow_partition_list = &(parent_disk_info->partitions);
            while(*follow_partition_list != NULL)
                follow_partition_list = &((*follow_partition_list)->next);

            new_partition_info = create_partition(device_name, follow_partition_list);
            if(new_partition_info != NULL)
                new_partition_info->disk = parent_disk_info;
        }
    }

    //disk_info_list->partitions = new_partition_info;
    free(partition_info);
    return disk_info_list;
}

int test_if_System_folder(const char *const dirname){
    const char *const MS_System_folder[] = {"SYSTEM VOLUME INFORMATION", "RECYCLER", "RECYCLED", "$RECYCLE.BIN", NULL};
    const char *const Linux_System_folder[] = {"lost+found", NULL};
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

char *get_upper_str(const char *const str, char **target){
    int len, i;
    char *ptr;

    len = strlen(str);
    *target = (char *)malloc(sizeof(char)*(len+1));
    if(*target == NULL){
        fprintf(stderr,"No memory \"*target\".\n");
        return NULL;
    }
    ptr = *target;
    for(i = 0; i < len; ++i)
        ptr[i] = toupper(str[i]);
    ptr[len] = 0;

    return ptr;
}

int upper_strcmp(const char *const str1, const char *const str2){
    char *upper_str1, *upper_str2;
    int ret;

    if(str1 == NULL || str2 == NULL)
        return -1;

    if(get_upper_str(str1, &upper_str1) == NULL)
        return -1;

    if(get_upper_str(str2, &upper_str2) == NULL){
        free(upper_str1);
        return -1;
    }

    ret = strcmp(upper_str1, upper_str2);
    free(upper_str1);
    free(upper_str2);

    return ret;
}

int
        check_if_dir_exist(const char *dirpath)
{
    struct stat stat_buf;

    if (!stat(dirpath, &stat_buf))
        return S_ISDIR(stat_buf.st_mode);
    else
        return 0;
}

int get_all_folder(const char *const mount_path, int *sh_num, char ***folder_list) {
    DIR *pool_to_open;
    struct dirent *dp;
    char *testdir;
    char **tmp_folder_list, **tmp_folder;
    int len, i;

    pool_to_open = opendir(mount_path);
    if (pool_to_open == NULL) {
        fprintf(stderr,"Can't opendir \"%s\".\n", mount_path);
        return -1;
    }

    *sh_num = 0;
    while ((dp = readdir(pool_to_open)) != NULL) {
        if (dp->d_name[0] == '.')
            continue;

        if (test_if_System_folder(dp->d_name) == 1)
            continue;

        len = strlen(mount_path)+strlen("/")+strlen(dp->d_name);
        testdir = (char *)malloc(sizeof(char)*(len+1));
        if (testdir == NULL) {
            closedir(pool_to_open);
            return -1;
        }
        sprintf(testdir, "%s/%s", mount_path, dp->d_name);
        testdir[len] = 0;
        if (!check_if_dir_exist(testdir)) {
            free(testdir);
            continue;
        }
        free(testdir);

        tmp_folder = (char **)malloc(sizeof(char *)*(*sh_num+1));
        if (tmp_folder == NULL) {
            fprintf(stderr,"Can't malloc \"tmp_folder\".\n");
            return -1;
        }

        len = strlen(dp->d_name);
        tmp_folder[*sh_num] = (char *)malloc(sizeof(char)*(len+1));
        if (tmp_folder[*sh_num] == NULL) {
            fprintf(stderr,"Can't malloc \"tmp_folder[%d]\".\n", *sh_num);
            free(tmp_folder);
            return -1;
        }
        strcpy(tmp_folder[*sh_num], dp->d_name);
        if (*sh_num != 0) {
            for (i = 0; i < *sh_num; ++i)
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

void free_2_dimension_list(int *num, char ***list) {
    int i;
    char **target = *list;

    if (*num <= 0 || target == NULL){
        *num = 0;
        return;
    }

    for (i = 0; i < *num; ++i)
        if (target[i] != NULL)
            free(target[i]);

    if (target != NULL)
        free(target);

    *num = 0;
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
    //fprintf(stderr,"getdata=%s\n",data);
    init_cgi(data);	// there wasn't '?' in the head.
    char *value;
    char *url;
    char *type;
    char *current_url;
    char *next_url;
    char *next_host;
    char *script;

    value = websGetVar(wp, "action_mode", "");
    //fprintf(stderr,"value=%s\n",value);

    if(!strcmp(value,"MEDIASERVER_GETCONFIG")){
        FILE *fp;
        int i;
        int j = 0;
        char content[256];
        char output_conf[7][256];
        memset(content, 0, sizeof(content));
        if(fp = fopen("/opt/etc/Mediaserver.conf", "r"))
        {
            while(fgets(content, 256, fp))
            {
                if(content[strlen(content)-1]=='\n')
                    content[strlen(content)-1]='\0';
                for(i=0;i<strlen(content);i++)
                {
                    if(content[i] == '=')
                        break;
                }
                strcpy(output_conf[j],content + i + 1);
                j++;
            }
            if(strcmp(output_conf[6],"1"))
                printf("[\"%s\",\"%s\",\"\",\"\",\"%s\",\"%s\",\"%s\"]",output_conf[0],output_conf[1],output_conf[4],output_conf[5],output_conf[6]);
            else
                printf("[\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\",\"%s\"]",output_conf[0],output_conf[1],output_conf[2],output_conf[3],output_conf[4],output_conf[5],output_conf[6]);

            fclose(fp);
        }
        else
            fprintf(stderr,"\nread config error!\n");
    }
    else if(!strncmp(value,"MEDIASERVER_GETSTATUS",21))
    {
        //fprintf(stderr,"\nvalue=%s\n",value);
        memset(tag_dir,0,sizeof(tag_dir));
        sprintf(tag_dir, "%s","/tmp/Mediaserver/scantag");
        printf("[");
        if(access(tag_dir, 0) == 0)
        {
            printf("\"Scanning\"");
        }
        else{
            printf("\"Idle\"");
        }
        printf("]");
        /*char *point;
        point = value;
        point = point + 30;
        //fprintf(stderr,"\npoint=%s\n",point);
        if(access(point,0) == 0)
            printf(",\"folder is OK\"]");
        else
            printf(",\"folder is Flase\"]");*/
    }
    else if(!strncmp(value,"layer_order",11))
    {
        char *layer_order;
        char *follow_info, *follow_info_end, backup;
        int layer = 0, first;
        int disk_count, partition_count, folder_count;
        int disk_order = -1, partition_order = -1;
        disk_info_t *disks_info, *follow_disk;
        partition_info_t *follow_partition;
        layer_order = value + 12;

        if (strlen(layer_order) <= 0){
            fprintf(stderr,"No input \"layer_order\"!\n");
            return -1;
        }

        follow_info = index(layer_order, '_');
        while (follow_info != NULL && *follow_info != 0){
            ++layer;
            ++follow_info;
            if (*follow_info == 0)
                break;
            follow_info_end = follow_info;
            while (*follow_info_end != 0 && isdigit(*follow_info_end))
                ++follow_info_end;
            backup = *follow_info_end;
            *follow_info_end = 0;

            if (layer == 1){
                disk_order = atoi(follow_info);
            }
            else if (layer == 2)
                partition_order = atoi(follow_info);
            else{
                *follow_info_end = backup;
                fprintf(stderr,"Input \"%s\" is incorrect!\n", layer_order);
                return -1;
            }

            *follow_info_end = backup;
            follow_info = follow_info_end;
        }

        disks_info = read_disk_data();
        if (disks_info == NULL){
            fprintf(stderr,"Can't read the information of disks.\n");
            return -1;
        }

        first = 1;
        disk_count = 0;
        printf("[");
        for (follow_disk = disks_info; follow_disk != NULL; follow_disk = follow_disk->next, ++disk_count){
            partition_count = 0;
            for (follow_partition = follow_disk->partitions; follow_partition != NULL; follow_partition = follow_partition->next, ++partition_count){
                if (layer != 0 && follow_partition->mount_point != NULL && strlen(follow_partition->mount_point) > 1){
                    int i;
                    char **folder_list;
                    int result;

                    result = get_all_folder(follow_partition->mount_point, &folder_count, &folder_list);
                    if (result < 0){
                        fprintf(stderr,"get_disk_tree: Can't get the folder list in \"%s\".\n", follow_partition->mount_point);

                        folder_count = 0;
                    }

                    if (layer == 2 && disk_count == disk_order && partition_count == partition_order){
                        //printf("[");
                        for (i = 0; i < folder_count; ++i){
                            if (first == 1)
                                first = 0;
                            else
                                printf(", ");

                            printf("\"%s#%u#0\"",folder_list[i],i);
                        }
                        //printf("]");
                    }
                    else if (layer == 1 && disk_count == disk_order){
                        if (first == 1){
                            //printf("[");
                            first = 0;}
                        else
                            printf(", ");

                        follow_info = rindex(follow_partition->mount_point, '/');
                        printf("\"%s#%u#%u\"",follow_info+1, partition_count, folder_count);
                        //if(follow_partition->next == NULL)
                            //printf("]");
                    }

                    free_2_dimension_list(&folder_count, &folder_list);
                }
            }
            if (layer == 0){

                if (follow_disk->next == NULL && first == 1)
                    printf("'%s#%u#%u'",follow_disk->tag, disk_count, partition_count);
                else
                {
                    if (first == 1){
                        printf("'%s#%u#%u'",follow_disk->tag, disk_count, partition_count);
                        first = 0;
                    }
                    else{
                        printf(", ");
                        printf("'%s#%u#%u'",follow_disk->tag, disk_count, partition_count);
                    }
                }
            }

            if (layer > 0 && disk_count == disk_order)
                break;
        }
        printf("]");

        free_disk_data(&disks_info);
    }
    else if(!strncmp(value,"getsharefolder",14))
    {
        char *diskname, *mount_name;
        int sh_num = 0, result, i;
        char **folder_list;
        disk_info_t *disks_info, *follow_disk;
        partition_info_t *follow_partition;
        diskname = value + 15;

        if (strlen(diskname) <= 0){
            fprintf(stderr,"No input \"diskname\"!\n");
            return -1;
        }
        //fprintf(stderr,"\ndiskname=%s\n",diskname);
        disks_info = read_disk_data();
        if (disks_info == NULL){
            fprintf(stderr,"error to read disk data\n");
            return -1;
        }

        for (follow_disk = disks_info; follow_disk != NULL; follow_disk = follow_disk->next)
            for (follow_partition = follow_disk->partitions; follow_partition != NULL; follow_partition = follow_partition->next){
            if(strlen(follow_partition->mount_point) ==1)
                continue;
            mount_name = rindex(follow_partition->mount_point, '/') + 1;
            if (!strncmp(mount_name,diskname,strlen(diskname)) && strlen(follow_partition->mount_point) > 0){
                printf("[\"\"");
                result = get_all_folder(follow_partition->mount_point, &sh_num, &folder_list);
                if (result < 0){

                    fprintf(stderr,"get_AiDisk_status: Can't get the folder list in \"%s\".\n", follow_partition->mount_point);

                    free_2_dimension_list(&sh_num, &folder_list);

                    continue;
                }

                for (i = 0; i < sh_num; ++i){
                    printf(", ");
                    printf("\"%s\"", folder_list[i]);

                }
                printf("]");
            }
        }

        if (disks_info != NULL){
            free_2_dimension_list(&sh_num, &folder_list);
            free_disk_data(&disks_info);
        }

    }
    else if(!strncmp(value,"createfolder",12))
    {
        char path[100];
        int status;
        memset(path,'\0',sizeof(path));
        strncpy(path,"/tmp/mnt/",9);
        strcat(path,value+13);
        if(!access(path,0))
            printf("folder exists");
        else
        {
            status = mkdir(path,0777);
            if(status == 0)
                printf("success");
            else
            {
                printf("error");
            }
        }
    }
    else if(!strncmp(value,"deletefolder",12))
    {
        char path[100];
        int status;
        memset(path,'\0',sizeof(path));
        strncpy(path,"/tmp",4);
        strcat(path,value+13);


        replace(path,"spechar7spechar","&");
        replace(path,"spechar3spechar","#");
        replace(path,"spechar12spechar","+");
        replace(path,"spechar11spechar",";");

        if(access(path,0))
            printf("have no this folder");
        else
        {
            status = remove(path);
            if(status == 0)
                printf("success");
            else
            {
                printf("error");
            }
        }
    }
    else if(!strncmp(value,"modifyfolder",12))
    {
        char disk[100];
        char oldpath[100];
        char newpath[100];
        memset(disk,'\0',sizeof(disk));
        memset(oldpath,'\0',sizeof(oldpath));
        memset(newpath,'\0',sizeof(newpath));
        strncpy(disk,"/tmp/mnt/",9);
        int status;
        char *p;
        //fprintf(stderr,"value=%s\n",value);
        p = strtok(value+13,"@");
        strcat(disk,p);
        //fprintf(stderr,"disk=%s\n",disk);

        p = strtok(NULL,"@");
        strncpy(oldpath,disk,strlen(disk));
        strcat(oldpath,"/");
        strcat(oldpath,p);
        //fprintf(stderr,"oldpath=%s\n",oldpath);

        p = strtok(NULL,"@");
        strncpy(newpath,disk,strlen(disk));
        strcat(newpath,"/");
        strcat(newpath,p);
        //fprintf(stderr,"newpath=%s\n",newpath);

        replace(oldpath,"spechar7spechar","&");
        replace(oldpath,"spechar3spechar","#");
        replace(oldpath,"spechar12spechar","+");
        replace(oldpath,"spechar11spechar",";");
        if(access(oldpath,0))
            printf("have no this folder");
        else if(!access(newpath,0))
            printf("new folder name exists");
        else
        {
            status = rename(oldpath,newpath);
            if(status == 0)
                printf("success");
            else
            {
                printf("error");
            }
        }
    }
    fflush(stdout);

    return 0;
}
