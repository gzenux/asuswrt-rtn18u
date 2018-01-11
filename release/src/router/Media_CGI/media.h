#include <arpa/inet.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#ifdef WRITE2FLASH
#include <linux/mtd/mtd.h>
#endif
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/vfs.h>

#include <sys/socket.h>
#include <sys/klog.h>
#include <stdarg.h>
#include <sys/wait.h>
#include <syslog.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>

#define FILE_MODE  (S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH)
#define MAX_SHOWS  100	// webpage max display lists
#define foreac(word, wordlist, next) \
        for (next = &wordlist[strspn(wordlist, " ")], \
             strncpy(word, next, sizeof(word)), \
             word[strcspn(word, " ")] = '\0', \
             word[sizeof(word) - 1] = '\0', \
             next = strchr(next, ' '); \
             strlen(word); \
             next = next ? &next[strspn(next, " ")] : "", \
             strncpy(word, next, sizeof(word)), \
             word[strcspn(word, " ")] = '\0', \
             word[sizeof(word) - 1] = '\0', \
             next = strchr(next, ' '))

typedef struct disk_info disk_info_t;
typedef struct partition_info partition_info_t;

char ehci_string[32];
char ohci_string[32];

struct disk_info{
        char *tag;
        char *vendor;
        char *model;
        char *device;
        unsigned int major;
        unsigned int minor;
        char *port;
        unsigned int partition_number;
        unsigned int mounted_number;
        unsigned long long size_in_kilobytes;
        partition_info_t *partitions;
        disk_info_t *next;
} ;

struct partition_info{
        char *device;
        char *label;
        unsigned int partition_order;
        char *mount_point;
        char *file_system;
        char *permission;
        unsigned long long size_in_kilobytes;
        unsigned long long used_kilobytes;
        disk_info_t *disk;
        partition_info_t *next;
} ;
	
char  tag_dir[256];
char *Base_dir;

int remain_lists ;
int  first_log;

/* CGI helper functions */
extern void init_cgi(char *query);
extern char * get_cgi(char *name);
#define websGetVar(wp, var, default) (get_cgi(var) ? : default)

