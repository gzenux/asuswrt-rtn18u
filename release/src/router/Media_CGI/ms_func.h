#ifndef DM_FUNC_H
#define DM_FUNC_H 1

#include"ms.h"

int tmp_enable, tmp_shour, tmp_smin, tmp_ehour, tmp_emin, tmp_day;
char nv_enable_time[4],nv_data[8], nv_time1[10], nv_time2[10];

typedef struct TM
{
int tm_min;
int tm_hour;
int tm_wday;
}tm;


struct datetime{
	char start[6];		// start time
	char stop[6];		// stop time
	char tmpstop[6];	// cross-night stop time
} __attribute__((packed));

int Sem_close(Sem_t *);
int chk_on_process(char *, char *);
void init_path();
//20120821 magic modify{
//char *getbasepath();
char *getrouterconfig();
char *getdmconfig();
//20120821 magic modify}
char *getlogid(const char *);
int isOnProc(uint8_t status);
int read_log(Log_struc *, char *);
int remove_torrent(char*  , uint8_t );
void check_alive();
void Clear_log(char* );
int  Close_sem(char *);
int  Sem_open(Sem_t *, const char *, int, ... );
int  Sem_post(Sem_t *);
int  Sem_wait(Sem_t *);
void delet(char *s,int d);
void char_to_ascii(char *output, char *input);
int check_download_time();
void small_sleep(float nsec);
int check_ed2k_length(char *url);
int decode_path(char *url);
int detect_process(char * process_name);
int64_t check_disk_space(char *path);
static int in_sched(int now_mins, int now_dow, int sched_begin, int sched_end, int sched_begin2, int sched_end2, int sched_dow);  //2012.07.10 magic added for cross-night
int timecheck_item(char *activeDate, char *activeTime, char *activeTime2);  //2012.07.10 magic added for cross-night
#endif
