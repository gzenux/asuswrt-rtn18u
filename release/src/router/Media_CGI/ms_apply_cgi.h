#ifndef DM_APPLY_CGI_H
#define DM_APPLY_CGI_H 1

char *getlogid2(const char *);
void init_tmp_dst(char *dst, char *src, int );
void print_apply(char* );
void DM_APPLY(char* );
int DM_CTRL(char* cmd, char*  , char* );
void unencode(char *, char *, char *);

#endif
