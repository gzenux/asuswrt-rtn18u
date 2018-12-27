/* test.h */
/* $Id: //BBN_Linux/Branch/Branch_for_SDK_Release_MultiChip_20111013/tclinux_phoenix/apps/public/openssl-1.0.0d/demos/easy_tls/test.h#1 $ */


void test_process_init(int fd, int client_p, void *apparg);
#define TLS_APP_PROCESS_INIT test_process_init

#undef TLS_CUMULATE_ERRORS

void test_errflush(int child_p, char *errbuf, size_t num, void *apparg);
#define TLS_APP_ERRFLUSH test_errflush
