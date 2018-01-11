#ifndef EAPLEAP_H
#define EAPLEAP_H

#include <netinet/in.h>
#include "profile.h"

#define EAP_TYPE_LEAP 0x11

struct leap_data {
  char *keyingMaterial;
  int eapsuccess;
};

struct leap_requests {
  uint8_t version;
  uint8_t reserved;  //unused field
  uint8_t count;  
  uint8_t randval[8];
  uint8_t name[5];   
};

struct leap_responses {
  uint8_t version;
  uint8_t reserved;  //unused field
  uint8_t count;
  uint8_t randval[24];
  uint8_t name[5];
};

struct leap_challenges {
  uint8_t pc[8];
  uint8_t pr[24];
  uint8_t apc[8];
  uint8_t apr[24];
};  
  
int eapleap_setup(struct generic_eap_data *);
int eapleap_process(struct generic_eap_data *, u_char *, int, u_char *, int *);
int eapleap_get_keys(struct interface_data *);
int eapleap_cleanup(struct generic_eap_data *);
int eapleap_done(struct generic_eap_data *);
int eapleap_failed(struct generic_eap_data *);
void print_hex(uint8_t *, int);

#endif
