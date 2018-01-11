#define PMK_LEN                         32
#ifdef RTL_WPA2
#define PMKID_LEN                       16
#endif
#define PTK_LEN                         64
#define PTK_LEN_TKIP            64
#define PTK_LEN_NO_TKIP         48      //for CCMP, WRAP, WEP
#define PTK_LEN_CCMP            48
#define PTK_LEN_WRAP            48
#define PTK_LEN_WEP             48

#define PTK_LEN_EAPOLMIC        16
#define PTK_LEN_EAPOLENC        16

#define GMK_LEN                 32
#define GTK_LEN			32
#define GTK_LEN_TKIP            32      //32 for TKIP and 16 for CCMP, WRAP, WEP
#define GTK_LEN_NO_TKIP         16
#define GTK_LEN_CCMP            16
#define GTK_LEN_WRAP            16
#define GTK_LEN_WEP             16
#ifdef CONFIG_IEEE80211W
#define IGTK_LEN 16
#endif /* CONFIG_IEEE80211W */


#ifdef CONFIG_IEEE80211R
#define INFO_ELEMENT_SIZE       384
#else
#define INFO_ELEMENT_SIZE       128
#endif

#define MAX_EAPOLMSG_LEN        512
#define MAX_EAPOLKEYMSG_LEN MAX_EAPOLMSG_LEN - (ETHER_HDRLEN + LIB1X_EAPOL_HDRLEN)
#define EAPOLMSG_HDRLEN         95      //EAPOL-key payload length without KeyData

#define KEY_RC_LEN                      8
#define KEY_NONCE_LEN           32
#define KEY_IV_LEN                      16
#define KEY_RSC_LEN                     8
#define KEY_ID_LEN                      8
#define KEY_MIC_LEN                     16
#define KEY_MATERIAL_LEN        2

#define DescTypePos                     0
#define KeyInfoPos                      1
#define KeyLenPos                       3
#define ReplayCounterPos        5
#define KeyNoncePos                     13
#define KeyIVPos                        45
#define KeyRSCPos                       61
#define KeyIDPos                        69
#define KeyMICPos                       77
#define KeyDataLenPos           93
#define KeyDataPos                      95
