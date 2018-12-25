/*
 * Copyright (c) 2013 Quantenna Communications, Inc.
 */

#ifndef _QTN_WMM_AC_H
#define _QTN_WMM_AC_H

#define WMM_AC_BE	0
#define WMM_AC_BK	1
#define WMM_AC_VI	2
#define WMM_AC_VO	3
#define WMM_AC_NUM	4
#define QTN_AC_MGMT	WMM_AC_VO
#define WMM_AC_INVALID	WMM_AC_NUM

#define QTN_AC_ORDER	{ WMM_AC_VO, WMM_AC_VI, WMM_AC_BE, WMM_AC_BK }

#define QTN_TID_BE	0
#define QTN_TID_BK	1
#define QTN_TID_2	2
#define QTN_TID_OCS	3
#define QTN_TID_WLAN	4	/* 802.11 encap'ed data from wlan driver */
#define QTN_TID_VI	5
#define QTN_TID_VO	6
#define QTN_TID_MGMT	7
#ifdef PEARL_PLATFORM
#define QTN_TID_IS_80211(tid)	((tid == QTN_TID_MGMT) || (tid == QTN_TID_WLAN) || (tid == QTN_TID_OCS))
#else
#define QTN_TID_IS_80211(tid)	((tid == QTN_TID_MGMT) || (tid == QTN_TID_WLAN))
#endif

#ifdef PEARL_PLATFORM
#ifdef PEARL_A0_DSCP_WAR
#define QTN_TID_ORDER	{ \
	QTN_TID_2,	\
	QTN_TID_MGMT,	\
	QTN_TID_WLAN,	\
	QTN_TID_OCS,	\
	QTN_TID_VO,	\
	QTN_TID_VI,	\
	QTN_TID_BE,	\
	QTN_TID_BK	\
}
#else
#define QTN_TID_ORDER	{ \
	QTN_TID_MGMT,	\
	QTN_TID_WLAN,	\
	QTN_TID_OCS,	\
	QTN_TID_VO,	\
	QTN_TID_VI,	\
	QTN_TID_BE,	\
	QTN_TID_BK,	\
	QTN_TID_2	\
}
#endif
#else
#define QTN_TID_ORDER	{ \
	QTN_TID_MGMT,	\
	QTN_TID_WLAN,	\
	QTN_TID_VO,	\
	QTN_TID_VI,	\
	QTN_TID_BE,	\
	QTN_TID_BK	\
}
#endif

#define QTN_TID_ORDER_DATA { \
	QTN_TID_VO,	\
	QTN_TID_VI,	\
	QTN_TID_BE,	\
	QTN_TID_BK	\
}
#define QTN_TID_ORDER_DATA_BITMAP	(BIT(QTN_TID_VO) |			\
						BIT(QTN_TID_VI) |		\
						BIT(QTN_TID_BE) |		\
						BIT(QTN_TID_BK))

#ifdef PEARL_PLATFORM
#ifdef PEARL_A0_DSCP_WAR
#define QTN_TID_ORDER_POLL { \
	QTN_TID_2,	\
	QTN_TID_VO,	\
	QTN_TID_VI,	\
	QTN_TID_BE,	\
	QTN_TID_BK,	\
	QTN_TID_OCS,	\
	QTN_TID_WLAN,	\
	QTN_TID_MGMT	\
}
#else
#define QTN_TID_ORDER_POLL { \
	QTN_TID_VO,	\
	QTN_TID_VI,	\
	QTN_TID_BE,	\
	QTN_TID_BK,	\
	QTN_TID_2,	\
	QTN_TID_OCS,	\
	QTN_TID_WLAN,	\
	QTN_TID_MGMT	\
}
#endif
#else
#define QTN_TID_ORDER_POLL { \
	QTN_TID_VO,	\
	QTN_TID_VI,	\
	QTN_TID_BE,	\
	QTN_TID_BK,	\
	QTN_TID_WLAN,	\
	QTN_TID_MGMT	\
}
#endif

#define WMM_AC_TO_TID(_ac) (			\
	(_ac == WMM_AC_VO) ? QTN_TID_VO :	\
	(_ac == WMM_AC_VI) ? QTN_TID_VI :	\
	(_ac == WMM_AC_BK) ? QTN_TID_BK :	\
	QTN_TID_BE)

#ifdef PEARL_PLATFORM
#define TID_TO_WMM_AC(_tid) (		\
	(_tid == QTN_TID_BK)	? WMM_AC_BK :	\
	(_tid == QTN_TID_2)	? WMM_AC_BK :	\
	(_tid == QTN_TID_VI)	? WMM_AC_VI :	\
	(_tid == QTN_TID_VO)	? WMM_AC_VO :	\
	(_tid == QTN_TID_OCS)	? QTN_AC_MGMT :	\
	(_tid == QTN_TID_WLAN)	? QTN_AC_MGMT :	\
	(_tid == QTN_TID_MGMT)	? QTN_AC_MGMT :	\
	WMM_AC_BE)
#else
#define TID_TO_WMM_AC(_tid) (		\
	(_tid == QTN_TID_BK)	? WMM_AC_BK :	\
	(_tid == QTN_TID_VI)	? WMM_AC_VI :	\
	(_tid == QTN_TID_VO)	? WMM_AC_VO :	\
	(_tid == QTN_TID_WLAN)	? QTN_AC_MGMT :	\
	(_tid == QTN_TID_MGMT)	? QTN_AC_MGMT :	\
	WMM_AC_BE)
#endif

#define QTN_TID_COLLAPSE(_tid)	WMM_AC_TO_TID(TID_TO_WMM_AC(_tid))

#define AC_TO_QTN_QNUM(_ac)		\
	(((_ac) == WME_AC_BE) ? 1 :	\
	 ((_ac) == WME_AC_BK) ? 0 :	\
	  (_ac))

#ifdef PEARL_PLATFORM
#define QTN_TID_MAP_UNUSED(_tid) (_tid)
#else
#define QTN_TID_MAP_UNUSED(_tid) ( \
	(_tid == QTN_TID_2) ? QTN_TID_BK : \
	(_tid == QTN_TID_OCS) ? QTN_TID_BE : \
	(_tid))
#endif

#endif	/* _QTN_WMM_AC_H */
