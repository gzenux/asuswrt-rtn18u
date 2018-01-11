#ifndef TYPEDEF_H
#define TYPEDEF_H

#ifdef RSDK_BUILT  
#include <linux/types.h>
#else
#include <stddef.h>
#endif


// Private Area ====================================================
typedef unsigned char		UCHAR;
typedef unsigned short		USHORT;
typedef unsigned long		ULONG;

#ifdef RSDK_BUILT
  typedef long long			LONGLONG;
  typedef unsigned long long	ULONGLONG;
#endif

// ======== ====================================================
#ifdef RSDK_BUILT
     typedef void        VOID;
#endif

typedef void *		PVOID;

typedef UCHAR		BOOLEAN,*PBOOLEAN;

typedef UCHAR		u1Byte,*pu1Byte;
typedef USHORT		u2Byte,*pu2Byte;
typedef ULONG		u4Byte,*pu4Byte;

#ifdef RSDK_BUILT
  typedef ULONGLONG	u8Byte,*pu8Byte;
#endif

typedef char			s1Byte,*ps1Byte;
typedef short			s2Byte,*ps2Byte;
typedef long			s4Byte,*ps4Byte;

#ifdef RSDK_BUILT
  typedef LONGLONG	s8Byte,*ps8Byte;
#endif

#endif
