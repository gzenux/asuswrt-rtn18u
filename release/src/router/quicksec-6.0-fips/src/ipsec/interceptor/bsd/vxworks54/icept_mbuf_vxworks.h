/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   A mbuf management portability layer definitions and functions between
   freeBSD 22 and VxWorks.
*/

/* VxWorks IPV4/IPV6 dual stack defines in a file target/h/net/mbuf.h
   MLEN, MHLEN etc. but definitions are not compatible with interceptor code
   as Windriver uses a cluster to simulate a data area in mbuf. Incompatible
   macros are redefined. In addition Windriver stores a pointer to a mbuf in
   cluster buffer. Packets coming from the IP-stack has the "back-pointer" in
   cluster buffer. However packets coming from network drivers do not have it.
   The "back pointer" appears to be something used internally by Windriver
   stack. We will not implement it in mbufs we generate. */

#ifdef MLEN
#undef MLEN
#endif
#define MLEN            0     /* normal data len */

#ifdef MHLEN
#undef MHLEN
#endif
#define MHLEN           0     /* data len w/pkthdr */

#ifdef MINCLSIZE
#undef MINCLSIZE
#endif
#define MINCLSIZE       (MHLEN+MLEN+1)  /* smallest amount to put in cluster */

/* Get a single mbuf, mbuf = mBlk in vxworks cannot contain any data,
   it has to be used in conjunction with MCLGET and store the data
   in the memory block cluster */
#ifdef MGET
#undef MGET
#endif
#define MGET(m, wait, type) \
  (m) = mBlkGet(_pNetDpool, (wait), (type))

#ifdef MGETHDR
#undef MGETHDR
#endif
#define MGETHDR(m, wait, type) \
do { \
  (m) = mBlkGet (_pNetDpool, (wait), (type)); \
    if ((m) != NULL) \
      (m)->m_flags |= M_PKTHDR; \
} while (0)

#ifndef M_COPY_PKTHDR
#define M_COPY_PKTHDR(to, from) \
do { \
  (to)->m_pkthdr = (from)->m_pkthdr; \
  (to)->m_flags = (from)->m_flags & M_COPYFLAGS; \
} while (0)
#endif

/* Frees a single mbuf m and places the successor, if any, in mbuf
   n. Implemented as a macro. */
#ifdef MFREE
#undef MFREE
#endif
#define MFREE(m, n) \
do { \
  (n) = (m)->m_next; \
  m_free((m)); \
} while (0)

/* Define this in case Windriver decides to include back-pointer into this
   calculation */
#undef M_LEADINGSPACE
#define	M_LEADINGSPACE(m) ((m)->m_data - (m)->m_extBuf)

/* Corrected buggy WindRiver macro from h/net/mbuf.h in old vxWorks versions */
#undef M_TRAILINGSPACE
#define M_TRAILINGSPACE(m) (((m)->m_extBuf + (m)->m_extSize) - \
  ((m)->m_data + (m)->m_len))

#define SSH_MCLGET(m, wait, size) \
  mClGet(_pNetDpool,(m),(size),(wait),FALSE)

#define SSH_MCLBYTES(m) (m)->m_extSize
#define SSH_MFREE(m,n) MFREE(m,n)
