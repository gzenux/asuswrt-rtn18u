/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Read and write file from and to the disk in various formats.
   The reading functions with suffix with_limit have a maximum length
   for the file that is being read.
*/

#ifndef SSHFILEIO_H
#define SSHFILEIO_H

/* Read binary file from the disk. Return mallocated buffer and the size of the
   buffer. If the reading of file failes return FALSE. If the file name is NULL
   or "-" then read from the stdin. */
Boolean ssh_read_file(const char *file_name,
                      unsigned char **buf,
                      size_t *buf_len);
/* Read binary file from the disk giving a size limit for the
   file. Return mallocated buffer and the size of the buffer. If the
   reading of file failes return FALSE. If the file name is NULL or
   "-" then read from the stdin. The size_limit is in bytes. If zero
   is used, the read file will try to read the whole file.

   If the file size exceeds the size_limit (given in bytes), FALSE
   is returned.  */
Boolean ssh_read_file_with_limit(const char *file_name,
                                 SshUInt32 size_limit,
                                 unsigned char **buf,
                                 size_t *buf_len);

/* Read base 64 encoded file from the disk. Return mallocated buffer and the
   size of the buffer. If the reading of file failes return FALSE. If the file
   name is NULL or "-" then read from the stdin. */
Boolean ssh_read_file_base64(const char *file_name,
                             unsigned char **buf,
                             size_t *buf_len);

/* Read base 64 encoded file from the disk. Return mallocated buffer
   and the size of the buffer. If the reading of file failes return
   FALSE. If the file name is NULL or "-" then read from the
   stdin. The size_limit is in bytes. If zero is used, the read file
   will try to read the whole file.

   If the file size exceeds the size_limit (given in bytes), FALSE
   is returned. */
Boolean ssh_read_file_base64_with_limit(const char *file_name,
                                        SshUInt32 size_limit,
                                        unsigned char **buf,
                                        size_t *buf_len);


/* Read hexl encoded file from the disk. Return mallocated buffer and the size
   of the buffer. If the reading of file failes return FALSE. If the file name
   is NULL or "-" then read from the stdin. */
Boolean ssh_read_file_hexl(const char *file_name,
                           unsigned char **buf,
                           size_t *buf_len);


/* Read hexl encoded file from the disk. Return mallocated buffer and
   the size of the buffer. If the reading of file failes return
   FALSE. If the file name is NULL or "-" then read from the
   stdin. The size_limit is in bytes. If zero is used, the read file
   will try to read the whole file.

   If the file size exceeds the size_limit (given in bytes), FALSE
   is returned. */
Boolean ssh_read_file_hexl_with_limit(const char *file_name,
                                      SshUInt32 size_limit,
                                      unsigned char **buf,
                                      size_t *buf_len);

/* Read pem/hexl/binary file from the disk. Return mallocated buffer and the
   size of the buffer. If the reading of file failes return FALSE. If the file
   name starts with :p: then assume file is pem encoded, if it starts with :h:
   then it is assumed to be hexl format, and if it starts with :b: then it is
   assumed to be binary. If no :[bph]: is given then file is assumed to be
   binary. If any other letter is given between colons then warning message is
   printed and operation fails. If the file name is NULL or "-" then
   read from the stdin (":p:-" == stdin in pem encoded format). */
Boolean ssh_read_gen_file(const char *file_name,
                          unsigned char **buf,
                          size_t *buf_len);

/* Read pem/hexl/binary file from the disk. Return mallocated buffer
   and the size of the buffer. If the reading of file failes return
   FALSE. If the file name starts with :p: then assume file is pem
   encoded, if it starts with :h: then it is assumed to be hexl
   format, and if it starts with :b: then it is assumed to be
   binary. If no :[bph]: is given then file is assumed to be
   binary. If any other letter is given between colons then warning
   message is printed and operation fails. If the file name is NULL or
   "-" then read from the stdin (":p:-" == stdin in pem encoded
   format). The size_limit is in bytes. If zero is used, the read file
   will try to read the whole file.

   If the file size exceeds the size_limit (given in bytes), FALSE
   is returned. */
Boolean ssh_read_gen_file_with_limit(const char *file_name,
                                     SshUInt32 size_limit,
                                     unsigned char **buf,
                                     size_t *buf_len);


/* Write binary file to the disk. If the write fails retuns FALSE. If the file
   name is NULL or "-" then write to the stdout */
Boolean ssh_write_file(const char *file_name,
                       const unsigned char *buf,
                       size_t buf_len);

/* Write base 64 encoded file to the disk. If the write fails retuns FALSE. If
   the file name is NULL or "-" then write to the stdout. Begin and end are the
   PEM headers written before and after the PEM block. If they are NULL then no
   header/footer is written. */
Boolean ssh_write_file_base64(const char *file_name,
                              const char *begin,
                              const char *end,
                              const unsigned char *buf,
                              size_t buf_len);

/* Write hexl encoded file to the disk. If the write fails retuns FALSE. If the
   file name is NULL or "-" then write to the stdout */
Boolean ssh_write_file_hexl(const char *file_name,
                            const unsigned char *buf,
                            size_t buf_len);

/* Write pem/hexl/binary file from the disk. If the write fails retuns FALSE.
   If the file name starts with :p: then assume file is pem encoded, if it
   starts with :h: then it is assumed to be hexl format, and if it starts with
   :b: then it is assumed to be binary. If no :[bph]: is given then file is
   assumed to be binary. If any other letter is given between colons then
   warning message is printed and operation fails. If the file name is NULL or
   "-" then read from the stdout (":p:-" == stdout in pem encoded format). */
Boolean ssh_write_gen_file(const char *file_name,
                           const char *begin,
                           const char *end,
                           const unsigned char *buf,
                           size_t buf_len);



/* Some predefined size limits to be used with functions that limit
   the size of the file read.  Adjust or add more if necessary. */

/* Use this as a size_limit argument not to have any max
   length for the file */
#define SSH_READ_FILE_NO_LIMIT 0

/* A default size limit for config files, etc... */
#define SSH_READ_FILE_LIMIT_CONFIG_FILE 1024000

/* A default size limit for certificates, keys, etc. */
#define SSH_READ_FILE_LIMIT_CRYPTO_OBJ 96000

/* Commonly used PEM begin and end strings */

/* Generic pem encoded block */
#define SSH_PEM_GENERIC_BEGIN     "-----BEGIN PEM ENCODED DATA-----"
#define SSH_PEM_GENERIC_END       "-----END PEM ENCODED DATA-----"
#define SSH_PEM_GENERIC           SSH_PEM_GENERIC_BEGIN, SSH_PEM_GENERIC_END

/* X.509 Certificate Block */
#define SSH_PEM_X509_BEGIN        "-----BEGIN X509 CERTIFICATE-----"
#define SSH_PEM_X509_END          "-----END X509 CERTIFICATE-----"
#define SSH_PEM_X509              SSH_PEM_X509_BEGIN, SSH_PEM_X509_END

/* SSH X.509 Private Key Block */
#define SSH_PEM_SSH_PRV_KEY_BEGIN "-----BEGIN SSH X.509 PRIVATE KEY-----"
#define SSH_PEM_SSH_PRV_KEY_END   "-----END SSH X.509 PRIVATE KEY-----"
#define SSH_PEM_SSH_PRV_KEY SSH_PEM_SSH_PRV_KEY_BEGIN, SSH_PEM_SSH_PRV_KEY_END

/* X.509 Certificate Revocation List Block */
#define SSH_PEM_X509_CRL_BEGIN    "-----BEGIN X509 CRL-----"
#define SSH_PEM_X509_CRL_END      "-----END X509 CRL-----"
#define SSH_PEM_X509_CRL          SSH_PEM_X509_CRL_BEGIN, SSH_PEM_X509_CRL_END

/* PKCS#10 Certificate Request Block */
#define SSH_PEM_CERT_REQ_BEGIN    "-----BEGIN CERTIFICATE REQUEST-----"
#define SSH_PEM_CERT_REQ_END      "-----END CERTIFICATE REQUEST-----"
#define SSH_PEM_CERT_REQ          SSH_PEM_CERT_REQ_BEGIN, SSH_PEM_CERT_REQ_END

/* PKCS#1 Private Key block */
#define SSH_PEM_PKCS1_RSA_BEGIN    "-----BEGIN RSA PRIVATE KEY-----"
#define SSH_PEM_PKCS1_RSA_END      "-----END RSA PRIVATE KEY-----"
#define SSH_PEM_PKCS1_RSA      SSH_PEM_PKCS1_RSA_BEGIN, SSH_PEM_PKCS1_RSA_END

#define SSH_PEM_PKCS1_DSA_BEGIN    "-----BEGIN DSA PRIVATE KEY-----"
#define SSH_PEM_PKCS1_DSA_END      "-----END DSA PRIVATE KEY-----"
#define SSH_PEM_PKCS1_DSA      SSH_PEM_PKCS1_DSA_BEGIN, SSH_PEM_PKCS1_DSA_END

/* PKCS#8 Private Key block */
#define SSH_PEM_PKCS8_BEGIN    "-----BEGIN PRIVATE KEY-----"
#define SSH_PEM_PKCS8_END      "-----END PRIVATE KEY-----"
#define SSH_PEM_PKCS8          SSH_PEM_PKCS8_BEGIN, SSH_PEM_PKCS8_END

/* Encrypted PKCS#8 Private Key block */
#define SSH_PEM_ENCRYPTED_PKCS8_BEGIN "-----BEGIN ENCRYPTED PRIVATE KEY-----"
#define SSH_PEM_ENCRYPTED_PKCS8_END   "-----END ENCRYPTED PRIVATE KEY-----"
#define SSH_PEM_ENCRYPTED_PKCS8 \
        SSH_PEM_ENCRYPTED_PKCS8_BEGIN, SSH_PEM_ENCRYPTED_PKCS8_END

#endif /* SSHFILEIO_H */
