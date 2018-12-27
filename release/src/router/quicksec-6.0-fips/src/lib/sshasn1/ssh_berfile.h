/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Interface to handle data which is built of sequential
   BER data records. You can remove and add data records and
   also change the data of the records. This interface
   interprets BER records with class and tag zero as empty
   records. The data may become fraqmented in case of
   record removals and additions. This interface also contains
   routine for compress (defraqment) the data.
*/

#ifndef SSH_BER_FILE_H
#define SSH_BER_FILE_H

/* BER file contains sequential BER records. */
typedef struct SshBERFileRec *SshBERFile;

/* Represents one BER encoded blob in the BER file. */
typedef struct SshBERFileRecordRec *SshBERFileRecord;

typedef enum {
  SSH_BER_FILE_ERR_OK,
  SSH_BER_FILE_ERR_MEMORY,
  SSH_BER_FILE_ERR_NO_SPACE,
  SSH_BER_FILE_ERR_INVALID_RECORD,
  SSH_BER_FILE_ERR_FORMAT
} SshBERFileStatus;

/* Creates a BER file object. If data is not NULL, it
   is copied and assumed to contain sequential BER
   data blobs. The file size will be 'data_len' after
   this call even if the 'data' is NULL. */
SshBERFileStatus
ssh_ber_file_create(const unsigned char *data,
                    size_t data_len,
                    SshBERFile *file_ret);

/* Destroys the BER file and the data it contains. */
void
ssh_ber_file_destroy(SshBERFile file);

/* Resizes the BER file. Size difference is given in 'delta'. If
   'delta' is positive file size is incremented and if 'delta' is
   negative file size is decremented. */
SshBERFileStatus
ssh_ber_file_resize(SshBERFile file,
                    SshInt32 delta);

/* Removes all the empty BER records from the middle of file and
   combines them as a one big empty record to the end of the file. */
SshBERFileStatus
ssh_ber_file_compress(SshBERFile file);

/* Gets the size of the empty space in the end of the file. There
   might be more space available if you call ssh_ber_file_compress. */
SshUInt32
ssh_ber_file_get_free_space(SshBERFile file);

/* Returns the pointer to the data which contains all the
   records of the file. Caller must NOT free the returned
   data. */
void
ssh_ber_file_get_data(SshBERFile file,
                      unsigned char **data_ret,
                      size_t *data_len_ret);

/* Adds a record to a BER file. 'data' MUST contain a valid
   BER encoded blob. This function can fail, if there is not
   enough room in the file for the new record. */
SshBERFileStatus
ssh_ber_file_add_record(SshBERFile file,
                        const unsigned char *data,
                        size_t data_len,
                        SshBERFileRecord *record_ret);

/* Starts the enumeration of file records. */
void
ssh_ber_file_enum_start(SshBERFile file);

/* Enumerates the non-empty records in the file. Returns TRUE
   if this function was able to get the record from file. In
   this case a record is returned in 'record_ret'. This
   function will return FALSE if no more records found. */
Boolean
ssh_ber_file_enum_next(SshBERFile file,
                       SshBERFileRecord *record_ret);


/* Destroys the record in the file. The record is marked as
   empty (tag and class zero) in the file. The 'record' is
   invalid after this call and cannot be used anymore. */
void
ssh_ber_record_destroy(SshBERFileRecord record);

/* Returns the pointer to the beginning of the data of
   the BER record. The returned data must NOT be freed by
   the caller. */
void
ssh_ber_record_get_data(SshBERFileRecord record,
                        unsigned char **data_ret,
                        size_t *data_len_ret);

/* Resets the data of a BER record in the file. This function
   can fail if you try to set a bigger data to record that it
   contained earlier and there is not enough space in the file
   to contain the extra data. */
SshBERFileStatus
ssh_ber_record_set_data(SshBERFileRecord record,
                        const unsigned char *data,
                        size_t data_len);

#endif /* SSH_BER_FILE_H */
