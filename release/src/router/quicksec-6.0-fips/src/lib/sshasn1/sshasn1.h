/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Definitions for ASN.1 tree handling routines.

   Design of the ASN.1 parsing here uses a tree presentation mainly for
   simplifying reasons. One could easily implement so-called lber
   library which would not expand the binary ber to a tree form,
   however, then decoding might get more difficult. Our experience with
   this construction has shown that it works reasonably well. One could
   argue in favor of lber implementation, however, some constructions
   are not available in lber which are useful.

   One could, of course, build a real ASN.1 parser, but we hardly need that
   much ASN.1. Indeed, the parser would in many cases be a lot more
   complex and difficult to maintain. Yet, it would ease development in
   some cases.
*/

#ifndef ASN1_H
#define ASN1_H

#include "sshmp.h"

/* ASN.1 status type. */
typedef enum
{
  /* Returned if function/operation did what it was ment to do. */
  SSH_ASN1_STATUS_OK = 0,

  /* Partial success at decoding, probably nothing bad has happened. That
     is, most application should consider accepting these. Although,
     later we probably make this same as the SSH_ASN1_STATUS_OK. */
  SSH_ASN1_STATUS_OK_GARBAGE_AT_END,

  /* Partial success at decoding, however, at the inner structure, thus
     might infact be invalid for the use one tries the packet. Better to
     not to use if packets are of some value. */
  SSH_ASN1_STATUS_BAD_GARBAGE_AT_END,

  /* Function could not finish. */
  SSH_ASN1_STATUS_OPERATION_FAILED,

  /* Constructed type assumed, but primitive met. */
  SSH_ASN1_STATUS_CONSTRUCTED_ASSUMED,
  /* List was empty. */
  SSH_ASN1_STATUS_LIST_EMPTY,

  /* Format string misses closing parenthesis. That is invalid format. */
  SSH_ASN1_STATUS_MISSING_CLOSING_MARKER,
  /* Format string is in invalid format or internal error occurred. */
  SSH_ASN1_STATUS_FORMAT_STRING_TOO_SHORT,
  /* Command in format string is unknown (i.e. cipherish). */
  SSH_ASN1_STATUS_UNKNOWN_COMMAND,
  /* The format string ends at the position. */
  SSH_ASN1_STATUS_FORMAT_STRING_END,

  /* Given node is NULL when something else assumed. */
  SSH_ASN1_STATUS_NODE_NULL,
  SSH_ASN1_STATUS_ALL_NULL,

  /* Node has no child although operation implies otherwise. I.e. it should
     be obvious that this routine needs child nodes to be existent. */
  SSH_ASN1_STATUS_NO_CHILD,
  /* Node has no parent although operation implies otherwise. */
  SSH_ASN1_STATUS_NO_PARENT,

  /* BER encoding error. */
  SSH_ASN1_STATUS_BER_OPEN_FAILED,
  SSH_ASN1_STATUS_BER_STEP_FAILED,
  SSH_ASN1_STATUS_BER_CLOSE_FAILED,

  /* Error in decoding or encoding at BER level. */
  SSH_ASN1_STATUS_BER_DECODE_FAILED,
  SSH_ASN1_STATUS_BER_ENCODE_FAILED,

  /* SshBuffer too small, internal error. */
  SSH_ASN1_STATUS_BUFFER_OVERFLOW,
  SSH_ASN1_STATUS_BUFFER_TOO_SMALL,

  /* Searching succeeded in finding that searched nodes could
     not be located. This is an error only if such node should have been
     found, i.e. was found before. However, in most common case this
     return flag just shows that such a node/tree could not be found. */
  SSH_ASN1_STATUS_MATCH_NOT_FOUND,

  /* Returned if a choice statement in ssh_asn1_read_node/tree found that
     more than one child matches correctly. */
  SSH_ASN1_STATUS_CHOICE_TOO_MANY_MATCHES,

  /* This operation or command or type is not yet implemented in this
     revision. If operation or command or type is needed, then implementation
     should be considered. */
  SSH_ASN1_STATUS_NOT_YET_IMPLEMENTED,

  /* Generic error, if none of the above is applicable */
  SSH_ASN1_STATUS_ERROR
} SshAsn1Status;

/* Type of an ASN.1 encoding. */
typedef unsigned int SshAsn1Encoding;
#define SSH_ASN1_ENCODING_PRIMITIVE   0
#define SSH_ASN1_ENCODING_CONSTRUCTED 1


/* Definitions for universally defined tag numbers. */
#define SSH_ASN1_TAG_RESERVED_0              0
#define SSH_ASN1_TAG_BOOLEAN                 1
#define SSH_ASN1_TAG_INTEGER                 2
#define SSH_ASN1_TAG_BIT_STRING              3
#define SSH_ASN1_TAG_OCTET_STRING            4
#define SSH_ASN1_TAG_NULL                    5
#define SSH_ASN1_TAG_OID_TYPE                6
#define SSH_ASN1_TAG_ODE_TYPE                7
#define SSH_ASN1_TAG_ETI_TYPE                8
#define SSH_ASN1_TAG_REAL                    9
#define SSH_ASN1_TAG_ENUM                   10
#define SSH_ASN1_TAG_EMBEDDED               11
#define SSH_ASN1_TAG_UTF8_STRING            12
#define SSH_ASN1_TAG_RESERVED_1             13
#define SSH_ASN1_TAG_RESERVED_2             14
#define SSH_ASN1_TAG_RESERVED_3             15
#define SSH_ASN1_TAG_SEQUENCE               16
#define SSH_ASN1_TAG_SET                    17
#define SSH_ASN1_TAG_NUMERIC_STRING         18
#define SSH_ASN1_TAG_PRINTABLE_STRING       19
#define SSH_ASN1_TAG_TELETEX_STRING         20
#define SSH_ASN1_TAG_VIDEOTEX_STRING        21
#define SSH_ASN1_TAG_IA5_STRING             22
#define SSH_ASN1_TAG_UNIVERSAL_TIME         23
#define SSH_ASN1_TAG_GENERALIZED_TIME       24
#define SSH_ASN1_TAG_GRAPHIC_STRING         25
#define SSH_ASN1_TAG_VISIBLE_STRING         26
#define SSH_ASN1_TAG_GENERAL_STRING         27
#define SSH_ASN1_TAG_UNIVERSAL_STRING       28
#define SSH_ASN1_TAG_UNRESTRICTED_STRING    29
#define SSH_ASN1_TAG_BMP_STRING             30
#define SSH_ASN1_TAG_RESERVED_4             31

/* Context structure pointer for ASN.1 processing and internal memory
   management. */
typedef struct SshAsn1ContextRec *SshAsn1Context;

/* Parsed/constructed ASN.1 node. */
typedef struct SshAsn1NodeRec *SshAsn1Node;

/* Parsed ASN.1 tree object, used for moving in the ASN.1 tree. */
typedef struct SshAsn1TreeRec *SshAsn1Tree;

/* Note; these are used as flags so that
   flags = (SshAsn1Class & 0xff)|SshAsn1TaggingMode|SshAsn1LengthEncoding|
   some defintions between them. */
typedef enum
{
  SSH_ASN1_CLASS_UNIVERSAL    = 0,
  SSH_ASN1_CLASS_APPLICATION  = 1,
  SSH_ASN1_CLASS_CONTEXT      = 2,
  SSH_ASN1_CLASS_PRIVATE      = 3,
  SSH_ASN1_CLASS_MAX          = 4
} SshAsn1Class;


#define SSH_ASN1_TAGGED         (1 <<  8)
typedef enum
{
  SSH_ASN1_TAGGING_IMPLICIT   = (1 <<  9),
  SSH_ASN1_TAGGING_EXPLICIT   = (1 << 10)
} SshAsn1TaggingMode;

typedef enum
{
  SSH_ASN1_LENGTH_STAR        = (1 << 12),
  SSH_ASN1_LENGTH_DEFINITE    = (1 << 13),
  SSH_ASN1_LENGTH_INDEFINITE  = (1 << 14)
} SshAsn1LengthEncoding;

typedef SshUInt32 SshAsn1Tag;

/* Some BER. */

/* Time encoding. Because UTCTime and GeneralizeTime types need special
   handling we give this type which can be used for their encodings. */

typedef struct
{
  /**** first 32 bits ****/
  unsigned int local:1;

  unsigned int year:16;
  /* months range from 01 to 12 */
  unsigned int month:5;
  /* days range from 01 to 31 */
  unsigned int day:5;
  /* hours range from 00 to 23 */
  unsigned int hour:5;

  /**** second 32 bits ****/
  /* minutes range 00 to 59 */
  unsigned int minute:6;
  /* seconds range 00 to 59. */
  unsigned int second:6;
  /* Absolute value of the offset from GMT in hours and minutes. */
  unsigned int absolute_hours:5;
  unsigned int absolute_minutes:6;

  /* microseconds range 0 to 1000000. */
  unsigned int msecond;
} *SshBerTime, SshBerTimeStruct;

/* The BER time routines are given here to make the include file listings
   shorter. */

/* Compare two BER time contexts. Returns 0 if equal, -1 if b < a and 1
   if a > b. */
int ssh_ber_time_cmp(const SshBerTime a, const SshBerTime b);

/* Assign the time v to x. */
void ssh_ber_time_set(SshBerTime x, const SshBerTime v);

/* Add seconds to BER time. */
void ssh_ber_time_add_secs(SshBerTime x, unsigned long secs);

/* Get the BER time from UNIX time. */
void ssh_ber_time_set_from_unix_time(SshBerTime ber_time, SshTime unix_time);
/* Convert the BER time to UNIX time. The time in seconds since 1970 is
   returned. */
SshTime ssh_ber_time_get_unix_time(const SshBerTime ber_time);

/* Set the BER time structure to zero values. This indicates that no date/time
   has been set. It would be good practice to zero each and every BER time
   structure before you use it. However, sometimes this is not necessary.
   (For example, if you set the BER time with UNIX time etc.) */
void ssh_ber_time_zero(SshBerTime ber_time);

/* Check whether the BER time structure contains reasonable date/time
   values. (Basically whether it is zeroed or not using the above
   function.) */
Boolean ssh_ber_time_available(const SshBerTime ber_time);

/* Convert the BER time from string. The string may be in either of the
   following formats, both are equivalent.

   Write either

     "1999 Jan 27th, 20:08:30"

   or

     "1999/01/27/20:08:30"

   which ever suits your application better. The format allows multiple
   blanks, but not linefeeds etc. */
Boolean ssh_ber_time_set_from_string(SshBerTime ber_time, const char *str);
/* Using the 'prettier' format from above convert the BER time to
   string. */
void ssh_ber_time_to_string(const SshBerTime ber_time, char **str);

int ssh_ber_time_render(unsigned char *buf, int buf_size,
                        int precision, void *datum);

/* Convert only date part of given time to a string. */
char *ssh_str_bertime_to_date_str(const SshBerTime ber_time);

/* ASN.1 */

/* Allocates an ASN.1 processing context.  The context is used for memory
   allocation and similar purposes.  All parsing and generation happens with
   an SshAsn1Context structure.  The same context can be used for several
   parsing/generation operations; however, its size may increase as more
   operations are performed.  Creating and freeing contexts is relatively
   cheap; it is recommended that the context be freed and a new context be
   created whenever convenient. */
SshAsn1Context ssh_asn1_init(void);

/* Limitations for BER decoder. These can be overwritten with call to
   ssh_asn1_set_limits() for each Asn.1 decoder instance.
   - Maximum stack depth the recursive BER decoder can use. The decoder
     will use approximately 25 * (sizeof(void*)) bytes of stack for each
     level.
   - Maximum input length for encoded BER in bytes. */
#define SSH_BER_DECODE_STACK_DEPTH                 (32)
#define SSH_BER_DECODE_MAX_INPUT_SIZE (4 * (1024*1024))

/* Modifies built-in resource usage limitations for the module. Value
   zero does not alter setting. */
void ssh_asn1_set_limits(SshAsn1Context context,
                         size_t max_input_length,
                         size_t max_input_nesting);

/* Frees an asn1 processing context. */
void ssh_asn1_free(SshAsn1Context ac);

/* Given a binary format ASN.1 structure (in buf) parses it using BER
   encoding standard. Returns the parsed tree. Tree remains
   valid until the context is freed (it is legal to call this multiple
   times with the same context). Returns an error if could not parse. */

SshAsn1Status ssh_asn1_decode(SshAsn1Context context,
                              const unsigned char *buf, size_t len,
                              SshAsn1Tree *tree);

/* Same as above but creates only a node, not a full tree. This is
   basically the same. And usually using this interface one saves few
   lines of code. */
SshAsn1Status ssh_asn1_decode_node(SshAsn1Context context,
                                   const unsigned char *buf, size_t len,
                                   SshAsn1Node *node);

/* With DER encoding of an SET or SET-OF types it is important to sort
   them.  This must be done manually (using this function), no
   automatic method for this is available. The node first should be
   the first in the level where sorting should be done. I.e. the first
   child of the SET or SET-OF type. */

SshAsn1Node ssh_asn1_sort_list(SshAsn1Context context,
                               SshAsn1Node first);

/* Given a ASN.1 tree it will be encoded appropriately. The BER encoded
   binary format is placed in nodes.

   Reading the BER encoded data is possible currently with

   ssh_asn1_get_node - to get the encoded children / data from one node
   ssh_asn1_get_data - to get the encoded tree from tree context */

/* Tree context shall hold the full tree BER encoded in a separate
   pointer. */

SshAsn1Status ssh_asn1_encode(SshAsn1Context context,
                              SshAsn1Tree tree);

/* The node shall contain it's children and itself BER encoded. */

SshAsn1Status ssh_asn1_encode_node(SshAsn1Context context,
                                   SshAsn1Node node);

/* Create a tree. Function allows one to write the tree structure to the
   'format' string and give the contents data as input.

   When decoding each routine returing c string returns xmemdup'ed copy of the
   object (== strings are null terminated).

   The string 'format' has following format:

   ()
     empty list

   (command (options)
     (child)
     (child)
     ...
     (child))

    child
      optional command
      implies constructed type

    options
      upacei* tag-number

      one of

        u    UNIVERSAL   class    (default if options empty)
        p    PRIVATE     class
        a    APPLICATION class
        c    CONTEXT     class    (default if options present)

      any of

        e    EXPLICIT    tagging  (IMPLICIT default)
        i    INDEFINITE  encoding (DEFINITE default)

      and wildcard (star-operator)
        *
             Used in reading. Means that any tagged version is passed as
             the command.

        Star variables

        l*   both indefinite and definite lengths are allowed.

      class, tagging/encoding and star must be in single string without
      whitespaces.

      tag-number
        any positive integer < 2^32

     command

       boolean
             C type
               Boolean

       integer
             C type
               SshMPInt

       integer-short
             C type
               SshWord


       bit-string
             C type pair
               unsigned char *
               size_t
             Encoded msb first. Length is given in bits.

       enum
             C type
               SshMPInt

       enum-short
             C type
               SshWord

       octet-string
             C type pair
               unsigned char *
               size_t

       null
             No C type

       object-identifier
             C type
               char *

       utc-time
       generalized-time
             C type
               SshBerTime

       ia5-string
       printable-string
       visible-string
       teletex-string
       graphic-string
       ... etc.
            C type
              unsigned char *
              size_t

       ... other types to be added as needed ...

       sequence
             constructed
             No C type
             There is no separate sequence-of type.

       set
             constructed
             No C type
             There is no separete set-of type.


     special forms:

       any
             anything
             SshAsn1Node

     constructed
       might have child(s)
       opposite to primitive

     primitive
       no child
       contains data

     example:

       Assume we have

       SshMPInteger integer_1;
       SshMPInteger integer_2;

       initialized. Then

       status =
         ssh_asn1_create_tree(context, &tree,
                              "(sequence (a 10) (integer (1)) (integer (2)))",
                              integer_1,
                              integer_2);

       creates the tree corresponding to

       tree = [APPLICATION 10] SEQUENCE {
            integer_1 [1]INTEGER,
            integer_2 [2]INTEGER }.


   */

/* Create a node using given format and list of primitive data
   elements.  Nodes can be combined to a tree context later. Format is
   a C-string described above. */

SshAsn1Status ssh_asn1_create_node(SshAsn1Context context,
                                   SshAsn1Node *node,
                                   const char *format, ...);

/* Create a tree (context) using given format and list of primitive
   data elements. Format is a C-string described above. */

SshAsn1Status ssh_asn1_create_tree(SshAsn1Context context,
                                   SshAsn1Tree *tree,
                                   const char *format, ...);

/* Get value(s) from a node (which might have subnodes etc.). Format
   string is in the above format. Given data is ssh_xmalloc'ed, or
   assumed to be pre-alloced/initialized, and should be freed with
   ssh_xfree, or any appropriate freeing/clearing procedure. Output
   data can be altered.

   Arguments are given as pointers. Arguments should be exactly in the
   correct expected format or results are undefined.

   We have also two additional specials forms at our disposal.

     choice
            children of which one should match the underlying type
            unsigned int *
              (and as needed for each child in case of match)

     optional
            children of which one might find
            Boolean *
              (and as needed for children in case of match)

   It is also nice to know that the search procedure for tagged values
   is throughout the current list. Also in sets all values are always
   searched throughout the current list.

   The special form any is only matched if it is tagged. Special forms
   choice and optional do not have any options part. Also they are not
   guaranteed to work with very complex expressions. It is adviced
   that tagged any should be used in those cases with choice and
   optional.

   However, see the code which uses these for more examples and
   possibly discussion of the subject.

   Current implementation ignores the context argument.  */

SshAsn1Status ssh_asn1_read_tree(SshAsn1Context context,
                                 SshAsn1Tree tree,
                                 const char *format, ...);

SshAsn1Status ssh_asn1_read_node(SshAsn1Context context,
                                 SshAsn1Node node,
                                 const char *format, ...);

/*************** Movement 'round the ASN.1 tree ****************/

/* Create new tree (containing null values). These tree's are meant only
   to be used when moving or maybe testing the system. The root node
   should be set to NULL (if not specifically otherwise useful which might
   be the case for beta versions).

   Root node tells the first node of the tree, and the current node tells
   the place where you are in the tree currently. One could use this
   function to build a tree from a node (with possible children). */

SshAsn1Tree ssh_asn1_init_tree(SshAsn1Context context, SshAsn1Node root,
                               SshAsn1Node current);

/* Copy one tree to another (i.e. copying basically just the root and current
   pointers). Useful when moving down and need to return fast to an another
   node. The actual data and nodes are same for both trees, i.e. changes to
   another will affect the another. */

void ssh_asn1_copy_tree(SshAsn1Tree dest, SshAsn1Tree src);

/* Reset the tree by setting the current Node to be equal to the Root node.
   This operation could be useful i.e. in traversing the tree in
   subroutines etc. */

void ssh_asn1_reset_tree(SshAsn1Tree tree);

#ifdef DEBUG_LIGHT
/* Print out the tree if debug version. */
void ssh_asn1_print_tree(SshAsn1Tree tree);
void ssh_asn1_print_node(SshAsn1Node node);
#else
#define ssh_asn1_print_tree(_t) do { } while (0)
#define ssh_asn1_print_node(_n) do { } while (0)
#endif

/* Advance over n nodes in the tree. Returns the steps actually moved. The
   current node is always valid tree node (i.e. one cannot run over the
   edge). */

unsigned int ssh_asn1_move_forward(SshAsn1Tree tree, unsigned int n);

/* Step n nodes backward in the tree. Returns the steps actually moved. The
   current node is always valid tree node. */

unsigned int ssh_asn1_move_backward(SshAsn1Tree tree, unsigned int n);

/* Move one level down if possible. Return SSH_ASN1_STATUS_OK if successful. */

SshAsn1Status ssh_asn1_move_down(SshAsn1Tree tree);

/* Move one level up if possible. Return SSH_ASN1_STATUS_OK if successful. */

SshAsn1Status ssh_asn1_move_up(SshAsn1Tree tree);

/* Get the current node. This routine is not intented to be used for reading
   node contents, but for simple way of passing nodes around. I.e.
   one gets the pointer of the current node. */

SshAsn1Node ssh_asn1_get_current(SshAsn1Tree tree);

/* Get the root node. */

SshAsn1Node ssh_asn1_get_root(SshAsn1Tree tree);

/* Traversal of the node given. These are usually the simplest ways of moving
   around the tree. For example, with sequence-of and set-of lists one
   can uses these in simply loop to go through the list. */

SshAsn1Node ssh_asn1_node_next(SshAsn1Node node);
SshAsn1Node ssh_asn1_node_prev(SshAsn1Node node);
SshAsn1Node ssh_asn1_node_parent(SshAsn1Node node);
SshAsn1Node ssh_asn1_node_child(SshAsn1Node node);

/*********************** Reading data from tree **********************/

/* Get data from the tree. This is the function which should be used for
   reading the encoded data from the tree. Returns ssh_xmalloc'ed data, which
   should be free with ssh_xmalloc. Cannot fail although the tree might not
   contain any valid data without actually encoding it using
   ssh_asn1_encode routines. */

void ssh_asn1_get_data(SshAsn1Tree tree, unsigned char **data, size_t *length);

/* Returns the amount of space needed for the encodings of this tree. */
size_t ssh_asn1_bytes_used(SshAsn1Tree tree);

/* Read the data of a node. The output in data is ssh_xmalloc'ed and thus
   must be freed with ssh_xfree. */

SshAsn1Status ssh_asn1_node_get_data(SshAsn1Node node,
                                     unsigned char **data,
                                     size_t *data_len);

/************* Insertion and deletion operations *********************/

/* Equal to the insert_node version, but assumes that also the following
   nodes (i.e. next nodes from node) should be inserted. Removes the
   list from possible list it was taken. */

SshAsn1Status ssh_asn1_insert_list(SshAsn1Node before,
                                   SshAsn1Node after, SshAsn1Node node);

SshAsn1Node ssh_asn1_add_list(SshAsn1Node list, SshAsn1Node node);

/* Remove a node (from the tree). The node is still valid, i.e. it is not
   deleted from memory. So it is possible to use this particular node for
   other operations. */

SshAsn1Status ssh_asn1_remove_node(SshAsn1Node node);

/* Insert a child if base node is constructed. This should ease the
   buiding of large trees. Inserts the node (or nodes) as the last in the
   (possible) list from base child node. */

SshAsn1Status ssh_asn1_insert_subnode(SshAsn1Node base, SshAsn1Node node);

/* Notice changes on tagging. This functions should be called in case
   a BER blob has been decoded to node, and this node is later put
   into a new node, with different tagging. */

void ssh_asn1_flag_changes(SshAsn1Node node);

/****** Direct manipulation of nodes (i.e. low level routines) *********/

/* These should not be used if the same effect can be performed with
   any of the above routines. These are here as a backup for special, and
   rare cases, which are hardly worth to implement. However, if any
   operation needs to be used more than once it might get its special
   form as above has been mentioned. */

/* Allocate and initialize new node. Allocated from context thus need not be
   freed specificly. If the node will be inserted into a tree the context
   should be same as the trees, otherwise undefined problems could arise
   (but need not). */

SshAsn1Node ssh_asn1_node_init(SshAsn1Context context);

/* Get the space taken by the node when linearized. This function
   must be called after encoding. The functions returns the tag size
   for constructed and tag size + date length for primitive. */
int ssh_asn1_node_size(SshAsn1Node node);

/* Get information contained by the node. Every pointer can be null and then
   that field is just ignored. The data outputed doesn't contain tag
   information. */

SshAsn1Status ssh_asn1_node_get(SshAsn1Node node,
                                SshAsn1Class *asn1_class,
                                SshAsn1Encoding *encoding,
                                SshAsn1Tag *tag_number,
                                SshAsn1LengthEncoding *length_encoding,
                                size_t *length,
                                unsigned char **data);

/* Set up a node manually. This operation is the most fundamental and might
   break up things. Use only if neccessary.
   DEPRECATED: this function might dissappear in future revisions. */

SshAsn1Status ssh_asn1_node_put(SshAsn1Context context,
                                SshAsn1Node node,
                                SshAsn1Class asn1_class,
                                SshAsn1Encoding encoding,
                                SshAsn1Tag tag_number,
                                SshAsn1LengthEncoding length_encoding,
                                size_t length,
                                unsigned char *data);

/* Copy the internal node level information to the other node.
   This may be usefull when using the same kind of SshAsn1Node in different
   places. Using the same node would mess up next and child pointers.

   WARNING: Use only with single node structures (no lists) because
   next/prev/parent pointers are not copied.

   WARNING: Do not use if you going to change the node or the childs of the
   node, because the node contains pointers that point to objects that are
   pointed by the pointers in the old node also. Changing the node will
   change the old node. */

SshAsn1Status ssh_asn1_copy_node(SshAsn1Context context,
                                 SshAsn1Node *node_to,
                                 SshAsn1Node node_from);

/* Convert Asn1 status code to string */
const char *ssh_asn1_error_string(SshAsn1Status status);



#endif /* ASN1_H */
