/**
   @copyright
   Copyright (c) 2002 - 2014, INSIDE Secure Oy. All rights reserved.
*/

/**
   Internal header file for the XML library.
*/

#ifndef SSHXML_INTERNAL_H
#define SSHXML_INTERNAL_H

#include "sshxml.h"
#include "sshxml_dom.h"
#include "sshfsm.h"
#include "sshdatastream.h"
#include "sshadt_bag.h"
#include "sshutf8.h"
#include "sshbuffer.h"
#include "sshobstack.h"

/* ************************ Types and definitions ***************************/

/* Predicates for character types. */

#define SSH_XML_IS_CHAR(ch)                     \
((ch) == 0x9 || (ch) == 0xa || (ch) == 0xd      \
 || (0x00020 <= (ch) && (ch) <= 0x00d7ff)       \
 || (0xe0000 <= (ch) && (ch) <= 0x0ffffd)       \
 || (0x10000 <= (ch) && (ch) <= 0x10ffff))

#define SSH_XML_IS_SPACE(ch)    \
((ch) == 0x20 || (ch) == 0x9 || (ch) == 0xd || (ch) == 0xa)

#define SSH_XML_CHAR_IN_ARRAY(ch, array)        \
ssh_xml_char_in_array((ch), array, array ## _num_items)

#define SSH_XML_IS_BASE_CHAR(ch)        \
SSH_XML_CHAR_IN_ARRAY((ch), ssh_xml_base_char)

#define SSH_XML_IS_IDEOGRAPHIC(ch)      \
SSH_XML_CHAR_IN_ARRAY((ch), ssh_xml_ideographic)

#define SSH_XML_IS_COMBINING_CHAR(ch)   \
SSH_XML_CHAR_IN_ARRAY((ch), ssh_xml_combining_char)

#define SSH_XML_IS_DIGIT(ch)    \
SSH_XML_CHAR_IN_ARRAY((ch), ssh_xml_digit)

#define SSH_XML_IS_EXTENDER(ch) \
SSH_XML_CHAR_IN_ARRAY((ch), ssh_xml_extender)

#define SSH_XML_IS_LETTER(ch)   \
(SSH_XML_IS_BASE_CHAR(ch) || SSH_XML_IS_IDEOGRAPHIC(ch))

#define SSH_XML_IS_NAME_CHAR(ch)                                \
(SSH_XML_IS_LETTER(ch) || SSH_XML_IS_DIGIT(ch)                  \
 || (ch) == '.' || (ch) == '-' || (ch) == '_' || (ch) == ':'    \
 || SSH_XML_IS_COMBINING_CHAR(ch) || SSH_XML_IS_EXTENDER(ch))

#define SSH_XML_IS_NAME_FIRST_CHAR(ch)  \
(SSH_XML_IS_LETTER(ch) || (ch) == '_' || (ch) == ':')

#define SSH_XML_IS_PUBID_CHAR(ch)                               \
((ch) == 0x20 || (ch) == 0xd || (ch) == 0xa                     \
 || ('a' <= (ch) && (ch) <= 'z')                                \
 || ('A' <= (ch) && (ch) <= 'Z')                                \
 || ('0' <= (ch) && (ch) <= '9')                                \
 || (ch) == '-' || (ch) == '-' || (ch) == '\'' || (ch) == '('   \
 || (ch) == ')' || (ch) == '+' || (ch) == ',' || (ch) == '.'    \
 || (ch) == '/' || (ch) == ':' || (ch) == '=' || (ch) == '?'    \
 || (ch) == ';' || (ch) == '!' || (ch) == '*' || (ch) == '#'    \
 || (ch) == '@' || (ch) == '$' || (ch) == '_' || (ch) == '%')

/* A character. */
typedef SshUInt32 SshXmlChar;

/* A character range. */
struct SshXmlCharRangeRec
{
  SshUInt16 min;
  SshUInt16 max;
};

typedef struct SshXmlCharRangeRec SshXmlCharRangeStruct;
typedef struct SshXmlCharRangeRec *SshXmlCharRange;

/* A pre-defined entity. */
struct SshXmlPreDefinedEntityRec
{
  char *name;
  char *value;
};

typedef struct SshXmlPreDefinedEntityRec SshXmlPreDefinedEntityStruct;
typedef struct SshXmlPreDefinedEntityRec *SshXmlPreDefinedEntity;

/* A header structure for hash table items which are hashed by their
   name. */
struct SshXmlNameHashHeaderRec
{
  /* ADT header. */
  SshADTHeaderStruct adt_header;

  /* The name. */
  unsigned char *name;
  size_t name_len;
};

typedef struct SshXmlNameHashHeaderRec SshXmlNameHashHeaderStruct;
typedef struct SshXmlNameHashHeaderRec *SshXmlNameHashHeader;

/* An attribute. */
struct SshXmlAttributeRec
{
  /* Name hash header. */
  SshXmlNameHashHeaderStruct header;

   /* Attribute value. */
  unsigned char *value;
  size_t value_len;
};

typedef struct SshXmlAttributeRec SshXmlAttributeStruct;
typedef struct SshXmlAttributeRec *SshXmlAttribute;

/* An entity. */
struct SshXmlEntityRec
{
  /* Name hash header. */
  SshXmlNameHashHeaderStruct header;

  /* Flags. */
  unsigned int predefined : 1;  /* Predefined entity. */
  unsigned int general : 1;     /* General entity (otherwise parameter). */
  unsigned int internal : 1;    /* Internal entity. */
  unsigned int from_dtd : 1;    /* Defined from an external DTD. */

  /* The name of the input stream that defined the entity. */
  char *where_defined;

  /* The value of the entity.  The flag `internal' selects the union
     field. */
  union
  {
    /* An internal entity value. */
    struct
    {
      unsigned char *data;
      size_t data_len;
    } internal;

    /* An external entity value. */
    struct
    {
      unsigned char *pubid;
      size_t pubid_len;
      unsigned char *sysid;
      size_t sysid_len;
      unsigned char *ndata;
      size_t ndata_len;
    } external;
  } value;
};

typedef struct SshXmlEntityRec SshXmlEntityStruct;
typedef struct SshXmlEntityRec *SshXmlEntity;

/* A namespace declaration. */
struct SshXmlNamespaceRec
{
  /* Link field. */
  struct SshXmlNamespaceRec *next;

  /* The assigned prefix. */
  unsigned char *prefix;
  size_t prefix_len;

  /* The declared namespace URI. */
  unsigned char *uri;
};

typedef struct SshXmlNamespaceRec SshXmlNamespaceStruct;
typedef struct SshXmlNamespaceRec *SshXmlNamespace;

/* An element in the syntax tree. */
struct SshXmlElementRec
{
  /* Pointer to the parent. */
  struct SshXmlElementRec *next;

  /* Flags. */
  unsigned int empty : 1;       /* An empty element. */

  /* The name of the element. */
  unsigned char *name;
  size_t name_len;

  /* Namespace declarations. */
  unsigned char *default_namespace;
  SshXmlNamespace namespaces;

  /* The attributes of the element. */
  SshADTContainer attributes;
};

typedef struct SshXmlElementRec SshXmlElementStruct;
typedef struct SshXmlElementRec *SshXmlElement;

/* A DFA. */
typedef struct SshXmlDfaRec *SshXmlDfa;

/* An element declaration.  This is used by verifier to store DTD's
   element declarations. */
struct SshXmlElementDeclRec
{
  /* Name hash header. */
  SshXmlNameHashHeaderStruct header;

  /* Flags. */
  unsigned int declared : 1;    /* Element declared. */

  /* Content specification. */
  SshXmlElementContentSpec content_spec;

  /* DFA implementing the expression content specification. */
  SshXmlDfa dfa;

  /* The attribute definitions of the element. */
  SshADTContainer attributes;
};

typedef struct SshXmlElementDeclRec SshXmlElementDeclStruct;
typedef struct SshXmlElementDeclRec *SshXmlElementDecl;

/* Attribute types. */
typedef enum
{
  SSH_XML_ATTRIBUTE_TYPE_CDATA,
  SSH_XML_ATTRIBUTE_TYPE_ID,
  SSH_XML_ATTRIBUTE_TYPE_IDREF,
  SSH_XML_ATTRIBUTE_TYPE_IDREFS,
  SSH_XML_ATTRIBUTE_TYPE_ENTITY,
  SSH_XML_ATTRIBUTE_TYPE_ENTITIES,
  SSH_XML_ATTRIBUTE_TYPE_NMTOKEN,
  SSH_XML_ATTRIBUTE_TYPE_NMTOKENS,
  SSH_XML_ATTRIBUTE_TYPE_NOTATION,
  SSH_XML_ATTRIBUTE_TYPE_ENUMERATION
} SshXmlAttributeType;

/* Attribute default type. */
typedef enum
{
  SSH_XML_ATTRIBUTE_DEFAULT_TYPE_REQUIRED,
  SSH_XML_ATTRIBUTE_DEFAULT_TYPE_IMPLIED,
  SSH_XML_ATTRIBUTE_DEFAULT_TYPE_FIXED,
  SSH_XML_ATTRIBUTE_DEFAULT_TYPE_DEFAULT
} SshXmlAttributeDefaultType;

/* An attribute definition. */
struct SshXmlAttributeDefinitionRec
{
  /* Name hash header. */
  SshXmlNameHashHeaderStruct header;

  /* Flags. */
  unsigned int enums_interned : 1; /* Enum values interned. */

  /* The type of the attribute. */
  SshXmlAttributeType type;

  /* Values for enumeration and notation types. */
  SshUInt32 num_enums;
  unsigned char **enums;
  size_t *enum_lens;

  /* The default declaration type. */
  SshXmlAttributeDefaultType default_type;

  /* An optional default value. */
  unsigned char *value;
  size_t value_len;
};

typedef struct SshXmlAttributeDefinitionRec SshXmlAttributeDefinitionStruct;
typedef struct SshXmlAttributeDefinitionRec *SshXmlAttributeDefinition;

/* An ID.  This is used in the verifier to identify an attribute of
   type ID. */
struct SshXmlIDRec
{
  /* Name hash header. */
  SshXmlNameHashHeaderStruct header;

  /* Flags. */
  unsigned int defined : 1;     /* Is the ID defined. */

  /* The first location from which an undefined ID was referenced. */
  char *name;
  SshUInt32 line;
  SshUInt32 column;
};

typedef struct SshXmlIDRec SshXmlIDStruct;
typedef struct SshXmlIDRec *SshXmlID;

/* A lexer stack frame. */
struct SshXmlLexerRec
{
  /* Pointer to the next (lower) stack frame. */
  struct SshXmlLexerRec *next;

  /* Data of the current token being constructed. */
  unsigned char *data;
  size_t data_allocated;
  size_t data_len;

  /* State from which a sub-state machine continues after it is
     complete.  The continue state is taken only in success cases.  If
     the sub-state machine fails, it reports its error to the user and
     the control moves to the `ssh_xml_st_error' state. */
  SshFSMStepCB continue_state;

  /* Literal end character. */
  SshXmlChar literal_endch;
};

typedef struct SshXmlLexerRec SshXmlLexerStruct;
typedef struct SshXmlLexerRec *SshXmlLexer;

/* Input encodings. */
typedef enum
{
  SSH_XML_INPUT_ENC_UNKNOWN,
  SSH_XML_INPUT_ENC_UTF_8,
  SSH_XML_INPUT_ENC_UTF_16_BE,
  SSH_XML_INPUT_ENC_UTF_16_LE,
  SSH_XML_INPUT_ENC_UCS_4_BE,
  SSH_XML_INPUT_ENC_UCS_4_LE,
  SSH_XML_INPUT_ENC_UCS_4_2143,
  SSH_XML_INPUT_ENC_UCS_4_3412,
  SSH_XML_INPUT_ENC_ISO_8859_1,
  SSH_XML_INPUT_ENC_US_ASCII
} SshXmlInputEncoding;

/* An input stream. */
struct SshXmlInputRec
{
  /* Pointer to the next input stream. */
  struct SshXmlInputRec *next;

  /* The input stream. */
  SshStream stream;

  /* The name of the stream. */
  char *name;

  /* Flags. */
  unsigned int ungetch_valid : 1;    /* Is the `ungetch' valid? */
  unsigned int general_entity : 1;   /* Value of a general entity. */
  unsigned int parameter_entity : 1; /* Value of a parameter entity. */
  unsigned int from_literal : 1;     /* Frame was added from a literal. */

  /* Character that was unget. */
  SshXmlChar ungetch;

  /* Encoding of this input. */
  SshXmlInputEncoding encoding;

  /* Destructor callback for the input stream. */
  SshXmlDestructorCB destructor_cb;
  void *destructor_cb_context;

  /* Location in the current input stream. */
  SshUInt32 line;
  SshUInt32 column;

  /* Buffer holding data read from the stream. */
  unsigned char buf[1024];
  size_t data_in_buf;
  size_t bufpos;
};

typedef struct SshXmlInputRec SshXmlInputStruct;
typedef struct SshXmlInputRec *SshXmlInput;

/* The type of the literal being parsed. */
typedef enum
{
  SSH_XML_LITERAL_ENTITY_VALUE,
  SSH_XML_LITERAL_ATTRIBUTE_VALUE,
  SSH_XML_LITERAL_SYSTEM_LITERAL,
  SSH_XML_LITERAL_PUBID_LITERAL
} SshXmlLiteralType;

/* State of the XMLDecl parsing. */
typedef enum
{
  SSH_XML_DECL_VERSION,
  SSH_XML_DECL_ENCODING,
  SSH_XML_DECL_SDDECL,
  SSH_XML_DECL_END
} SshXmlDeclState;

/* An XML parser. */
struct SshXmlParserRec
{
  /* Parameters for the parser. */
  SshXmlParamsStruct params;

  /* Flags. */
  unsigned int standalone : 1;     /* Is the XML document standalone? */
  unsigned int dtd : 1;            /* Parsing DTD. */
  unsigned int doctype_dtd : 1;    /* Parsing embedded DOCTYPE DTD. */
  unsigned int in_comment : 1;     /* Parsing comment. */
  unsigned int in_literal : 1;     /* Parsing literal. */
  unsigned int in_ignore : 1;      /* Parsing IGNORE section. */
  unsigned int in_enum : 1;        /* Parsing list of enum values. */
  unsigned int general_entity : 1; /* General entity (else parameter). */
  unsigned int ungetch_valid : 1;  /* Is the `ungetch' valid? */
  unsigned int blocked : 1;        /* Waiting for an external callback. */
  unsigned int at_eof : 1;         /* Input is at EOF. */
  unsigned int cdata_wspace : 1;   /* All CDATA is whitespace. */
  unsigned int colon_seen : 1;     /* Is the `:' character seen in name. */
  unsigned int peref_flag : 1;     /* Sync/async flag for PERef resolving. */
  unsigned int name_nmtoken : 1;   /* Is name Nmtoken or Name? */
  unsigned int extid_public : 1;   /* ExternalID is PUBLIC (SYSTEM). */
  unsigned int extid_notation : 1; /* Notation type ExternalID. */
  unsigned int had_whitespace : 1; /* Optional whitespace was non-empty. */
  unsigned int end_document : 1;   /* Is the End Document already notified. */

  /* Depth of the input stack. */
  SshUInt8 input_stack_depth;

  /* Pointer to the top of the lexer stack. */
  SshXmlLexer lexer;

  /* Pointer to the top of the input stream stack. */
  SshXmlInput input;

  /* Character conversion module for converting internal UNICODE
     strings into UTF-8 when they are shown for user. */
  SshChrConv output_conv;

  /* Supporting modules for the input encoding. */
  SshChrConv chr_conv;

  /* Character that was unget. */
  SshXmlChar ungetch;

  /* State of the XMLDecl parsing. */
  SshXmlDeclState xmldecl_state;

  /* The type of the literal being parsed. */
  SshXmlLiteralType literal_type;

  /* The PEReference name currently being collected. */
  SshXmlLexer pereference;

  /* The current parse tree. */
  SshXmlElement parse_tree;

  /* Interned names. */
  SshADTContainer interned_names;

  /* Entities. */
  SshADTContainer general_entities;
  SshADTContainer parameter_entities;

  /* The current attribute being read. */
  SshXmlAttribute current_attribute;

  /* The current entity begin read. */
  SshXmlEntity current_entity;

  /* The current attribute definition being parsed. */
  SshADTContainer attribute_definitions;
  SshXmlAttributeDefinition current_attdef;
  SshXmlAttributeType current_attdef_type;

  /* Result callback for the current parsing operation. */
  SshXmlResultCB result_cb;
  void *result_cb_context;

  /* Result of the parser operation. */
  SshXmlResult parse_result;

  /* A timeout that calls user's `result_cb'. */
  SshTimeoutStruct result_cb_timeout;

  /* Operation handle for the parse operation. */
  SshOperationHandleStruct parse_handle;
  Boolean parse_handle_aborted;

  /* Operation handle for the pending handler callback. */
  SshOperationHandle callback_handle;

  /* Handlers. */
  void *handler_context;
  SshXmlContentHandlerStruct content_handler;
  SshXmlErrorHandlerStruct error_handler;
  SshXmlDtdHandlerStruct dtd_handler;
  SshXmlEntityCB entity_resolver;
  SshXmlParseDoneCB parse_done_cb;

  /* Buffer for comment termination handling. */
  unsigned char comment_end[3];
  size_t comment_end_len;

  /* Nesting count for IGNORE sections. */
  SshUInt32 ignore_nesting_count;

  /* Nesting count for INCLUDE sections. */
  SshUInt32 include_nesting_count;

  /* Temporary data blocks used in various parsing tasks. */
  unsigned char *data1;
  size_t data1_len;
  unsigned char *data2;
  size_t data2_len;
  unsigned char *data3;
  size_t data3_len;

  /* The number of open parenthesis in content expression parsing. */
  SshUInt32 paren_level;

  /* An FSM instance. */
  SshFSMStruct fsm;

  /* Condition variable for I/O synchronization. */
  SshFSMConditionStruct io_cond;

  /* A thread controlling the parsing. */
  SshFSMThreadStruct thread;
};

typedef struct SshXmlParserRec SshXmlParserStruct;


/* XML verifier definitions. */

/* Syntax tree item for XML verifier. */
struct SshXmlVerifierElementRec
{
  /* Pointer to the parent. */
  struct SshXmlVerifierElementRec *next;

  /* The declaration of the element. */
  SshXmlElementDecl decl;

  /* For expression type content data, this is the current state in
     the DFA verifying the content specification. */
  SshUInt16 dfa_state;
};

typedef struct SshXmlVerifierElementRec SshXmlVerifierElementStruct;
typedef struct SshXmlVerifierElementRec *SshXmlVerifierElement;

/* An XML verifier. */
struct SshXmlVerifierRec
{
  /* Parameters. */
  SshXmlVerifierParamsStruct params;

  /* Flags. */
  unsigned int dtd : 1;                  /* Parsing DTD file. */
  unsigned int dfa_ungetch_valid : 1;    /* DFA's ungetch valid. */
  unsigned int dfa_ungettoken_valid : 1; /* DFA's unget token valid. */

  /* The XML parser for which this verifier is configured. */
  SshXmlParser parser;

  /* The intercepted next-level handlers. */
  void *handler_context;
  SshXmlContentHandlerStruct content_handler;
  SshXmlErrorHandlerStruct error_handler;
  SshXmlDtdHandlerStruct dtd_handler;
  SshXmlParseDoneCB parse_done_cb;
  SshXmlEntityCB entity_resolver;

  /* DTD callback. */
  SshXmlVerifierDtdCB dtd_callback;
  void *dtd_callback_context;

  /* Result callback for a pending operation from our `parser'. */
  SshXmlResultCB result_cb;
  void *result_cb_context;

  /* An XML parser for parsing document's DTD. */
  SshXmlParser dtd_parser;

  /* Name of the current DTD stream. */
  char *dtd_name;

  /* Destructor for the DTD stream. */
  SshXmlDestructorCB dtd_destructor;
  void *dtd_destructor_context;

  /* DTD parsing. */

  /* An operation handle the verifier returns to the XML parser for an
     external DTD subset parsing. */
  SshOperationHandleStruct dtd_parse_handle;
  Boolean dtd_parse_handle_registered;
  Boolean dtd_parse_handle_aborted;

  /* An operation handle for a pending external DTD subset parsing
     operation.  This is used to store both the operation handle of
     the DTD callback and the handle of the DTD parsing operation. */
  SshOperationHandle handle;

  /* Syntax tree. */
  SshXmlVerifierElement syntax_tree;

  /* The name of the root element (from DOCTYPE).  If this is set, it
     also means that we must verify the XML content to the specified
     DTD. */
  unsigned char *root_element;

  /* Entities. */
  SshADTContainer general_entities;
  SshADTContainer parameter_entities;

  /* Elements. */
  SshADTContainer elements;

  /* Known IDs. */
  SshADTContainer ids;

  /* Obstack for memory mangement. */
  SshObStackContext obstack;

  /* DFA construction. */
  struct
  {
    /* Conversion routine for the content spec UTF-8 to UNICODE
       conversion.  This is valid as long as the verifier object is
       valid. */
    SshChrConv input_conv;

    /* The input string. */
    unsigned char *input;
    size_t input_len;
    size_t input_pos;

    /* Start offset of the current character. */
    size_t char_start;

    /* The unget character. */
    SshXmlChar ungetch;

    /* The last token passed to the caller.  This is also the unget
       token if the `dfa_unget_token' is set. */
    SshUInt32 last_token;
    unsigned char *last_name;

    /* The number of nodes in the syntax tree. */
    SshUInt32 num_nodes;

    /* The possible error code from the DFA construction. */
    SshXmlResult error;
  } dfa;
};

typedef struct SshXmlVerifierRec SshXmlVerifierStruct;


/* DOM definitions. */

/* A DOM node. */
struct SshXmlDomNodeRec
{
  /* Pointers for the list of children of our parent. */
  SshXmlDomNode next;
  SshXmlDomNode prev;

  /* Parent node. */
  SshXmlDomNode parent;

  /* The type of the node. */
  SshXmlDomNodeType type;

  /* Value. */
  union
  {
    struct
    {
      /* The name of the element. */
      const unsigned char *name;
      size_t name_len;

      /* Attributes and the parser for which they belong to. */
      SshADTContainer attributes;

      /* Children of the node. */
      SshXmlDomNode children;
      SshXmlDomNode children_tail;
    } element;

    struct
    {
      unsigned char *data;
      size_t data_len;
    } text;

    struct
    {
      unsigned char *data;
      size_t data_len;
    } comment;
  } u;
};

/* A DOM object. */
struct SshXmlDomRec
{
  /* Parameters. */
  SshXmlDomParamsStruct params;

  /* The intercepted XML parser. */
  SshXmlParser parser;

  /* The intercepted next-level handlers. */
  void *handler_context;
  SshXmlContentHandlerStruct content_handler;
  SshXmlErrorHandlerStruct error_handler;
  SshXmlDtdHandlerStruct dtd_handler;
  SshXmlParseDoneCB parse_done_cb;
  SshXmlEntityCB entity_resolver;

  /* Root element. */
  SshXmlDomNode root;

  /* The current element in the DOM tree. */
  SshXmlDomNode node;
};


/* Prototypes for help functions shared between parser and upper modules ***/

/* Create an ADT bag to hold objects, castable to the
   SshXmlNameHashHeader type. */
SshADTContainer ssh_xml_name_hash_create(SshXmlParser parser);

/* Insert entity `name', `name_len' into the entity bag `bag'.  The
   argument `general' specifies whether the entity is a general or a
   parameter entity.  The function returns the entity object or NULL
   if the entity could not be created.  If the operation was
   successful, the `unique_return' is set to hold the fact whether the
   attribute name is unique or not. */
SshXmlEntity ssh_xml_insert_entity(SshXmlParser parser, SshADTContainer bag,
                                   const char *input_stream_name,
                                   Boolean general, const unsigned char *name,
                                   size_t name_len, Boolean *unique_return);

/* Clear all entities from the bag `bag'.  If the argument `clear_all'
   has the value TRUE, all enties are cleared.  Otherwise, pre-defined
   entities are left in the bag. */
void ssh_xml_clear_entities(SshXmlParser parser, SshADTContainer bag,
                            Boolean clear_all);

/* Free the attribute definition bag `bag'. */
void ssh_xml_attribute_definitions_free(SshXmlParser parser,
                                        SshADTContainer bag);

/* Steal the current attribute definitions list of the parser
   `parser'.  This can be called only from DTD handler's
   `attlist_decl' method. */
void ssh_xml_steal_attribute_definitions(SshXmlParser parser);

/* Steal the current attributes of the parser `parser'.  This can be
   called only from the content handler's `start_element' method. */
void ssh_xml_steal_attributes(SshXmlParser parser);

/* Free the element attributes `attributes'. */
void ssh_xml_attributes_free(SshADTContainer attributes);

/* Lookup the attribute definition `name', `name_len' from the
   container `bag'. */
SshXmlAttributeDefinition ssh_xml_lookup_attribute_definitions(
                                                SshADTContainer bag,
                                                const unsigned char *name,
                                                size_t name_len);

/* Insert attribute `name', `name_len' into the attributes bag `bag'.
   The function returns NULL if the system runs of of memory and the
   attribute object otherwise.  If the operation was successful, the
   `unique_return' is set to hold the fact whether the attribute name
   is unique or not. */
SshXmlAttribute ssh_xml_insert_attribute(SshXmlParser parser,
                                         SshADTContainer bag,
                                         const unsigned char *name,
                                         size_t name_len,
                                         Boolean *unique_return);

/* Lookup attribute `name', `name_len' from the attribute list `bag'.
   The function returns a pointer to the attribute or NULL if the
   attribute is undefind. */
SshXmlAttribute ssh_xml_lookup_attribute(SshADTContainer bag,
                                         const unsigned char *name,
                                         size_t name_len);

/* Intern name `name', `name_len' into the XML parser `parser'.  The
   function returns a pointer to the interned name or NULL if the
   system ran out of memory. */
unsigned char *ssh_xml_intern(SshXmlParser parser,
                              const unsigned char *name, size_t name_len);

/* Report a warning using the parser's error handler. */
void ssh_xml_warning(SshXmlParser parser, ...);

/* Report an error using the parser's error handler. */
void ssh_xml_error(SshXmlParser parser, ...);

/* Report a fatal error using the parser's error handler. */
void ssh_xml_fatal_error(SshXmlParser parser, ...);

/* Report a fatal error using the parser's error handler.  The error
   was generated from the location `input'. */
void ssh_xml_fatal_error_with_input(SshXmlParser parser, SshXmlInput input,
                                    ...);


/* ********** Helper functions for handling UTF-8 encoded values ************/

/* Get the next character from the enumeration context `enum_ctx'.
   The function returns TRUE if the character could be extracted and
   FALSE otherwise.  If the function returns FALSE,
   `enum_ctx->invalid' is set to TRUE if the input was malformed. */
Boolean ssh_xml_value_enum_next_char(SshXmlAttrEnumCtx enum_ctx,
                                     SshXmlChar *char_return);


/* * ************* Compiling element content specifications *****************/

/* Create a DFA matching the content specification expression `expr'.
   The function returns a DFA or NULL if an error occurred.  In case
   or an errro, the function sets the error code into
   `verifier->dfa.error'. */
SshXmlDfa ssh_xml_verifier_create_dfa(SshXmlVerifier verifier,
                                      const unsigned char *expr,
                                      size_t expr_len);

/* Destroy the DFA `dfa'. */
void ssh_xml_verifier_destroy_dfa(SshXmlDfa dfa);

/* Special input symbols for DFA. */
#define SSH_XML_DFA_INPUT_EOF           ((void *) 0)
#define SSH_XML_DFA_INPUT_PCDATA        ((void *) 1)

/* Execute DFA `dfa' with the input symbol `input'.  The argument
   `state' holds the current state of the DFA.  The function returns
   TRUE if the DFA accepts the input and FALSE otherwise.  The current
   state `state' is updated on successful input symbols. */
Boolean ssh_xml_verifier_execute_dfa(SshXmlDfa dfa, const unsigned char *input,
                                     SshUInt16 *state);


/* ********************* Character types and classes ************************/

#define SSH_XML_EXTERN_CHAR_ARRAY(name)         \
extern const SshXmlCharRangeStruct name[];      \
extern const size_t name ## _num_items

/* Character classes. */
SSH_XML_EXTERN_CHAR_ARRAY(ssh_xml_base_char);
SSH_XML_EXTERN_CHAR_ARRAY(ssh_xml_ideographic);
SSH_XML_EXTERN_CHAR_ARRAY(ssh_xml_combining_char);
SSH_XML_EXTERN_CHAR_ARRAY(ssh_xml_digit);
SSH_XML_EXTERN_CHAR_ARRAY(ssh_xml_extender);

/* Check whether the character `ch' is in the character range `array'
   containing `num_items' character ranges. */
Boolean ssh_xml_char_in_array(SshXmlChar ch,
                              const SshXmlCharRangeStruct array[],
                              size_t num_items);


/* ************************* Pre-defined entities ***************************/

/* The pre-defined entities. */
extern const SshXmlPreDefinedEntityStruct ssh_xml_pre_defined_entities[];

/* The number of pre-defined entities. */
extern const size_t ssh_xml_pre_defined_entities_num_items;


/* ************************ Known input encodings ***************************/

/* Returns the input encoding matching the name `name' in
   `encoding_return'.  The function returns TRUE if the encoding is
   known and FALSE otherwise. */
Boolean ssh_xml_input_encoding(const char *name,
                               SshXmlInputEncoding *encoding_return);

#endif /* not SSHXML_INTERNAL_H */
